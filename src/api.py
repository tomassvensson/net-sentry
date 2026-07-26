"""FastAPI application for Net Sentry device dashboard and REST API.

Provides:
- Dependency-free live web dashboard at /
- REST API at /api/v1/ for device history and management
- Prometheus metrics at /metrics (protected when authentication is enabled)
- Health check at /api/v1/health
- JWT auth on /api/v1/* when api.auth_enabled=true (default: disabled)
- CORS middleware (configurable via api.cors_origins in config)
- CSV/JSON export at /api/v1/export/*
- Device detail page at /devices/{mac}
"""

import csv
import io
import json
import logging
import re
import secrets
import uuid
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import generate_latest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.types import ASGIApp

from src.auth import (
    ACCESS_COOKIE_NAME,
    authenticate_user,
    configure_auth,
    get_jwt_expire_minutes,
    is_auth_enabled,
    is_cookie_secure,
    issue_access_token,
    require_auth,
    require_ui_auth,
)
from src.database import get_session, init_database, purge_old_windows
from src.export_utils import sanitize_csv_value
from src.models import Device, VisibilityWindow
from src.tracing import instrument_fastapi

logger = logging.getLogger(__name__)

# Template directory
_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# Module-level engine reference (set during lifespan)
_engine = None
_runtime_config: Any = None
_app_configured = False
_cors_origins = ["http://localhost", "http://127.0.0.1"]
_allowed_hosts = ["localhost", "127.0.0.1", "testserver"]
_PHOTOS_DIR = Path("data/photos")

# Shared string constants
_DEVICE_NOT_FOUND = "Device not found"

# Rate limiter (key by client IP)
limiter = Limiter(key_func=get_remote_address)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add HTTP security headers to every response."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialise middleware."""
        super().__init__(app)

    async def dispatch(self, request: StarletteRequest, call_next: Any) -> StarletteResponse:
        """Add security headers to the response."""
        nonce = secrets.token_urlsafe(18)
        request.state.csp_nonce = nonce
        response: StarletteResponse = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.url.path.startswith(("/docs", "/redoc")):
            script_policy = "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net"
            style_policy = "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net"
        else:
            script_policy = f"script-src 'self' 'nonce-{nonce}'"
            style_policy = "style-src 'self' 'unsafe-inline'"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"{script_policy}; "
            f"{style_policy}; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        if request.url.path.startswith("/media/photos/"):
            response.headers.setdefault("Cache-Control", "private, max-age=3600")
        elif not request.url.path.startswith("/static/"):
            response.headers.setdefault("Cache-Control", "no-store")
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Inject a correlation ID into every request/response as X-Request-ID."""

    async def dispatch(self, request: StarletteRequest, call_next: Any) -> StarletteResponse:
        """Read or generate a request ID and add it to the response."""
        supplied_id = request.headers.get("X-Request-ID", "")
        request_id = supplied_id if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", supplied_id) else str(uuid.uuid4())
        request.state.request_id = request_id
        response: StarletteResponse = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


_CSRF_COOKIE_NAME = "csrftoken"
_CSRF_HEADER_NAME = "X-CSRFToken"
_CSRF_PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_CSRF_EXEMPT_PATHS = {"/api/v1/auth/token"}


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection for mutating API endpoints."""

    async def dispatch(self, request: StarletteRequest, call_next: Any) -> StarletteResponse:
        """Validate CSRF token on mutating requests, set cookie on all responses."""
        if request.method == "POST" and request.url.path == "/login":
            origin = request.headers.get("Origin")
            expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin and not _constant_time_compare(origin.rstrip("/"), expected_origin.rstrip("/")):
                return StarletteResponse(
                    content='{"detail":"Cross-origin login rejected"}',
                    status_code=403,
                    media_type="application/json",
                )

        bearer_auth = request.headers.get("Authorization", "").lower().startswith("bearer ")
        protected_path = request.url.path.startswith("/api/v1/") or request.url.path == "/logout"
        requires_csrf = (
            request.method in _CSRF_PROTECTED_METHODS
            and protected_path
            and request.url.path not in _CSRF_EXEMPT_PATHS
            and not bearer_auth
        )
        if requires_csrf:
            cookie_token = request.cookies.get(_CSRF_COOKIE_NAME)
            header_token = request.headers.get(_CSRF_HEADER_NAME)
            if not cookie_token or not header_token or not _constant_time_compare(cookie_token, header_token):
                return StarletteResponse(
                    content='{"detail":"CSRF token missing or invalid"}',
                    status_code=403,
                    media_type="application/json",
                )
        response: StarletteResponse = await call_next(request)
        if _CSRF_COOKIE_NAME not in request.cookies:
            token = str(uuid.uuid4())
            response.set_cookie(
                _CSRF_COOKIE_NAME,
                token,
                httponly=False,
                secure=is_cookie_secure(),
                samesite="strict",
                path="/",
            )
        return response


class ConfigurableCORSMiddleware:
    """CORS wrapper whose policy can be updated before or during lifespan startup."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._signature: tuple[str, ...] = ()
        self._middleware: ASGIApp | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        signature = tuple(_cors_origins)
        if self._middleware is None or signature != self._signature:
            self._signature = signature
            self._middleware = CORSMiddleware(
                self.app,
                allow_origins=list(signature),
                allow_credentials=True,
                allow_methods=["GET", "POST", "PATCH", "DELETE"],
                allow_headers=["Authorization", "Content-Type", _CSRF_HEADER_NAME],
            )
        middleware = self._middleware
        await middleware(scope, receive, send)


class ConfigurableTrustedHostMiddleware:
    """Trusted-host wrapper whose allowlist follows runtime configuration."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._signature: tuple[str, ...] = ()
        self._middleware: ASGIApp | None = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        signature = tuple(_allowed_hosts)
        if self._middleware is None or signature != self._signature:
            self._signature = signature
            self._middleware = TrustedHostMiddleware(
                self.app,
                allowed_hosts=list(signature),
                www_redirect=False,
            )
        middleware = self._middleware
        await middleware(scope, receive, send)


def _constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    import hmac

    return hmac.compare_digest(a.encode(), b.encode())


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan: initialize DB, start background jobs on startup."""
    import asyncio

    global _engine  # noqa: PLW0603
    owned_engine = None
    if not _app_configured:
        from src.config import load_config

        configure_app(load_config())

    if _engine is None:
        database_url = _runtime_config.database.url if _runtime_config is not None else None
        owned_engine = init_database(database_url)
        _engine = owned_engine
    logger.info("API server started, database initialized")

    # Start background data-retention/vacuum job
    task = asyncio.create_task(_retention_task())

    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        if owned_engine is not None:
            owned_engine.dispose()
            if _engine is owned_engine:
                _engine = None
        logger.info("API server shutting down")


async def _retention_task() -> None:
    """Background task: purge old visibility windows once per day."""
    import asyncio

    _interval_seconds = 86_400  # run once per day
    while True:
        await asyncio.sleep(_interval_seconds)
        if _engine is None:
            continue
        try:
            cfg = _runtime_config
            if cfg is None:
                continue
            retention_days = cfg.database.retention_days
            if retention_days > 0:
                deleted = purge_old_windows(_engine, retention_days)
                logger.info("Retention job: purged %d windows (retention=%d days)", deleted, retention_days)
        except Exception:
            logger.exception("Retention task encountered an error")


def set_engine(engine: Any) -> None:
    """Set the database engine (used in tests and from main)."""
    global _engine  # noqa: PLW0603
    _engine = engine


def configure_app(config: Any) -> None:
    """Apply runtime config to the running FastAPI app (CORS, auth).

    Called by the launcher (main.py / uvicorn startup) after loading config.

    Args:
        config: AppConfig instance.
    """
    global _allowed_hosts, _app_configured, _cors_origins, _runtime_config, _PHOTOS_DIR  # noqa: PLW0603

    from src.config import validate_config

    validate_config(config)
    configure_auth(
        enabled=config.api.auth_enabled,
        secret=config.api.jwt_secret,
        algorithm=config.api.jwt_algorithm,
        expire_minutes=config.api.jwt_expire_minutes,
        users=config.api.api_users,
        cookie_secure=config.api.cookie_secure,
    )
    _cors_origins = list(config.api.cors_origins or ["http://localhost", "http://127.0.0.1"])
    _allowed_hosts = list(config.api.allowed_hosts)
    _PHOTOS_DIR = Path(config.api.photo_directory).expanduser().resolve()
    _runtime_config = config
    _app_configured = True
    instrument_fastapi(app, enabled=config.tracing.enabled)
    logger.info("CORS origins: %s", _cors_origins)


app = FastAPI(
    title="Net Sentry Device Tracker",
    description="Track WiFi and Bluetooth device visibility over time",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# Register rate-limit exceeded handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# Reject untrusted Host headers before requests reach application routes.
app.add_middleware(ConfigurableTrustedHostMiddleware)
# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)
# Add correlation ID middleware
app.add_middleware(RequestIdMiddleware)
# Add CSRF protection middleware
app.add_middleware(CSRFMiddleware)
# Add runtime-configurable CORS as the outermost application middleware
app.add_middleware(ConfigurableCORSMiddleware)

# Serve static files if directory exists
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


def get_db() -> Generator[Session]:
    """Dependency: provide a database session."""
    if _engine is None:
        raise RuntimeError("Database not initialized")
    with get_session(_engine) as session:
        yield session


# Reusable dependency type aliases (Annotated pattern — FastAPI best practice)
DbSession = Annotated[Session, Depends(get_db)]
AuthUser = Annotated[str | None, Depends(require_auth)]
UiAuthUser = Annotated[str | None, Depends(require_ui_auth)]


# ---------------------------------------------------------------------------
# Auth-aware API documentation
# ---------------------------------------------------------------------------
@app.get("/openapi.json", include_in_schema=False)
def openapi_schema(_user: str | None = Depends(require_auth)) -> JSONResponse:
    """Serve the API schema only to authorized users when auth is enabled."""
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False)
def swagger_docs(_user: str | None = Depends(require_auth)) -> HTMLResponse:
    """Serve Swagger UI behind the same authentication policy as the API."""
    return get_swagger_ui_html(openapi_url="/openapi.json", title=f"{app.title} - Swagger UI")


@app.get("/redoc", include_in_schema=False)
def redoc_docs(_user: str | None = Depends(require_auth)) -> HTMLResponse:
    """Serve ReDoc behind the same authentication policy as the API."""
    return get_redoc_html(openapi_url="/openapi.json", title=f"{app.title} - ReDoc")


# ---------------------------------------------------------------------------
# API v1 router
# ---------------------------------------------------------------------------
v1 = APIRouter(prefix="/api/v1")


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
@v1.get("/health")
def health_check() -> dict[str, Any]:
    """Health check endpoint.

    Returns:
        Health status with database connectivity info.
    """
    status: dict[str, Any] = {
        "status": "healthy",
        "timestamp": datetime.now(UTC).isoformat(),
        "version": "0.1.0",
    }

    try:
        if _engine is not None:
            with get_session(_engine) as session:
                count = session.query(func.count(Device.id)).scalar()
                status["database"] = {"connected": True, "device_count": count}
        else:
            status["database"] = {"connected": False}
            status["status"] = "degraded"
    except Exception:
        logger.exception("Health check DB query failed")
        status["database"] = {"connected": False, "error": "query_failed"}
        status["status"] = "degraded"

    return status


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics(_user: str | None = Depends(require_auth)) -> str:
    """Expose Prometheus metrics.

    Returns:
        Prometheus text-format metrics.
    """
    return generate_latest().decode("utf-8")


# ---------------------------------------------------------------------------
# Browser authentication
# ---------------------------------------------------------------------------
def _safe_local_redirect(value: str | None) -> str:
    """Allow only same-origin absolute paths as post-login destinations."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    return value


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next_url: str = Query("/", alias="next")) -> StarletteResponse:
    """Render the browser login page."""
    if not is_auth_enabled():
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"next_url": _safe_local_redirect(next_url), "error": None},
    )


@app.post("/login", response_class=HTMLResponse)
@limiter.limit("5/minute")
def browser_login(
    request: Request,
    username: str = Form(..., max_length=128),
    password: str = Form(..., max_length=1024),
    next_url: str = Form("/", alias="next"),
) -> StarletteResponse:
    """Authenticate a browser user and issue an HttpOnly session cookie."""
    if not is_auth_enabled():
        return RedirectResponse(url="/", status_code=303)
    if not authenticate_user(username, password):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"next_url": _safe_local_redirect(next_url), "error": "Incorrect username or password"},
            status_code=401,
        )

    token = issue_access_token(username)
    response = RedirectResponse(url=_safe_local_redirect(next_url), status_code=303)
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        token,
        max_age=get_jwt_expire_minutes() * 60,
        httponly=True,
        secure=is_cookie_secure(),
        samesite="strict",
        path="/",
    )
    return response


@app.post("/logout")
def browser_logout(
    request: Request,
    _user: str | None = Depends(require_ui_auth),
) -> RedirectResponse:
    """Clear the browser session cookie."""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(ACCESS_COOKIE_NAME, path="/", secure=is_cookie_secure(), samesite="strict")
    return response


# ---------------------------------------------------------------------------
# REST API v1 — Devices
# ---------------------------------------------------------------------------
@v1.get("/devices")
@limiter.limit("100/minute")
def list_devices(
    request: Request,
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    page_size: Annotated[int, Query(ge=1, le=200, description="Items per page")] = 50,
    device_type: Annotated[str | None, Query(description="Filter by device type")] = None,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """List all known devices with pagination.

    Args:
        request: FastAPI request (required by rate limiter).
        page: Page number (1-indexed).
        page_size: Number of items per page.
        device_type: Optional filter.
        session: Database session.

    Returns:
        Paginated device list.
    """
    query = session.query(Device)
    if device_type:
        query = query.filter(Device.device_type == device_type)

    total = query.count()
    devices = query.order_by(Device.updated_at.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if page_size else 0,
        "devices": [_serialize_device(d) for d in devices],
    }


@v1.get("/devices/{mac_address}", responses={404: {"description": "Device not found"}})
@limiter.limit("200/minute")
def get_device(
    request: Request,
    mac_address: str,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """Get device details by MAC address.

    Args:
        request: FastAPI request (required by rate limiter).
        mac_address: Device MAC address.
        session: Database session.

    Returns:
        Device details with latest visibility window.
    """
    device = session.query(Device).filter_by(mac_address=mac_address).first()
    if device is None:
        raise HTTPException(status_code=404, detail=_DEVICE_NOT_FOUND)

    latest_window = (
        session.query(VisibilityWindow)
        .filter_by(mac_address=mac_address)
        .order_by(VisibilityWindow.last_seen.desc())
        .first()
    )

    result = _serialize_device(device)
    result["latest_window"] = _serialize_window(latest_window) if latest_window else None
    return result


@v1.get("/devices/{mac_address}/windows", responses={404: {"description": "Device not found"}})
@limiter.limit("100/minute")
def get_device_windows(
    request: Request,
    mac_address: str,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """Get visibility windows for a device.

    Args:
        request: FastAPI request (required by rate limiter).
        mac_address: Device MAC address.
        page: Page number.
        page_size: Items per page.
        session: Database session.

    Returns:
        Paginated visibility windows.
    """
    query = session.query(VisibilityWindow).filter_by(mac_address=mac_address)
    total = query.count()

    windows = query.order_by(VisibilityWindow.last_seen.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "mac_address": mac_address,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if page_size else 0,
        "windows": [_serialize_window(w) for w in windows],
    }


# ---------------------------------------------------------------------------
# REST API v1 — Device notes / label
# ---------------------------------------------------------------------------


@v1.patch("/devices/{mac_address}/notes", responses={404: {"description": "Device not found"}})
@limiter.limit("60/minute")
def update_device_notes(
    request: Request,
    mac_address: str,
    label: Annotated[str | None, Form(max_length=255)] = None,
    notes: Annotated[str | None, Form(max_length=4096)] = None,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """Update the operator label and notes for a device.

    Args:
        request: FastAPI request.
        mac_address: Device MAC address.
        label: Human-readable alias (max 255 chars).
        notes: Free-form notes.
        session: Database session.

    Returns:
        Updated device fields.
    """
    device = session.query(Device).filter_by(mac_address=mac_address).first()
    if device is None:
        raise HTTPException(status_code=404, detail=_DEVICE_NOT_FOUND)
    if label is not None:
        device.label = label or None
    if notes is not None:
        device.notes = notes or None
    session.commit()
    return {"mac_address": mac_address, "label": device.label, "notes": device.notes}


_MAX_PHOTO_BYTES = 10 * 1024 * 1024  # 10 MB
_PHOTO_MEDIA_TYPES = {
    ".jpg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
}


def _detect_image_extension(header: bytes) -> str | None:
    """Identify supported image formats from file signatures."""
    if header.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return ".webp"
    return None


@v1.post(
    "/devices/{mac_address}/photo",
    responses={
        404: {"description": "Device not found"},
        413: {"description": "Photo exceeds size limit"},
        415: {"description": "Unsupported file type"},
    },
)
@limiter.limit("20/minute")
async def upload_device_photo(
    request: Request,
    mac_address: str,
    photo: Annotated[UploadFile, File()],
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """Upload an optional photo for a device.

    Stores the file under the configured data directory using a UUID filename.
    Content is validated by file signature rather than trusting its extension.

    Args:
        request: FastAPI request.
        mac_address: Device MAC address.
        photo: Uploaded image file.
        session: Database session.

    Returns:
        ``{"photo_url": "<relative URL to the uploaded file>"}``
    """
    device = session.query(Device).filter_by(mac_address=mac_address).first()
    if device is None:
        raise HTTPException(status_code=404, detail=_DEVICE_NOT_FOUND)

    first_chunk = await photo.read(65536)
    suffix = _detect_image_extension(first_chunk)
    if suffix is None:
        raise HTTPException(status_code=415, detail="Uploaded content is not a supported JPEG, PNG, GIF, or WebP image")

    supplied_suffix = Path(photo.filename or "").suffix.lower()
    if supplied_suffix == ".jpeg":
        supplied_suffix = ".jpg"
    if supplied_suffix and supplied_suffix != suffix:
        raise HTTPException(status_code=415, detail="Filename extension does not match the uploaded image content")

    _PHOTOS_DIR.mkdir(parents=True, exist_ok=True)
    safe_filename = f"{uuid.uuid4()}{suffix}"
    dest = _PHOTOS_DIR / safe_filename

    bytes_written = len(first_chunk)
    if bytes_written > _MAX_PHOTO_BYTES:
        raise HTTPException(status_code=413, detail="Photo exceeds 10 MB limit")
    with dest.open("wb") as out_file:
        out_file.write(first_chunk)
        while chunk := await photo.read(65536):
            bytes_written += len(chunk)
            if bytes_written > _MAX_PHOTO_BYTES:
                dest.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="Photo exceeds 10 MB limit")
            out_file.write(chunk)

    # Remove old photo if it exists
    if device.photo_path:
        old_file = (_PHOTOS_DIR / Path(device.photo_path).name).resolve()
        if old_file.exists() and old_file.is_relative_to(_PHOTOS_DIR):
            old_file.unlink(missing_ok=True)

    relative_url = f"/media/photos/{safe_filename}"
    device.photo_path = relative_url
    session.commit()
    return {"photo_url": relative_url}


@app.get("/media/photos/{filename}", response_class=FileResponse)
def get_device_photo(
    filename: str,
    _user: str | None = Depends(require_ui_auth),
) -> FileResponse:
    """Serve an uploaded photo only to authenticated dashboard users."""
    if not re.fullmatch(r"[0-9a-fA-F-]{36}\.(?:jpg|png|gif|webp)", filename):
        raise HTTPException(status_code=404, detail="Photo not found")
    path = (_PHOTOS_DIR / filename).resolve()
    if not path.is_relative_to(_PHOTOS_DIR) or not path.is_file():
        raise HTTPException(status_code=404, detail="Photo not found")
    return FileResponse(path, media_type=_PHOTO_MEDIA_TYPES[path.suffix.lower()])


# ---------------------------------------------------------------------------
# REST API v1 — Summary
# ---------------------------------------------------------------------------
@v1.get("/summary")
@limiter.limit("60/minute")
def get_summary(
    request: Request,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """Get an overview of the device database.

    Args:
        request: FastAPI request (required by rate limiter).
        session: Database session.

    Returns:
        Summary statistics.
    """
    total_devices = session.query(func.count(Device.id)).scalar() or 0

    # Count by type
    type_counts: dict[str, int] = {}
    rows = session.query(Device.device_type, func.count(Device.id)).group_by(Device.device_type).all()
    for device_type, count in rows:
        type_counts[device_type] = count

    # Active windows (seen in last 10 minutes)
    cutoff = datetime.now(UTC)
    # Use a broad cutoff — we just want recent activity
    active_windows = (
        session.query(func.count(VisibilityWindow.id))
        .filter(VisibilityWindow.last_seen >= cutoff.replace(minute=cutoff.minute - 10 if cutoff.minute >= 10 else 0))
        .scalar()
        or 0
    )

    return {
        "total_devices": total_devices,
        "device_types": type_counts,
        "active_windows": active_windows,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    session: DbSession = None,  # type: ignore[assignment]
    _user: UiAuthUser = None,
) -> HTMLResponse:
    """Render the live dashboard.

    Args:
        request: FastAPI request.
        session: Database session.

    Returns:
        Rendered HTML dashboard.
    """
    total_devices = session.query(func.count(Device.id)).scalar() or 0
    devices = session.query(Device).order_by(Device.updated_at.desc()).limit(50).all()

    device_list = []
    for device in devices:
        window = (
            session.query(VisibilityWindow)
            .filter_by(mac_address=device.mac_address)
            .order_by(VisibilityWindow.last_seen.desc())
            .first()
        )
        device_list.append({"device": device, "window": window})

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "total_devices": total_devices,
            "devices": device_list,
            "now": datetime.now(UTC),
            "auth_enabled": is_auth_enabled(),
        },
    )


@v1.get("/devices-table", response_class=HTMLResponse)
def devices_table_fragment(
    request: Request,
    page: Annotated[int, Query(ge=1)] = 1,
    session: DbSession = None,  # type: ignore[assignment]
    _user: UiAuthUser = None,
) -> HTMLResponse:
    """HTML fragment: device table rows for live updates.

    Args:
        request: FastAPI request.
        page: Page number.
        session: Database session.

    Returns:
        HTML table rows fragment.
    """
    page_size = 20
    devices = (
        session.query(Device).order_by(Device.updated_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    )

    device_list = []
    for device in devices:
        window = (
            session.query(VisibilityWindow)
            .filter_by(mac_address=device.mac_address)
            .order_by(VisibilityWindow.last_seen.desc())
            .first()
        )
        device_list.append({"device": device, "window": window})

    total = session.query(func.count(Device.id)).scalar() or 0
    pages = (total + page_size - 1) // page_size

    return templates.TemplateResponse(
        request=request,
        name="devices_table.html",
        context={
            "devices": device_list,
            "page": page,
            "pages": pages,
            "now": datetime.now(UTC),
        },
    )


# ---------------------------------------------------------------------------
# Device detail page (visibility windows UI)
# ---------------------------------------------------------------------------
@app.get("/devices/{mac_address}", response_class=HTMLResponse)
def device_detail_page(
    request: Request,
    mac_address: str,
    page: Annotated[int, Query(ge=1)] = 1,
    session: DbSession = None,  # type: ignore[assignment]
    _user: UiAuthUser = None,
) -> HTMLResponse:
    """Render the device detail page showing all visibility windows.

    Args:
        request: FastAPI request.
        mac_address: Device MAC address.
        page: Page number for visibility windows.
        session: Database session.

    Returns:
        Rendered HTML device detail page.
    """
    device = session.query(Device).filter_by(mac_address=mac_address).first()
    if device is None:
        return HTMLResponse(content="<h1>Device not found</h1>", status_code=404)

    page_size = 20
    windows_query = (
        session.query(VisibilityWindow).filter_by(mac_address=mac_address).order_by(VisibilityWindow.last_seen.desc())
    )
    total_windows = windows_query.count()
    windows = windows_query.offset((page - 1) * page_size).limit(page_size).all()
    pages = (total_windows + page_size - 1) // page_size

    return templates.TemplateResponse(
        request=request,
        name="device_detail.html",
        context={
            "device": device,
            "windows": windows,
            "page": page,
            "pages": pages,
            "total_windows": total_windows,
            "mac_address": device.mac_address,
            "now": datetime.now(UTC),
            "auth_enabled": is_auth_enabled(),
        },
    )


@app.get("/devices/{mac_address}/timeline", response_class=HTMLResponse)
def device_timeline_page(
    request: Request,
    mac_address: str,
    gap_minutes: Annotated[int, Query(ge=1, le=10080, description="Gap threshold in minutes.")] = 60,
    session: DbSession = None,  # type: ignore[assignment]
    _user: UiAuthUser = None,
) -> HTMLResponse:
    """Render the device timeline page showing visibility gaps and windows visually.

    Args:
        request: FastAPI request.
        mac_address: Device MAC address.
        gap_minutes: Minimum gap (minutes) between windows to report as absent.
        session: Database session.

    Returns:
        Rendered HTML timeline page.
    """
    device = session.query(Device).filter_by(mac_address=mac_address).first()
    if device is None:
        return HTMLResponse(content="<h1>Device not found</h1>", status_code=404)

    windows: list[VisibilityWindow] = (
        session.query(VisibilityWindow)
        .filter_by(mac_address=mac_address)
        .order_by(VisibilityWindow.first_seen.asc())
        .all()
    )

    gap_threshold_seconds = gap_minutes * 60

    entries: list[dict[str, Any]] = []
    for i, w in enumerate(windows):
        entries.append({"type": "window", "window": w})
        if i + 1 < len(windows):
            next_w = windows[i + 1]
            gap_seconds = (next_w.first_seen - w.last_seen).total_seconds()
            if gap_seconds >= gap_threshold_seconds:
                entries.append(
                    {
                        "type": "gap",
                        "gap_start": w.last_seen,
                        "gap_end": next_w.first_seen,
                        "gap_seconds": int(gap_seconds),
                    }
                )

    return templates.TemplateResponse(
        request=request,
        name="device_timeline.html",
        context={
            "device": device,
            "entries": entries,
            "gap_minutes": gap_minutes,
            "total_windows": len(windows),
            "first_seen": windows[0].first_seen if windows else None,
            "last_seen": windows[-1].last_seen if windows else None,
            "now": datetime.now(UTC),
            "auth_enabled": is_auth_enabled(),
        },
    )


@v1.get(
    "/devices/{mac_address}/windows-table",
    response_class=HTMLResponse,
    responses={404: {"description": "Device not found"}},
)
def windows_table_fragment(
    request: Request,
    mac_address: str,
    page: Annotated[int, Query(ge=1)] = 1,
    session: DbSession = None,  # type: ignore[assignment]
    _user: UiAuthUser = None,
) -> HTMLResponse:
    """HTML fragment: visibility windows table rows for a device.

    Args:
        request: FastAPI request.
        mac_address: Device MAC address.
        page: Page number.
        session: Database session.

    Returns:
        HTML table rows fragment.
    """
    page_size = 20
    windows_query = (
        session.query(VisibilityWindow).filter_by(mac_address=mac_address).order_by(VisibilityWindow.last_seen.desc())
    )
    total_windows = windows_query.count()
    windows = windows_query.offset((page - 1) * page_size).limit(page_size).all()
    pages = (total_windows + page_size - 1) // page_size

    return templates.TemplateResponse(
        request=request,
        name="windows_table.html",
        context={
            "mac_address": mac_address,
            "windows": windows,
            "page": page,
            "pages": pages,
        },
    )


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------
@v1.post("/auth/token", responses={401: {"description": "Incorrect username or password"}})
@limiter.limit("5/minute")  # Tight limit to mitigate brute-force attacks
def login(
    request: Request,
    username: Annotated[str, Form(max_length=128)],
    password: Annotated[str, Form(max_length=1024)],
) -> dict[str, Any]:
    """Obtain a JWT access token (OAuth2 password flow).

    Only available when ``api.auth_enabled=true``.

    Args:
        request: FastAPI request (required by rate limiter).
        username: API username.
        password: Plain-text password.

    Returns:
        ``{"access_token": "...", "token_type": "bearer"}``
    """
    if not is_auth_enabled():
        raise HTTPException(status_code=404, detail="Authentication is disabled")
    if not authenticate_user(username, password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = issue_access_token(username)
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Export endpoints
# ---------------------------------------------------------------------------

_DEVICE_CSV_FIELDS = [
    "id",
    "mac_address",
    "device_type",
    "vendor",
    "device_name",
    "ssid",
    "hostname",
    "ip_address",
    "category",
    "is_whitelisted",
    "reconnect_count",
    "created_at",
    "updated_at",
]

_WINDOW_CSV_FIELDS = [
    "id",
    "mac_address",
    "first_seen",
    "last_seen",
    "signal_strength_dbm",
    "min_signal_dbm",
    "max_signal_dbm",
    "scan_count",
]


@v1.get("/export/devices.csv")
@limiter.limit("20/minute")
def export_devices_csv(
    request: Request,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> StreamingResponse:
    """Export all devices as CSV.

    Args:
        request: FastAPI request.
        session: Database session.
        _user: Authenticated user (or None if auth disabled).

    Returns:
        Streaming CSV response.
    """
    devices = session.query(Device).order_by(Device.updated_at.desc()).all()
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_DEVICE_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for d in devices:
        writer.writerow({f: sanitize_csv_value(getattr(d, f, "")) for f in _DEVICE_CSV_FIELDS})
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=devices.csv"},
    )


@v1.get("/export/devices.json")
@limiter.limit("20/minute")
def export_devices_json(
    request: Request,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> StreamingResponse:
    """Export all devices as JSON.

    Args:
        request: FastAPI request.
        session: Database session.
        _user: Authenticated user (or None if auth disabled).

    Returns:
        Streaming JSON response.
    """
    devices = session.query(Device).order_by(Device.updated_at.desc()).all()
    data = [_serialize_device(d) for d in devices]
    content = json.dumps(data, indent=2, default=str)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=devices.json"},
    )


@v1.get("/export/windows.csv")
@limiter.limit("20/minute")
def export_windows_csv(
    request: Request,
    mac_address: Annotated[str | None, Query(description="Filter by MAC address")] = None,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> StreamingResponse:
    """Export visibility windows as CSV.

    Args:
        request: FastAPI request.
        mac_address: Optional filter by device MAC.
        session: Database session.
        _user: Authenticated user (or None if auth disabled).

    Returns:
        Streaming CSV response.
    """
    query = session.query(VisibilityWindow)
    if mac_address:
        query = query.filter_by(mac_address=mac_address)
    windows = query.order_by(VisibilityWindow.last_seen.desc()).all()

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_WINDOW_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for w in windows:
        writer.writerow({f: sanitize_csv_value(getattr(w, f, "")) for f in _WINDOW_CSV_FIELDS})
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=windows.csv"},
    )


# ---------------------------------------------------------------------------
# Timeline endpoint
# ---------------------------------------------------------------------------
@v1.get("/devices/{mac_address}/timeline", responses={404: {"description": "Device not found"}})
@limiter.limit("100/minute")
def get_device_timeline(
    request: Request,
    mac_address: str,
    gap_minutes: Annotated[
        int,
        Query(
            ge=1,
            le=10080,
            description="Minimum gap (minutes) between windows to be reported as a gap period.",
        ),
    ] = 60,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """Return all visibility windows for a device in chronological order.

    Consecutive windows are compared; if the gap between ``last_seen`` of one
    window and ``first_seen`` of the next exceeds *gap_minutes*, a synthetic
    ``gap`` entry is inserted in the ``entries`` list so callers can render
    absent periods distinctly.

    Args:
        request: FastAPI request (required by rate limiter).
        mac_address: Device MAC address.
        gap_minutes: Gap threshold in minutes.
        session: Database session.

    Returns:
        ``{"mac_address": …, "first_seen": …, "last_seen": …, "total_windows": …,
           "entries": [{type, …window_fields | gap_fields}]}``
    """
    device = session.query(Device).filter_by(mac_address=mac_address).first()
    if device is None:
        raise HTTPException(status_code=404, detail=_DEVICE_NOT_FOUND)

    windows: list[VisibilityWindow] = (
        session.query(VisibilityWindow)
        .filter_by(mac_address=mac_address)
        .order_by(VisibilityWindow.first_seen.asc())
        .all()
    )

    entries = _build_timeline_api_entries(windows, gap_minutes * 60)

    first_seen = windows[0].first_seen.isoformat() if windows else None
    last_seen = windows[-1].last_seen.isoformat() if windows else None

    return {
        "mac_address": mac_address,
        "device_name": device.device_name,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "total_windows": len(windows),
        "gap_threshold_minutes": gap_minutes,
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Randomized-MAC merge candidates endpoint
# ---------------------------------------------------------------------------
@v1.get("/devices/{mac_address}/merge-candidates", responses={404: {"description": "Device not found"}})
@limiter.limit("30/minute")
def get_merge_candidates(
    request: Request,
    mac_address: str,
    session: DbSession = None,  # type: ignore[assignment]
    _user: AuthUser = None,
) -> dict[str, Any]:
    """Find canonical devices that *mac_address* (a randomized MAC) may belong to.

    Returns an empty candidate list if the MAC is not randomized or if no
    matches are found.  See :mod:`src.mac_merge` for full caveats.

    Args:
        request: FastAPI request (required by rate limiter).
        mac_address: MAC address to inspect.
        session: Database session.

    Returns:
        ``{"mac_address": …, "is_randomized": …, "candidates": [{…}]}``
    """
    from src.mac_merge import MergeCandidate, find_merge_candidates
    from src.oui_lookup import is_randomized_mac

    device = session.query(Device).filter_by(mac_address=mac_address).first()
    if device is None:
        raise HTTPException(status_code=404, detail=_DEVICE_NOT_FOUND)

    randomized = is_randomized_mac(mac_address)
    raw: list[MergeCandidate] = find_merge_candidates(session, device) if randomized else []

    def _serialize_candidate(c: MergeCandidate) -> dict[str, Any]:
        return {
            "source_mac": c.source_mac,
            "target_mac": c.target_mac,
            "confidence": c.confidence,
            "reasons": c.reasons,
        }

    return {
        "mac_address": mac_address,
        "is_randomized": randomized,
        "already_merged_into": device.merged_into,
        "candidates": [_serialize_candidate(c) for c in raw],
    }


# Register all v1 routes with the app
app.include_router(v1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _serialize_device(device: Device) -> dict[str, Any]:
    """Serialize a Device to a dict."""
    return {
        "id": device.id,
        "mac_address": device.mac_address,
        "device_type": device.device_type,
        "vendor": device.vendor,
        "device_name": device.device_name,
        "ssid": device.ssid,
        "hostname": device.hostname,
        "ip_address": device.ip_address,
        "category": device.category,
        "is_whitelisted": device.is_whitelisted,
        "reconnect_count": device.reconnect_count,
        "label": device.label,
        "notes": device.notes,
        "photo_path": device.photo_path,
        "created_at": device.created_at.isoformat() if device.created_at else None,
        "updated_at": device.updated_at.isoformat() if device.updated_at else None,
    }


def _serialize_window(window: VisibilityWindow) -> dict[str, Any]:
    """Serialize a VisibilityWindow to a dict."""
    return {
        "id": window.id,
        "mac_address": window.mac_address,
        "first_seen": window.first_seen.isoformat() if window.first_seen else None,
        "last_seen": window.last_seen.isoformat() if window.last_seen else None,
        "signal_strength_dbm": window.signal_strength_dbm,
        "min_signal_dbm": window.min_signal_dbm,
        "max_signal_dbm": window.max_signal_dbm,
        "scan_count": window.scan_count,
    }


def _build_timeline_api_entries(windows: list[VisibilityWindow], gap_threshold_seconds: int) -> list[dict[str, Any]]:
    """Build window and gap entries for the timeline API response.

    Args:
        windows: Ordered list of visibility windows.
        gap_threshold_seconds: Minimum gap duration to report as a gap entry.

    Returns:
        List of dicts with ``type`` of ``"window"`` or ``"gap"``.
    """
    entries: list[dict[str, Any]] = []
    for i, w in enumerate(windows):
        entries.append({"type": "window", **_serialize_window(w)})
        if i + 1 < len(windows):
            next_w = windows[i + 1]
            gap_seconds = (next_w.first_seen - w.last_seen).total_seconds()
            if gap_seconds >= gap_threshold_seconds:
                entries.append(
                    {
                        "type": "gap",
                        "gap_start": w.last_seen.isoformat() if w.last_seen else None,
                        "gap_end": next_w.first_seen.isoformat() if next_w.first_seen else None,
                        "gap_seconds": int(gap_seconds),
                    }
                )
    return entries
