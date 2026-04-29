"""FastAPI application for Net Sentry device dashboard and REST API.

Provides:
- HTMX-powered web dashboard at /
- REST API at /api/v1/ for device history and management
- Prometheus metrics at /metrics (GET, no auth required)
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
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Form, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import generate_latest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import func
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.types import ASGIApp

from src.auth import configure_auth, require_auth
from src.database import get_session, init_database, purge_old_windows
from src.models import Device, VisibilityWindow

logger = logging.getLogger(__name__)

# Template directory
_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# Module-level engine reference (set during lifespan)
_engine = None

# Rate limiter (key by client IP)
limiter = Limiter(key_func=get_remote_address)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add HTTP security headers to every response."""

    def __init__(self, app: ASGIApp) -> None:
        """Initialise middleware."""
        super().__init__(app)

    async def dispatch(self, request: StarletteRequest, call_next: Any) -> StarletteResponse:
        """Add security headers to the response."""
        response: StarletteResponse = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "font-src 'self' data: https://cdn.jsdelivr.net;"
        )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initialize DB, start background jobs on startup."""
    import asyncio

    global _engine  # noqa: PLW0603
    if _engine is None:
        try:
            _engine = init_database()
        except Exception:
            logger.exception("Failed to initialize database in API lifespan")
    logger.info("API server started, database initialized")

    # Start background data-retention/vacuum job
    task = asyncio.create_task(_retention_task())

    yield

    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
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
            from src.config import load_config

            cfg = load_config()
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
    configure_auth(
        enabled=config.api.auth_enabled,
        secret=config.api.jwt_secret,
        algorithm=config.api.jwt_algorithm,
        expire_minutes=config.api.jwt_expire_minutes,
        users=config.api.api_users,
    )
    # Rebuild CORS middleware with the configured origins.
    # FastAPI middleware stack is built at startup; we add CORS once here.
    # For tests the defaults (allow localhost) are fine.
    origins = config.api.cors_origins or ["http://localhost", "http://127.0.0.1"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
    logger.info("CORS origins: %s", origins)


app = FastAPI(
    title="Net Sentry Device Tracker",
    description="Track WiFi and Bluetooth device visibility over time",
    version="0.1.0",
    lifespan=lifespan,
)

# Register rate-limit exceeded handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)

# Serve static files if directory exists
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


def get_db() -> Generator[Session, None, None]:
    """Dependency: provide a database session."""
    if _engine is None:
        raise RuntimeError("Database not initialized")
    with get_session(_engine) as session:
        yield session


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
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
def prometheus_metrics() -> str:
    """Expose Prometheus metrics.

    Returns:
        Prometheus text-format metrics.
    """
    return generate_latest().decode("utf-8")


# ---------------------------------------------------------------------------
# REST API v1 — Devices
# ---------------------------------------------------------------------------
@v1.get("/devices")
@limiter.limit("100/minute")
def list_devices(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    device_type: str | None = Query(None, description="Filter by device type"),
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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


@v1.get("/devices/{mac_address}")
@limiter.limit("200/minute")
def get_device(
    request: Request,
    mac_address: str,
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
        return {"error": "Device not found", "mac_address": mac_address}

    latest_window = (
        session.query(VisibilityWindow)
        .filter_by(mac_address=mac_address)
        .order_by(VisibilityWindow.last_seen.desc())
        .first()
    )

    result = _serialize_device(device)
    result["latest_window"] = _serialize_window(latest_window) if latest_window else None
    return result


@v1.get("/devices/{mac_address}/windows")
@limiter.limit("100/minute")
def get_device_windows(
    request: Request,
    mac_address: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
# REST API v1 — Summary
# ---------------------------------------------------------------------------
@v1.get("/summary")
@limiter.limit("60/minute")
def get_summary(
    request: Request,
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
    cutoff = datetime.now(timezone.utc)
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Dashboard (HTMX)
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_db)) -> HTMLResponse:
    """Render the HTMX-powered dashboard.

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
            "now": datetime.now(timezone.utc),
        },
    )


@v1.get("/devices-table", response_class=HTMLResponse)
def devices_table_fragment(
    request: Request,
    page: int = Query(1, ge=1),
    session: Session = Depends(get_db),
) -> HTMLResponse:
    """HTMX fragment: device table rows for live updates.

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
            "now": datetime.now(timezone.utc),
        },
    )


# ---------------------------------------------------------------------------
# Device detail page (visibility windows UI)
# ---------------------------------------------------------------------------
@app.get("/devices/{mac_address}", response_class=HTMLResponse)
def device_detail_page(
    request: Request,
    mac_address: str,
    page: int = Query(1, ge=1),
    session: Session = Depends(get_db),
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
    pages = (total_windows + page_size - 1) // page_size if page_size else 1

    return templates.TemplateResponse(
        request=request,
        name="device_detail.html",
        context={
            "device": device,
            "windows": windows,
            "page": page,
            "pages": pages,
            "total_windows": total_windows,
            "now": datetime.now(timezone.utc),
        },
    )


@app.get("/devices/{mac_address}/timeline", response_class=HTMLResponse)
def device_timeline_page(
    request: Request,
    mac_address: str,
    gap_minutes: int = Query(60, ge=1, le=10080, description="Gap threshold in minutes."),
    session: Session = Depends(get_db),
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
            "now": datetime.now(timezone.utc),
        },
    )


@v1.get("/devices/{mac_address}/windows-table", response_class=HTMLResponse)
def windows_table_fragment(
    request: Request,
    mac_address: str,
    page: int = Query(1, ge=1),
    session: Session = Depends(get_db),
) -> HTMLResponse:
    """HTMX fragment: visibility windows table rows for a device.

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
    pages = (total_windows + page_size - 1) // page_size if page_size else 1

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
@v1.post("/auth/token")
@limiter.limit("10/minute")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> dict[str, Any]:
    """Obtain a JWT access token (OAuth2 password flow).

    Only available when ``api.auth_enabled=true``.  When auth is disabled
    (default), this endpoint still responds but issues tokens that are
    ignored by protected endpoints.

    Args:
        request: FastAPI request (required by rate limiter).
        username: API username.
        password: Plain-text password.

    Returns:
        ``{"access_token": "...", "token_type": "bearer"}``
    """
    from src.auth import (
        _jwt_algorithm,
        _jwt_secret,
        authenticate_user,
        create_access_token,
        get_jwt_expire_minutes,
    )

    if not authenticate_user(username, password):
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        {"sub": username},
        secret=_jwt_secret,
        algorithm=_jwt_algorithm,
        expires_minutes=get_jwt_expire_minutes(),
    )
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
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
        writer.writerow({f: getattr(d, f, "") for f in _DEVICE_CSV_FIELDS})
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
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
    mac_address: str | None = Query(None, description="Filter by MAC address"),
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
        writer.writerow({f: getattr(w, f, "") for f in _WINDOW_CSV_FIELDS})
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=windows.csv"},
    )


# ---------------------------------------------------------------------------
# Timeline endpoint
# ---------------------------------------------------------------------------
@v1.get("/devices/{mac_address}/timeline")
@limiter.limit("100/minute")
def get_device_timeline(
    request: Request,
    mac_address: str,
    gap_minutes: int = Query(
        60,
        ge=1,
        le=10080,
        description="Minimum gap (minutes) between windows to be reported as a gap period.",
    ),
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Device not found")

    windows: list[VisibilityWindow] = (
        session.query(VisibilityWindow)
        .filter_by(mac_address=mac_address)
        .order_by(VisibilityWindow.first_seen.asc())
        .all()
    )

    entries: list[dict[str, Any]] = []
    gap_threshold_seconds = gap_minutes * 60

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
@v1.get("/devices/{mac_address}/merge-candidates")
@limiter.limit("30/minute")
def get_merge_candidates(
    request: Request,
    mac_address: str,
    session: Session = Depends(get_db),
    _user: str | None = Depends(require_auth),
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
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Device not found")

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
