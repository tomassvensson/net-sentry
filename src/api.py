"""FastAPI application for BtWiFi device dashboard and REST API.

Provides:
- HTMX-powered web dashboard at /
- REST API at /api/v1/ for device history and management
- Prometheus metrics at /metrics
- Health check at /api/v1/health
"""

import logging
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from prometheus_client import generate_latest
from sqlalchemy import func
from sqlalchemy.orm import Session

from src.database import get_session, init_database
from src.models import Device, VisibilityWindow

logger = logging.getLogger(__name__)

# Template directory
_TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

# Module-level engine reference (set during lifespan)
_engine = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initialize DB on startup."""
    global _engine  # noqa: PLW0603
    if _engine is None:
        try:
            _engine = init_database()
        except Exception:
            logger.exception("Failed to initialize database in API lifespan")
    logger.info("API server started, database initialized")
    yield
    logger.info("API server shutting down")


app = FastAPI(
    title="BtWiFi Device Tracker",
    description="Track WiFi and Bluetooth device visibility over time",
    version="0.1.0",
    lifespan=lifespan,
)

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
# Health check
# ---------------------------------------------------------------------------
@app.get("/api/v1/health")
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
@app.get("/api/v1/devices")
def list_devices(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    device_type: str | None = Query(None, description="Filter by device type"),
    session: Session = Depends(get_db),
) -> dict[str, Any]:
    """List all known devices with pagination.

    Args:
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
    devices = (
        query.order_by(Device.updated_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size if page_size else 0,
        "devices": [_serialize_device(d) for d in devices],
    }


@app.get("/api/v1/devices/{mac_address}")
def get_device(
    mac_address: str,
    session: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get device details by MAC address.

    Args:
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


@app.get("/api/v1/devices/{mac_address}/windows")
def get_device_windows(
    mac_address: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> dict[str, Any]:
    """Get visibility windows for a device.

    Args:
        mac_address: Device MAC address.
        page: Page number.
        page_size: Items per page.
        session: Database session.

    Returns:
        Paginated visibility windows.
    """
    query = session.query(VisibilityWindow).filter_by(mac_address=mac_address)
    total = query.count()

    windows = (
        query.order_by(VisibilityWindow.last_seen.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

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
@app.get("/api/v1/summary")
def get_summary(session: Session = Depends(get_db)) -> dict[str, Any]:
    """Get an overview of the device database.

    Args:
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


@app.get("/api/v1/devices-table", response_class=HTMLResponse)
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
        session.query(Device)
        .order_by(Device.updated_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
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


def set_engine(engine: Any) -> None:
    """Set the database engine for the API (used when embedding in scanner).

    Args:
        engine: SQLAlchemy Engine.
    """
    global _engine  # noqa: PLW0603
    _engine = engine
