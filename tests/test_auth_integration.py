"""Security regression tests across browser sessions, API auth, CSRF, and CORS."""

import re
from collections.abc import Generator
from datetime import UTC, datetime

import bcrypt  # type: ignore[import-untyped]
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from src.api import app, configure_app, get_db, set_engine
from src.config import AppConfig
from src.database import get_session
from src.models import Base, Device


@pytest.fixture()
def authenticated_client(tmp_path) -> Generator[TestClient]:
    """Create a fully configured authenticated app with isolated storage."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with get_session(engine) as session:
        session.add(
            Device(
                mac_address="AA:BB:CC:DD:EE:FF",
                device_type="network",
                device_name="Test device",
                created_at=now,
                updated_at=now,
            )
        )

    password_hash = bcrypt.hashpw(b"correct horse", bcrypt.gensalt(rounds=10)).decode()
    config = AppConfig()
    config.api.auth_enabled = True
    config.api.jwt_secret = "integration-test-secret-that-is-at-least-32-bytes"
    config.api.api_users = {"reviewer": password_hash}
    config.api.cors_origins = ["https://trusted-ui.example"]
    config.api.photo_directory = str(tmp_path / "photos")

    def _override_get_db() -> Generator[Session]:
        with get_session(engine) as session:
            yield session

    configure_app(config)
    set_engine(engine)
    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app, base_url="http://localhost", follow_redirects=False) as client:
            yield client
    finally:
        app.dependency_overrides.clear()
        set_engine(None)
        configure_app(AppConfig())
        engine.dispose()


def test_authentication_csrf_and_cors_work_together(authenticated_client: TestClient) -> None:
    """Exercise both auth transports and browser mutation protections."""
    client = authenticated_client

    page = client.get("/")
    assert page.status_code == 303
    assert page.headers["location"].startswith("/login?next=/")
    rejected_host = client.get("/api/v1/health", headers={"Host": "attacker.example"})
    assert rejected_host.status_code == 400
    assert rejected_host.headers["x-frame-options"] == "DENY"

    anonymous_api = client.get("/api/v1/devices")
    assert anonymous_api.status_code == 401
    assert client.get("/metrics").status_code == 401
    assert client.get("/docs").status_code == 401
    assert client.get("/openapi.json").status_code == 401

    token_response = client.post(
        "/api/v1/auth/token",
        data={"username": "reviewer", "password": "correct horse"},
    )
    assert token_response.status_code == 200
    token = token_response.json()["access_token"]
    assert client.get("/api/v1/devices", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert client.get("/openapi.json", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    login_page = client.get("/login")
    assert login_page.status_code == 200
    assert client.cookies.get("csrftoken")

    cross_origin_login = client.post(
        "/login",
        data={"username": "reviewer", "password": "correct horse", "next": "/"},
        headers={"Origin": "https://attacker.example"},
    )
    assert cross_origin_login.status_code == 403

    login_response = client.post(
        "/login",
        data={"username": "reviewer", "password": "correct horse", "next": "/"},
    )
    assert login_response.status_code == 303
    session_cookie = login_response.headers["set-cookie"]
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie
    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert dashboard.headers["cache-control"] == "no-store"
    content_security_policy = dashboard.headers["content-security-policy"]
    nonce_match = re.search(r"script-src 'self' 'nonce-([^']+)'", content_security_policy)
    assert nonce_match is not None
    assert "'unsafe-inline'" not in content_security_policy.split("style-src", maxsplit=1)[0]
    assert f'nonce="{nonce_match.group(1)}"' in dashboard.text
    assert "unpkg.com" not in dashboard.text

    notes_url = "/api/v1/devices/AA:BB:CC:DD:EE:FF/notes"
    assert client.patch(notes_url, data={"label": "Router", "notes": "Known device"}).status_code == 403

    csrf_token = client.cookies["csrftoken"]
    saved = client.patch(
        notes_url,
        data={"label": "Router", "notes": "Known device"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert saved.status_code == 200
    assert saved.json()["label"] == "Router"

    preflight = client.options(
        notes_url,
        headers={
            "Origin": "https://trusted-ui.example",
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "X-CSRFToken",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "https://trusted-ui.example"
    assert "PATCH" in preflight.headers["access-control-allow-methods"]

    rejected_upload = client.post(
        "/api/v1/devices/AA:BB:CC:DD:EE:FF/photo",
        files={"photo": ("device.png", b"not an image", "image/png")},
        headers={"X-CSRFToken": csrf_token},
    )
    assert rejected_upload.status_code == 415

    logout = client.post("/logout", headers={"X-CSRFToken": csrf_token})
    assert logout.status_code == 303
    assert client.get("/").status_code == 303
