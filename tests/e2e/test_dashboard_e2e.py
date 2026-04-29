"""Playwright E2E tests for the Net Sentry dashboard.

These tests start the FastAPI application in a background thread and use
Playwright to exercise the browser UI.  They are skipped automatically
when Playwright is not installed or when the ``e2e`` marker is deselected.

Run with::

    pytest tests/e2e/ -m e2e -v --timeout=60

Or as part of the full suite::

    pytest tests/ -m "not integration and not e2e"

to skip them in unit test runs.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

# Skip entire module when playwright is not installed
pytest.importorskip("playwright", reason="playwright is not installed — skipping E2E tests")

from playwright.sync_api import Page, expect, sync_playwright  # noqa: E402  # type: ignore[import]


def _chromium_available() -> bool:
    """Return True when the Playwright Chromium binary is installed locally."""
    try:
        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).exists()
    except Exception:
        return False


if not _chromium_available():
    pytest.skip("Playwright Chromium browser is not installed — skipping E2E tests", allow_module_level=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_free_port() -> int:
    """Return an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(port: int) -> threading.Thread:
    """Launch the FastAPI app in a daemon thread on *port*."""
    import uvicorn  # type: ignore[import]

    from src.api import app

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    def _run() -> None:
        server.run()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()

    # Wait up to 5 s for the server to become ready
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return thread
        except OSError:
            time.sleep(0.05)

    raise RuntimeError(f"Test server did not start on port {port} within 5 s")


# ---------------------------------------------------------------------------
# Session-scoped server fixture
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def base_url() -> Generator[str, None, None]:
    """Start the FastAPI server once per test session and yield the base URL."""
    port = _get_free_port()
    _start_server(port)
    yield f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.timeout(60)
class TestDashboard:
    """E2E tests for the main dashboard page (/)."""

    def test_page_title(self, page: Page, base_url: str) -> None:
        """The page title should contain 'BtWiFi'."""
        page.goto(base_url)
        expect(page).to_have_title("Net Sentry Device Tracker")

    def test_header_present(self, page: Page, base_url: str) -> None:
        """The header h1 should display the application name."""
        page.goto(base_url)
        heading = page.locator(".header h1")
        expect(heading).to_have_text("Net Sentry Device Tracker")

    def test_device_table_rendered(self, page: Page, base_url: str) -> None:
        """The device table wrapper should be present in the DOM."""
        page.goto(base_url)
        table = page.locator("table")
        expect(table).to_be_visible()

    def test_table_has_expected_columns(self, page: Page, base_url: str) -> None:
        """The table header should contain the required column names."""
        page.goto(base_url)
        header_row = page.locator("thead tr")
        expected_columns = ["MAC Address", "Type", "Vendor", "Last Seen"]
        for col in expected_columns:
            expect(header_row).to_contain_text(col)

    def test_refresh_button_present(self, page: Page, base_url: str) -> None:
        """A Refresh button should be visible in the header controls."""
        page.goto(base_url)
        refresh_btn = page.get_by_role("button", name="Refresh")
        expect(refresh_btn).to_be_visible()

    def test_theme_toggle_present(self, page: Page, base_url: str) -> None:
        """The theme-toggle button should be present."""
        page.goto(base_url)
        toggle = page.locator("#theme-toggle")
        expect(toggle).to_be_visible()

    def test_no_console_errors(self, page: Page, base_url: str) -> None:
        """The page should not produce any console error messages."""
        errors: list[str] = []
        page.on("console", lambda msg: errors.append(msg.text) if msg.type == "error" else None)
        page.goto(base_url)
        # Allow time for HTMX to load
        page.wait_for_timeout(1500)
        assert errors == [], f"Console errors: {errors}"

    def test_stat_total_devices(self, page: Page, base_url: str) -> None:
        """The total-devices stat counter should be present and numeric."""
        page.goto(base_url)
        stat_value = page.locator(".stat-value").first
        expect(stat_value).to_be_visible()
        text = stat_value.inner_text()
        assert text.strip().isdigit(), f"Expected numeric stat value, got: {text!r}"

    def test_htmx_script_loaded(self, page: Page, base_url: str) -> None:
        """The page should load the HTMX script."""
        page.goto(base_url)
        # HTMX attaches itself to window.htmx once loaded
        page.wait_for_timeout(1000)
        htmx_defined = page.evaluate("typeof window.htmx !== 'undefined'")
        assert htmx_defined, "window.htmx is not defined — HTMX did not load"


@pytest.mark.e2e
@pytest.mark.timeout(60)
class TestHealthEndpoint:
    """E2E sanity check for the /api/v1/health JSON endpoint."""

    def test_health_returns_200(self, page: Page, base_url: str) -> None:
        """GET /api/v1/health should return HTTP 200."""
        response = page.request.get(f"{base_url}/api/v1/health")
        assert response.status == 200

    def test_health_json_structure(self, page: Page, base_url: str) -> None:
        """Health response should have status and version keys."""
        response = page.request.get(f"{base_url}/api/v1/health")
        body = response.json()
        assert "status" in body
        assert body["status"] == "healthy"

    def test_openapi_docs_available(self, page: Page, base_url: str) -> None:
        """The /docs (Swagger UI) page should load successfully."""
        page.goto(f"{base_url}/docs")
        # Swagger UI renders a div with id="swagger-ui"
        swagger_ui = page.locator("#swagger-ui")
        expect(swagger_ui).to_be_visible(timeout=10000)


@pytest.mark.e2e
@pytest.mark.timeout(60)
class TestApiDevicesTable:
    """E2E tests for the HTMX /api/v1/devices-table fragment."""

    def test_devices_table_fragment_returns_html(self, page: Page, base_url: str) -> None:
        """The HTMX fragment endpoint should return HTML content."""
        response = page.request.get(f"{base_url}/api/v1/devices-table?page=1")
        assert response.status == 200
        content_type = response.headers.get("content-type", "")
        assert "text/html" in content_type

    def test_refresh_button_triggers_htmx(self, page: Page, base_url: str) -> None:
        """Clicking Refresh should fire the HTMX request and update the table."""
        page.goto(base_url)
        # Intercept the HTMX request to the devices-table endpoint
        requests: list[str] = []
        page.on("request", lambda req: requests.append(req.url) if "devices-table" in req.url else None)
        page.get_by_role("button", name="Refresh").click()
        # Wait briefly for HTMX request to fire
        page.wait_for_timeout(1000)
        assert any("devices-table" in url for url in requests), (
            "Clicking Refresh did not trigger a request to /api/v1/devices-table"
        )
