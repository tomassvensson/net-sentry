"""Integration test: bring up docker-compose stack and verify endpoints respond."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest
import requests

if TYPE_CHECKING:
    from collections.abc import Generator

COMPOSE_FILE = "docker-compose.yml"
API_BASE = "http://localhost:8000"
PROMETHEUS_BASE = "http://localhost:9090"
GRAFANA_BASE = "http://localhost:3000"


def _wait_for(url: str, timeout: int = 60, interval: float = 2.0) -> bool:
    """Poll *url* until it returns a 2xx/3xx or *timeout* seconds elapse."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code < 500:
                return True
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(interval)
    return False


@pytest.mark.integration
@pytest.mark.timeout(300)
class TestDockerComposeStack:
    """Tests that start the full docker-compose stack and probe its endpoints.

    These tests are skipped if Docker is not available on the host.
    Run them with::

        pytest -m integration tests/test_docker_compose_integration.py
    """

    @pytest.fixture(scope="class", autouse=True)
    def compose_stack(self) -> Generator[None, None, None]:
        """Start the dashboards stack, yield, then tear it down."""
        import subprocess

        docker_cmd = ["docker", "compose", "--profile", "dashboards", "up", "-d", "--build"]
        try:
            result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=180)
        except FileNotFoundError:
            pytest.skip("docker compose not available on this host")
        except subprocess.TimeoutExpired:
            pytest.skip("docker compose up timed out")

        if result.returncode != 0:
            pytest.skip(f"docker compose up failed: {result.stderr}")

        yield

        subprocess.run(
            ["docker", "compose", "--profile", "dashboards", "down", "-v", "--remove-orphans"],
            capture_output=True,
            timeout=60,
        )

    def test_api_health_endpoint(self) -> None:
        """The Net Sentry API health endpoint returns 200."""
        assert _wait_for(f"{API_BASE}/api/v1/health", timeout=60), "API did not come up in time"
        resp = requests.get(f"{API_BASE}/api/v1/health", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "ok"

    def test_api_metrics_endpoint(self) -> None:
        """The Prometheus /metrics endpoint is reachable."""
        resp = requests.get(f"{API_BASE}/metrics", timeout=10)
        assert resp.status_code == 200
        assert "net_sentry" in resp.text

    def test_api_dashboard_renders(self) -> None:
        """The HTMX dashboard renders without a 5xx error."""
        resp = requests.get(f"{API_BASE}/", timeout=10)
        assert resp.status_code == 200
        assert "Net Sentry" in resp.text

    def test_prometheus_accessible(self) -> None:
        """Prometheus is accessible and the ready endpoint returns 200."""
        assert _wait_for(f"{PROMETHEUS_BASE}/-/ready", timeout=60), "Prometheus did not come up in time"
        resp = requests.get(f"{PROMETHEUS_BASE}/-/ready", timeout=10)
        assert resp.status_code == 200

    def test_grafana_accessible(self) -> None:
        """Grafana is accessible (login page returns 200)."""
        assert _wait_for(f"{GRAFANA_BASE}/login", timeout=90), "Grafana did not come up in time"
        resp = requests.get(f"{GRAFANA_BASE}/login", timeout=10)
        assert resp.status_code == 200
