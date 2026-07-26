"""Integration test: bring up docker-compose stack and verify endpoints respond."""

from __future__ import annotations

import os
import socket
import time
from typing import TYPE_CHECKING

import pytest
import requests

if TYPE_CHECKING:
    from collections.abc import Generator

COMPOSE_PROJECT = "net-sentry-integration"


def _get_free_ports(count: int) -> list[int]:
    """Allocate distinct loopback ports for the isolated Compose project."""
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
        return [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


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
@pytest.mark.timeout(600)
class TestDockerComposeStack:
    """Tests that start the full docker-compose stack and probe its endpoints.

    These tests are skipped if Docker is not available on the host.
    Run them with::

        pytest -m integration tests/test_docker_compose_integration.py
    """

    @pytest.fixture(scope="class", autouse=True)
    @classmethod
    def compose_stack(cls) -> Generator[dict[str, str]]:
        """Start the dashboards stack, yield, then tear it down."""
        import subprocess

        api_port, prometheus_port, grafana_port = _get_free_ports(3)
        endpoints = {
            "api": f"http://127.0.0.1:{api_port}",
            "prometheus": f"http://127.0.0.1:{prometheus_port}",
            "grafana": f"http://127.0.0.1:{grafana_port}",
        }
        compose_env = os.environ.copy()
        compose_env.update(
            {
                "NET_SENTRY_PUBLISHED_PORT": str(api_port),
                "PROMETHEUS_PUBLISHED_PORT": str(prometheus_port),
                "GRAFANA_PUBLISHED_PORT": str(grafana_port),
            }
        )
        compose_base = [
            "docker",
            "compose",
            "--project-name",
            COMPOSE_PROJECT,
            "--profile",
            "dashboards",
        ]

        def run_compose(*args: str, timeout: int) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [*compose_base, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=compose_env,
                timeout=timeout,
            )

        def cleanup() -> subprocess.CompletedProcess[str]:
            return run_compose("down", "-v", "--remove-orphans", timeout=90)

        try:
            availability = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        except FileNotFoundError:
            pytest.skip("docker compose not available on this host")
        except subprocess.TimeoutExpired:
            pytest.skip("Docker daemon availability check timed out")

        if availability.returncode != 0:
            pytest.skip(f"Docker daemon not available: {availability.stderr}")

        try:
            result = run_compose("up", "-d", "--build", timeout=480)
        except subprocess.TimeoutExpired:
            cleanup()
            pytest.fail("docker compose up timed out after 480 seconds")

        if result.returncode != 0:
            cleanup()
            pytest.fail(f"docker compose up failed:\n{result.stdout}\n{result.stderr}")

        try:
            yield endpoints
        finally:
            teardown = cleanup()
            if teardown.returncode != 0:
                pytest.fail(f"docker compose teardown failed:\n{teardown.stdout}\n{teardown.stderr}")

    def test_api_health_endpoint(self, compose_stack: dict[str, str]) -> None:
        """The Net Sentry API health endpoint returns 200."""
        api_base = compose_stack["api"]
        assert _wait_for(f"{api_base}/api/v1/health", timeout=60), "API did not come up in time"
        resp = requests.get(f"{api_base}/api/v1/health", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("status") == "healthy"

    def test_api_metrics_endpoint(self, compose_stack: dict[str, str]) -> None:
        """The Prometheus /metrics endpoint is reachable."""
        resp = requests.get(f"{compose_stack['api']}/metrics", timeout=10)
        assert resp.status_code == 200
        assert "net_sentry" in resp.text

    def test_api_dashboard_renders(self, compose_stack: dict[str, str]) -> None:
        """The dashboard renders without a 5xx error."""
        resp = requests.get(f"{compose_stack['api']}/", timeout=10)
        assert resp.status_code == 200
        assert "Net Sentry" in resp.text

    def test_prometheus_accessible(self, compose_stack: dict[str, str]) -> None:
        """Prometheus is accessible and the ready endpoint returns 200."""
        prometheus_base = compose_stack["prometheus"]
        assert _wait_for(f"{prometheus_base}/-/ready", timeout=60), "Prometheus did not come up in time"
        resp = requests.get(f"{prometheus_base}/-/ready", timeout=10)
        assert resp.status_code == 200

    def test_grafana_accessible(self, compose_stack: dict[str, str]) -> None:
        """Grafana is accessible (login page returns 200)."""
        grafana_base = compose_stack["grafana"]
        assert _wait_for(f"{grafana_base}/login", timeout=90), "Grafana did not come up in time"
        resp = requests.get(f"{grafana_base}/login", timeout=10)
        assert resp.status_code == 200
