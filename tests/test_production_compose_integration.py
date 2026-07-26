"""Integration tests for the authenticated automatic-HTTPS Compose profile."""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import bcrypt
import pytest
import requests
import urllib3

if TYPE_CHECKING:
    from collections.abc import Generator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PROJECT = f"net-sentry-production-integration-{os.getpid()}"
TEST_PASSWORD = "correct horse battery staple"


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


def _request(method: str, url: str, **kwargs: Any) -> requests.Response:
    """Issue a request without inheriting workstation proxy settings."""
    with requests.Session() as session:
        session.trust_env = False
        return session.request(method, url, **kwargs)


def _wait_for_https(url: str, timeout: int = 90, interval: float = 2.0) -> bool:
    """Wait for Caddy's local test certificate and the upstream API."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = _request("GET", url, timeout=5, verify=False)
            if response.status_code < 500:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(interval)
    return False


@pytest.mark.integration
@pytest.mark.timeout(600)
@pytest.mark.filterwarnings("ignore:Unverified HTTPS request")
class TestProductionComposeStack:
    """Exercise the actual TLS, proxy-trust, secret, and auth boundary."""

    @pytest.fixture(scope="class", autouse=True)
    @classmethod
    def production_stack(
        cls,
        tmp_path_factory: pytest.TempPathFactory,
    ) -> Generator[dict[str, str]]:
        """Start the production profile with ephemeral credentials and ports."""
        secret_dir = tmp_path_factory.mktemp("net-sentry-production-secrets")
        jwt_file = secret_dir / "jwt.txt"
        users_file = secret_dir / "users.json"
        jwt_file.write_text(secrets.token_urlsafe(48), encoding="utf-8")
        password_hash = bcrypt.hashpw(TEST_PASSWORD.encode(), bcrypt.gensalt(rounds=10)).decode()
        users_file.write_text(json.dumps({"reviewer": password_hash}), encoding="utf-8")

        api_port, http_port, https_port = _get_free_ports(3)
        endpoints = {
            "api": f"http://127.0.0.1:{api_port}",
            "http": f"http://localhost:{http_port}",
            "https": f"https://localhost:{https_port}",
        }
        compose_env = os.environ.copy()
        compose_env.update(
            {
                "ACME_EMAIL": "security@example.invalid",
                "CADDY_BIND_ADDRESS": "127.0.0.1",
                "CADDY_HTTP_PUBLISHED_PORT": str(http_port),
                "CADDY_HTTPS_PUBLISHED_PORT": str(https_port),
                "NET_SENTRY_API_USERS_HOST_FILE": users_file.resolve().as_posix(),
                "NET_SENTRY_CORS_ORIGINS": endpoints["https"],
                "NET_SENTRY_JWT_SECRET_HOST_FILE": jwt_file.resolve().as_posix(),
                "NET_SENTRY_PROXY_CIDR": "172.31.254.0/24",
                "NET_SENTRY_PUBLIC_HOST": "localhost",
                "NET_SENTRY_PUBLISHED_PORT": str(api_port),
            }
        )
        compose_base = [
            "docker",
            "compose",
            "--project-name",
            COMPOSE_PROJECT,
            "-f",
            str(PROJECT_ROOT / "docker-compose.yml"),
            "-f",
            str(PROJECT_ROOT / "docker-compose.production.yml"),
            "--profile",
            "production",
        ]

        def run_compose(*args: str, timeout: int) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [*compose_base, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=PROJECT_ROOT,
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

        cleanup()
        try:
            result = run_compose("up", "-d", "--build", timeout=480)
        except subprocess.TimeoutExpired:
            cleanup()
            pytest.fail("production docker compose up timed out after 480 seconds")

        if result.returncode != 0:
            cleanup()
            pytest.fail(f"production docker compose up failed:\n{result.stdout}\n{result.stderr}")

        health_url = f"{endpoints['https']}/api/v1/health"
        if not _wait_for_https(health_url):
            status = run_compose("ps", "-a", timeout=30)
            logs = run_compose("logs", "--no-color", timeout=60)
            cleanup()
            pytest.fail(
                "production HTTPS endpoint did not become ready\n"
                f"compose ps:\n{status.stdout}\n{status.stderr}\n"
                f"compose logs:\n{logs.stdout}\n{logs.stderr}"
            )

        try:
            yield endpoints
        finally:
            teardown = cleanup()
            if teardown.returncode != 0:
                pytest.fail(f"production compose teardown failed:\n{teardown.stdout}\n{teardown.stderr}")

    def test_https_health_and_edge_headers(self, production_stack: dict[str, str]) -> None:
        """Caddy serves the public health check with hardened edge headers."""
        response = _request(
            "GET",
            f"{production_stack['https']}/api/v1/health",
            timeout=10,
            verify=False,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        assert response.headers["strict-transport-security"] == "max-age=31536000; includeSubDomains"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "server" not in response.headers

    def test_http_redirects_to_https(self, production_stack: dict[str, str]) -> None:
        """The plaintext listener does not serve application content."""
        response = _request(
            "GET",
            f"{production_stack['http']}/api/v1/health",
            allow_redirects=False,
            timeout=10,
        )
        assert response.status_code in {301, 302, 307, 308}
        assert response.headers["location"].startswith("https://localhost")

    def test_auth_is_enabled_and_cookie_is_secure(self, production_stack: dict[str, str]) -> None:
        """File-backed users authenticate and receive an HTTPS-only session."""
        https_base = production_stack["https"]
        anonymous = _request("GET", f"{https_base}/", allow_redirects=False, timeout=10, verify=False)
        assert anonymous.status_code == 303
        assert anonymous.headers["location"].startswith("/login?next=/")

        with requests.Session() as session:
            session.trust_env = False
            assert session.get(f"{https_base}/login", timeout=10, verify=False).status_code == 200
            login = session.post(
                f"{https_base}/login",
                data={"username": "reviewer", "password": TEST_PASSWORD, "next": "/"},
                headers={"Origin": https_base},
                allow_redirects=False,
                timeout=10,
                verify=False,
            )

        assert login.status_code == 303
        session_cookie = login.headers["set-cookie"]
        assert "HttpOnly" in session_cookie
        assert "Secure" in session_cookie
        assert "SameSite=strict" in session_cookie
