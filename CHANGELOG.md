# Changelog

All notable changes to **Net Sentry** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- JWT authentication enabled by default in `config.yaml.example` (`auth_enabled: true`).
- Tightened rate limit on `POST /api/v1/auth/token` to 5 requests/minute to mitigate brute-force.
- CSRF protection middleware (double-submit cookie pattern) for HTMX dashboard POSTs.
- Auto-generation of JWT secret key when the config still contains the placeholder value.
- Correlation-ID middleware: every HTTP response now carries `X-Request-ID` and the ID is injected into structured logs.
- `fingerprint_confidence` column on `Device` model; surfaced as a badge in the device detail UI.
- `mdns.service_types` config list — restrict which mDNS service types are queried.
- Webhook alert dispatcher (`WebhookDispatcher`) in `src/alert.py`, compatible with Slack and PagerDuty.
- Chart.js sparkline on the device timeline page to visualise signal-strength over time.
- `src/dhcp_scanner.py` — import device/hostname info from ISC DHCP lease files (`/var/lib/dhcp/dhcpd.leases`).
- IPv6 privacy-address de-duplication heuristic in `src/ipv6_scanner.py`.
- Parallel scanner execution via `ThreadPoolExecutor` in `src/main.py`.
- Bulk ARP device upserts using `INSERT … ON CONFLICT DO UPDATE` in `src/device_tracker.py`.
- OpenTelemetry trace-context propagation to scanner calls in `src/main.py`.
- `opentelemetry-exporter-otlp-proto-grpc` as optional `[observability]` extra in `pyproject.toml`.
- ADR 003 documenting the OpenTelemetry optional-dependency design decision.
- SQLite WAL journal mode (`PRAGMA journal_mode=WAL`) enabled on database init.
- LRU cache (`functools.lru_cache`) on OUI prefix lookups for faster repeated MAC-to-vendor resolution.
- `asyncio_mode = "strict"` enforcement via session-scoped conftest fixture.
- Molecule test scenario for the Ansible role (docker driver, Debian Bookworm).
- `CHANGELOG.md` (this file) and PyPI publish trigger on GitHub Release events.
- `[observability]` optional extra documented in `README.md`.

### Changed
- `config.yaml.example`: `api.auth_enabled` default changed from `false` to `true`.
- `POST /api/v1/auth/token` rate limit tightened from 10/minute to 5/minute.

### Fixed
- CSP header already present in `SecurityHeadersMiddleware` (no change needed).
- Multi-arch Docker image already built for `linux/amd64` and `linux/arm64` (no change needed).
- `ruff-format` hook already present in `.pre-commit-config.yaml` (no change needed).

---

## [0.1.0] — 2025-07-01

### Added
- Initial public release.
- WiFi AP and station scanning via `netsh` (Windows) and `iwlist`/`iw` (Linux).
- Bluetooth device scanning via PowerShell / BlueZ.
- ARP table scanning for network device discovery.
- mDNS service discovery (pure-Python, no zeroconf dependency).
- SSDP/UPnP device discovery.
- NetBIOS name scanning.
- SNMP community scanning.
- IPv6 neighbor discovery.
- Port scanning with human-readable service names.
- Home Assistant device name enrichment.
- OUI vendor lookup with local IEEE CSV cache and auto-update workflow.
- Device fingerprinting with Bayesian confidence scoring.
- MAC address merge logic for randomized-MAC de-duplication.
- FastAPI REST API (`/api/v1/`) with JWT authentication, CORS, and rate limiting.
- HTMX dashboard for browsing devices and visibility windows.
- Device detail, timeline, and label/notes/photo pages.
- Prometheus metrics endpoint (`/metrics`).
- OpenTelemetry tracing support (console and OTLP exporters).
- MQTT event publishing.
- Grafana dashboard provisioning configs.
- Ansible role for automated deployment.
- Alembic migrations for schema evolution.
- Data retention policy and SQLite VACUUM job.
- CSV/JSON export endpoints.
- Trivy container scanning, Bandit SAST, and SonarCloud integration in CI.
- Playwright E2E tests and Lighthouse CI performance scoring.

[Unreleased]: https://github.com/tomassvensson/net-sentry/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tomassvensson/net-sentry/releases/tag/v0.1.0
