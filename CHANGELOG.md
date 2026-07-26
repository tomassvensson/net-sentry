# Changelog

All notable changes to **Net Sentry** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- Browser login/logout with HttpOnly same-site session cookies.
- Cross-cutting security regression coverage for auth, CSRF, CORS, CSP,
  trusted hosts, protected docs/metrics, and uploads.
- Packaged Alembic environment and isolated wheel-install smoke test.
- Production-readiness review with threat model, resolved findings, residual
  risks, and verification contract.
- Hard ping-sweep target limits and lazy bounded SNMP subnet iteration.
- Configurable data directory for authenticated device photos.
- Universal cross-platform `uv.lock` plus a lock-enforced multi-stage runtime
  image and CI installation path.
- Production Caddy Compose profile with automatic HTTPS, isolated proxy
  networking, file-backed authentication secrets, and end-to-end coverage.

### Changed
- Safe listener default changed to `127.0.0.1`; non-local exposure must be
  explicit and pass configuration validation.
- Authenticated startup now requires strong JWT secrets, bcrypt cost 10+,
  active users, exact CORS origins, and trusted hosts.
- Replaced `python-jose` with PyJWT to remove the unmaintained `ecdsa`
  dependency, and raised vulnerable HTTP/parser dependency minimums.
- Aligned package and requirements metadata for core OpenTelemetry support,
  upgraded its FastAPI instrumentation, and moved tests to `httpx2`.
- Dashboard and timeline no longer execute third-party CDN JavaScript.
- Main UI CSP now uses per-request script nonces.
- Docker runs non-root/read-only with all capabilities dropped and localhost
  port publishing by default.
- Production Caddy runs non-root/read-only and retains only the bind-service
  capability required by its pinned official binary.
- Forwarded headers are opt-in and trusted peers are validated as explicit IP
  addresses or CIDR networks.
- CI security, integration, E2E, packaging, DAST, and image-scan jobs are
  blocking.
- CI now executes both real-PostgreSQL and full Docker Compose integration
  suites; unit jobs explicitly exclude browser tests.
- Alembic is the schema source of truth after one-time legacy bootstrap.

### Fixed
- Runtime configuration is applied before API traffic in both launch paths.
- Dashboard, fragments, media, metrics, and API documentation follow the same
  authentication policy as REST endpoints.
- Cookie-authenticated mutations send and validate CSRF tokens; bearer requests
  remain usable without browser CSRF state.
- Photo uploads validate content signatures, size, extension consistency, and
  use unguessable filenames outside the package tree.
- CSV exports neutralize spreadsheet formulas.
- CLI module execution can invoke export helpers reliably.
- Wheel metadata includes templates and migrations.
- API lifespan disposes database engines it creates without taking ownership
  of externally supplied engines.
- Docker Compose integration failures can no longer become skips; the harness
  uses UTF-8 output, dynamic host ports, isolated resources, and verified
  teardown.
- Playwright's local API server now shuts down deterministically.

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
