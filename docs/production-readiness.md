# Production Readiness & Security Review

## Executive assessment

Net Sentry is suitable for a local, trusted-network deployment and ships a
tested hardened reverse-proxied deployment profile. The application fails
closed on invalid security configuration, applies one authorization policy
across its browser and API surfaces, bounds active scanning work, ships its
migrations and templates correctly, and treats quality/security failures as CI
blockers.

The project deliberately does **not** claim to be an internet-facing identity
provider or an enterprise network sensor. The included Caddy boundary handles
TLS and file-mounted secrets; multi-factor identity, centralized revocation,
managed secret rotation, and distributed rate limiting remain deployment
concerns.

## Review priorities

The following list is ordered by severity first, then exploitability and
bang-for-buck.

| Priority | Risk / finding | Resolution and evidence | Status |
| --- | --- | --- | --- |
| P0 | Runtime auth configuration was not guaranteed to be applied before serving requests | Startup and lifespan both call `configure_app`; invalid authenticated configurations raise before the service starts | Closed |
| P0 | Dashboard, fragments, media, metrics, and API docs could diverge from API authorization | All sensitive surfaces use `require_auth` or `require_ui_auth`; health remains intentionally public and minimal | Closed |
| P0 | Browser login/mutations and API bearer auth had conflicting CSRF assumptions | Browser cookies use same-site policy and CSRF checks; bearer requests bypass cookie CSRF; login rejects cross-origin posts | Closed |
| P0 | Default non-local bind and broad container network capabilities increased blast radius | Host default is `127.0.0.1`; Compose publishes on localhost, drops all capabilities, runs non-root/read-only, and requires explicit monitor-mode overrides | Closed |
| P1 | CI security scans reported results but could not fail the build | `pip-audit`, Bandit, Trivy filesystem/image scans, integration/E2E, and ZAP are blocking | Closed |
| P1 | Application, CI, and container builds could resolve different dependency versions | A committed cross-platform `uv.lock` is checked by CI and consumed with `--locked` by every job and the multi-stage runtime image | Closed |
| P1 | Remote deployment guidance lacked an executable TLS, proxy-trust, and secret boundary | The production Compose profile runs pinned non-root Caddy, automatic HTTPS, file-backed credentials, exact hosts/origins, and CIDR-scoped forwarded-header trust; an end-to-end test exercises it | Closed |
| P1 | JWT and HTTP dependencies resolved to packages with known advisories | Replaced `python-jose`/`ecdsa` with PyJWT and raised patched minimums for FastAPI, Starlette, aiohttp, and python-multipart | Closed |
| P1 | Compose integration could skip real startup failures and collided with common host ports | Docker-available startup failures now fail the suite; tests use an isolated project and dynamic ports; published ports remain configurable with safe defaults | Closed |
| P1 | Unbounded subnet materialization enabled accidental resource exhaustion | Ping sweeps enforce a global target cap before scheduling; SNMP host generation is lazy and bounded | Closed |
| P1 | Custom model-driven schema mutation competed with Alembic | Packaged Alembic revisions are authoritative; a one-time compatibility bridge upgrades and stamps legacy unversioned databases | Closed |
| P1 | Uploads trusted filename extensions and lived under source/package paths | Content signatures, size limits, UUID names, configured data storage, authenticated serving, and safe replacement are enforced | Closed |
| P1 | CSV exports allowed spreadsheet formula execution | All string cells are escaped before CSV serialization in API and CLI paths | Closed |
| P1 | Wheel omitted runtime templates/migrations; CLI export entry point could execute before helper definition | Package data is explicit, CI installs the built wheel in isolation, and the module entry point is at end-of-file | Closed |
| P2 | CDN-hosted dashboard scripts expanded availability and supply-chain trust | Dashboard and timeline use first-party dependency-free JavaScript; the main UI CSP uses per-request nonces | Closed |
| P2 | Host-header attacks and stale user tokens were not explicitly handled | Trusted-host allowlist is configurable; decoded JWT subjects must still exist in the active user map | Closed |
| P2 | Outbound integration URLs accepted arbitrary schemes | Configuration accepts only absolute HTTP(S) webhook and Home Assistant URLs | Closed |
| P2 | API-created database engines and E2E servers lacked explicit ownership cleanup | Lifespan disposes only engines it owns; browser fixtures request shutdown and verify thread termination | Closed |
| P2 | Packaging metadata disagreed with the accepted OpenTelemetry dependency ADR | Core SDK/instrumentation, optional OTLP exporter, standalone requirements, and supported test client dependencies are aligned and regression-tested | Closed |

## Authentication model

Two transports share the same token validation and active-user check:

- API clients send `Authorization: Bearer <JWT>`.
- Browser users receive an HttpOnly, `SameSite=Strict` session cookie after
  login.

JWTs include `sub`, `iat`, `exp`, `jti`, and an access-token type marker. Only
HMAC algorithms explicitly allowed by configuration are accepted. Authenticated
startup requires:

- at least one named user;
- a 32-byte-or-longer signing secret;
- structurally valid bcrypt hashes with cost factor 10 or higher;
- exact CORS origins;
- a non-wildcard trusted-host allowlist.

The same signing secret and user map can be supplied through mutually exclusive
direct environment variables or `*_FILE` paths. The production profile uses
Compose-mounted files so credential values are not embedded in the service
environment.

Password verification performs a dummy bcrypt calculation for unknown users to
reduce username-enumeration timing differences. Login and token issuance are
rate-limited.

## Browser and HTTP controls

- Double-submit CSRF protection covers mutating cookie-authenticated API calls
  and logout.
- Cross-origin login POSTs are rejected.
- CSP uses a unique nonce for first-party scripts; object embedding, framing,
  and foreign connections are denied.
- Sensitive responses default to `Cache-Control: no-store`.
- `X-Frame-Options`, `X-Content-Type-Options`, HSTS on HTTPS, referrer policy,
  permissions policy, COOP, and CORP are set centrally.
- CORS permits only configured origins, required methods, and required headers.
- Request IDs accept only a bounded safe character set; otherwise a UUID is
  generated.
- Proxy headers are disabled by default. When enabled, trusted peers must be
  explicit IP addresses/CIDR networks (or a deliberately hardened wildcard);
  the production profile uses its dedicated internal proxy subnet.

## Data and migration integrity

Alembic revisions live under `src/migrations/`, are included in wheels, and run
automatically during `init_database()`. A database that predates Alembic is
detected by the presence of application tables without `alembic_version`.
Net Sentry then:

1. aligns missing legacy columns and indexes once;
2. verifies the unique device-identity invariant;
3. stamps the current Alembic head;
4. uses only versioned revisions from that point forward.

SQLite enables WAL for concurrent scanner/API access. PostgreSQL remains
available through the `postgres` optional dependency and Compose profile.

## Verification contract

Local commands mirror the CI gates:

```bash
uv lock --check
uv sync --locked --extra dev
uv run --no-sync ruff check src tests
uv run --no-sync ruff format --check src tests
uv run --no-sync mypy src --ignore-missing-imports
uv run --no-sync pytest tests/ -m "not integration and not e2e" --cov=src --cov-report=term-missing
uv run --no-sync bandit -r src -ll -q
uv export --quiet --locked --all-extras --no-hashes --no-emit-project --output-file .audit-requirements.txt
uv run --no-sync pip-audit --requirement .audit-requirements.txt --strict --desc on
uv run --no-sync python -m build
docker compose config
```

High-value regression suites:

- `tests/test_auth_integration.py`: auth transports, protected surfaces, CSRF,
  login origin, CORS, CSP nonce, host validation, logout, and upload rejection.
- `tests/test_database.py`: startup, legacy compatibility, and migration
  behavior.
- `tests/test_network_discovery_subprocess.py`: bounded ping targets and safe
  subprocess behavior.
- `tests/e2e/test_dashboard_e2e.py`: browser behavior without third-party
  runtime scripts.
- `tests/test_database_integration.py`: real PostgreSQL CRUD and Alembic
  upgrade/downgrade.
- `tests/test_docker_compose_integration.py`: built API container, dashboard,
  metrics, Prometheus, Grafana, dynamic host ports, and teardown.
- `tests/test_production_compose_integration.py`: pinned locked image,
  non-root Caddy, HTTPS redirect/headers, mounted auth secrets, exact-origin
  login, and secure session cookies.

Locally executed evidence:

- Unit/API suite: **723 passed**, **84.71% coverage**, with no
  project-owned resource warnings.
- PostgreSQL/Testcontainers: **13 passed**.
- Chromium/Playwright E2E: **14 passed**.
- Full Docker Compose dashboards stack: **5 passed**.
- Production HTTPS Compose profile: **3 passed**.
- Universal dependency lock: **current across supported Python/platform
  markers**.
- Strict project dependency audit: **no known vulnerabilities**.

## Remaining risks and recommended next investments

These are not hidden; they define the sensible next iteration.

| Rank | Residual risk | Severity in stated deployment | Recommended investment |
| --- | --- | --- | --- |
| 1 | Built-in username/password auth has no MFA, refresh-token rotation, or centralized revocation | High if exposed directly to the internet; Low on localhost/private LAN | Put the service behind an OIDC-capable reverse proxy and disable direct ingress |
| 2 | Rate limiting is process-local | Medium for multi-replica deployments | Use Redis-backed limits at the proxy or application layer |
| 3 | SNMP support is v2c and community strings are plaintext by protocol design | Medium on untrusted networks | Add SNMPv3 auth/privacy support and redact credentials from diagnostics |
| 4 | Some advanced scanners need host-specific privileges or device passthrough | Medium if combined with the web process | Split scanner and API into separate services with a narrow queue/database boundary |
| 5 | Legacy database bootstrap is intentionally permissive to preserve old installs | Low to Medium during upgrade | Add backup/restore automation and migration fixtures for every historical release |
| 6 | Host-file secrets are safer than environment values but are not a managed rotation system | Low for a single host; Medium across a fleet | Integrate Docker/Kubernetes secrets or a cloud vault and automate rotation/restart |
| 7 | Security headers for Swagger/ReDoc still permit their official CDN assets | Low, and docs are authenticated when auth is enabled | Vendor documentation assets or disable interactive docs in hardened production profiles |

## Deployment decision

- **Accept for local/private-network use:** yes.
- **Accept for a professionally managed reverse-proxied deployment:** yes,
  using the included production profile with valid DNS, exact origin settings,
  protected secret files, and operational backup/monitoring.
- **Accept for direct public-internet exposure:** no; use an identity-aware TLS
  proxy and network policy first.
