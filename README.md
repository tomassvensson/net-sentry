# Net Sentry — Network Device Visibility Tracker

[![CI](https://github.com/tomassvensson/net-sentry/actions/workflows/ci.yml/badge.svg)](https://github.com/tomassvensson/net-sentry/actions/workflows/ci.yml)
[![CodeQL](https://github.com/tomassvensson/net-sentry/actions/workflows/codeql.yml/badge.svg)](https://github.com/tomassvensson/net-sentry/actions/workflows/codeql.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=tomassvensson_btwf&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=tomassvensson_btwf)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=tomassvensson_btwf&metric=coverage)](https://sonarcloud.io/summary/new_code?id=tomassvensson_btwf)

> GitHub repo: <https://github.com/tomassvensson/net-sentry>
>
> **⚠️ Legal & Ethics Notice**
> Net Sentry is designed for monitoring **networks and devices that you own or have explicit permission to scan**.
> Scanning networks or devices without authorisation may violate applicable laws (e.g. the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, or equivalent legislation in your jurisdiction).
> By using Net Sentry you confirm that you have the necessary rights or permissions to scan the target environment.
> The authors accept no liability for any misuse.

---

Net Sentry continuously or on-demand scans your wireless and wired environment for devices — WiFi access points, Bluetooth peripherals, ARP-visible hosts, mDNS/SSDP services, and IPv6 neighbours — and persists every *visibility window* (who was visible, when, and how strongly) in a local database.

---

## Features

| Feature | Details |
| --- | --- |
| **WiFi scanning** | Discovers nearby access points (SSID, BSSID, signal, channel, encryption). Uses `netsh` on Windows, `nmcli`/`iw` on Linux |
| **Bluetooth / BLE** | Classic Bluetooth via PowerShell (Windows) or BlueZ; BLE via `bleak` on Linux |
| **ARP table** | Reads the kernel ARP cache for currently-reachable LAN devices |
| **Ping sweep** | ICMP sweep of configured subnets (useful in NAT/WSL2 setups) |
| **Network segments** | Label subnets (`192.168.1.0/24` → `"office"`) for display grouping |
| **Port scanning** | Optional TCP connect-scan of each network device; results cached per device |
| **mDNS / Bonjour** | Discovers `.local` services on the LAN |
| **SSDP / UPnP** | Discovers UPnP-advertising devices |
| **NetBIOS** | Reverse-resolves Windows hostnames from IP |
| **IPv6 NDP** | Reads IPv6 neighbour discovery table |
| **Monitor mode** | Passive 802.11 packet capture via Scapy (Linux / Docker) |
| **SNMP** | Polls SNMP-capable devices for system description |
| **Home Assistant** | Enriches device names and areas from HA `device_tracker.*` entities |
| **OUI vendor lookup** | Maps MAC OUI prefix to manufacturer name |
| **Visibility windows** | Only start/end of each presence window is stored (efficient, not every ping) |
| **REST API** | Versioned FastAPI at `/api/v1/` with JSON endpoints |
| **Web dashboard** | Dependency-free live dashboard at `http://localhost:8000/` |
| **Prometheus metrics** | Scraped at `http://localhost:8000/metrics`; protected when auth is enabled |
| **Grafana dashboard** | Pre-provisioned dashboard (included in repo) |
| **MQTT** | Publishes device events to an MQTT broker |
| **Alerts** | Log / sound / webhook on new device discovery; automatic warnings for devices not seen in 2 weeks |
| **Whitelist** | Mark trusted devices; unknown devices are flagged |
| **Export** | CSV and JSON export via CLI flag or API endpoint |
| **Alembic migrations** | Schema is versioned; upgrades run automatically |
| **Docker** | Locked scanner image, optional Prometheus/Grafana stack, and production automatic-HTTPS profile |

---

## Production-readiness highlights

- One startup path applies validated configuration before serving traffic.
- API, dashboard, uploaded media, metrics, and API docs share one auth policy.
- Browser sessions use HttpOnly, `SameSite=Strict` cookies; API clients use bearer JWTs.
- Mutating cookie-authenticated requests use CSRF protection; bearer requests are not coupled to browser cookies.
- Nonce-based CSP, trusted-host validation, exact-origin CORS, secure upload signatures, and CSV formula escaping are enforced.
- Subnet scans have hard target caps; SNMP subnet iteration is lazy and bounded.
- Alembic revisions ship inside the wheel and are the schema source of truth.
- The application container runs non-root/read-only with all capabilities dropped; the non-root TLS proxy retains only `NET_BIND_SERVICE`.
- A committed universal `uv.lock` is enforced by local setup, CI, and the multi-stage production image.
- The production Compose profile provides automatic HTTPS, file-backed secrets, exact origins/hosts, and CIDR-scoped proxy trust.
- CI treats lint, formatting, typing, tests, dependency audit, SAST, DAST, and HIGH/CRITICAL image findings as blocking.

The rationale, threat model, verification commands, and remaining risks are documented in
[Production Readiness & Security Review](docs/production-readiness.md).

---

## Quick Start

### Prerequisites

- Python 3.10+
- Linux (recommended) or Windows
- For Bluetooth scanning: BlueZ (Linux) or PowerShell (Windows)
- For monitor mode: compatible wireless adapter in monitor mode + Scapy

### Install

```bash
git clone https://github.com/tomassvensson/net-sentry.git
cd net-sentry
python -m pip install "uv==0.11.29"
uv sync --locked --extra dev
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\Activate.ps1

cp config.yaml.example config.yaml
# edit config.yaml as needed
```

`uv.lock` is the canonical reproducible application/development environment.
The standalone requirements files remain compatibility inputs for consumers
that cannot use `uv`.

### Run a single scan

```bash
net-sentry --once
```

### Run continuously

```bash
net-sentry --continuous
# or set continuous: true in config.yaml and run:
net-sentry
```

### Force a fresh TCP port scan

```bash
net-sentry --once --rescan-ports
```

By default this scans the configured shortlist of common TCP ports for speed.
Use a full TCP range scan when you need parity with deeper port scanners:

```bash
net-sentry --once --full-port-scan
```

### Export all known devices

```bash
net-sentry --export csv
net-sentry --export json --output devices.json
```

---

## CLI Reference

```text
net-sentry [OPTIONS]

Options:
  --once            Run a single scan cycle and exit (overrides config.scan.continuous)
  --continuous      Run in continuous loop (overrides config.scan.continuous)
  --rescan-ports    Force fresh TCP port scan for all discovered network devices
  --full-port-scan  Scan TCP ports 1-65535; implies --rescan-ports
  --export csv|json Dump all known devices and exit (no scan)
  --output PATH     Write --export output to file instead of stdout
```

---

## Configuration

Copy `config.yaml.example` to `config.yaml` and edit.  Key sections:

```yaml
scan:
  continuous: false          # override with --continuous / --once
  interval_seconds: 60
  wifi_enabled: true
  bluetooth_enabled: true
  ble_enabled: true
  arp_enabled: true
  snmp_enabled: false
  monitor_mode_enabled: false

ping_sweep:
  enabled: true
  subnets:
    - "192.168.1.0/24"
    - "192.168.2.0/24"
  max_targets: 4096       # hard cap across all configured subnets
  subnet_labels:
    "192.168.1.0/24": "office"
    "192.168.2.0/24": "IoT"

port_scan:
  enabled: true
  ports: [22, 80, 443, 445, 3389, 8080]
  timeout_seconds: 0.5

home_assistant:
  enabled: true
  url: "http://homeassistant.local:8123"
  token: "eyJ..."         # long-lived access token from HA Profile -> Security

api:
  enabled: true
  host: "127.0.0.1"       # safe local default
  port: 8000
  auth_enabled: false     # required before non-local exposure
  cookie_secure: false    # set true behind HTTPS
  allowed_hosts: ["localhost", "127.0.0.1"]
  api_users: {}

mqtt:
  enabled: false
  broker_host: "localhost"
  broker_port: 1883
  topic_prefix: "net-sentry"
```

For an authenticated deployment:

```bash
# Generate a bcrypt hash (cost factor 12 by default)
python -c "import bcrypt; print(bcrypt.hashpw(b'change-this-password', bcrypt.gensalt()).decode())"

# Generate a stable signing secret
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Add the hash under `api.api_users`, set `api.auth_enabled: true`, provide the
secret through `NET_SENTRY_JWT_SECRET`, list the public DNS name under
`api.allowed_hosts`, and set `api.cookie_secure: true` when TLS is enabled.
Startup fails closed if these invariants are not satisfied.

For a remote deployment, use the tested
[production HTTPS profile](deploy/README.md), which reads the signing secret
and user map from mounted files rather than environment values.

---

## REST API

The API is versioned under `/api/v1/`.  OpenAPI docs are at `http://localhost:8000/docs`.

### Interactive docs & schema

```bash
# Swagger UI
open http://localhost:8000/docs
# ReDoc
open http://localhost:8000/redoc
# Raw OpenAPI JSON schema
curl http://localhost:8000/openapi.json
```

### Example requests

```bash
# Health check
curl http://localhost:8000/api/v1/health

# List all devices (paginated)
curl "http://localhost:8000/api/v1/devices?page=1&page_size=20"

# Get a specific device
curl http://localhost:8000/api/v1/devices/aa:bb:cc:dd:ee:ff

# List visibility windows for a device
curl http://localhost:8000/api/v1/devices/aa:bb:cc:dd:ee:ff/windows

# Summary stats
curl http://localhost:8000/api/v1/summary

# Export all devices as JSON
curl http://localhost:8000/api/v1/export/devices.json

# Obtain a JWT (when auth is enabled)
curl -X POST http://localhost:8000/api/v1/auth/token \
     -d 'username=admin&password=changeme'

# Authenticated request
curl -H 'Authorization: Bearer <token>' \
     http://localhost:8000/api/v1/devices
```

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/v1/health` | Public liveness/readiness status |
| `GET` | `/api/v1/devices` | List devices (`page`, `page_size`, `device_type`) |
| `GET` | `/api/v1/devices/{mac}` | Single device with visibility history |
| `GET` | `/api/v1/devices/{mac}/windows` | Paginated visibility windows |
| `PATCH` | `/api/v1/devices/{mac}/notes` | Update operator label and notes |
| `POST` | `/api/v1/devices/{mac}/photo` | Upload a validated JPEG/PNG/GIF/WebP |
| `GET` | `/api/v1/devices/{mac}/timeline` | Timeline and absence gaps |
| `GET` | `/api/v1/export/devices.csv` | Export devices as formula-safe CSV |
| `GET` | `/api/v1/export/devices.json` | Export devices as JSON |
| `GET` | `/api/v1/export/windows.csv` | Export visibility windows |
| `POST` | `/api/v1/auth/token` | Obtain JWT (when auth enabled) |
| `GET` | `/metrics` | Prometheus metrics; authenticated when auth is enabled |
| `GET` | `/docs`, `/redoc`, `/openapi.json` | API docs/schema; authenticated when auth is enabled |
| `GET` | `/` | Live web dashboard |
| `GET` | `/devices/{mac}` | Device detail page |

---

## Metrics & Observability

Net Sentry exposes Prometheus metrics at `/metrics`:

- `net_sentry_devices_total` — gauge of known devices by type
- `net_sentry_scans_total` — scan cycle counter
- `net_sentry_scan_duration_seconds` — scan latency histogram

### Grafana

A pre-built dashboard JSON is included at `grafana/provisioning/dashboards/net-sentry.json`.
It is auto-provisioned when you start the dashboards stack (see Docker section below).

---

## Docker

### Minimal stack (scanner only)

**Linux:**
```bash
docker compose up net-sentry
```

On Docker Desktop for Windows, Bluetooth hardware is not passed through to the Linux container. The compose stack therefore disables Bluetooth and BLE scanners by default while still allowing the service to start. To opt in on a host/container setup that exposes Bluetooth:

```bash
NET_SENTRY_SCAN_BLUETOOTH=true NET_SENTRY_SCAN_BLE=true docker compose up net-sentry
```

### Production HTTPS

The production override enables auth, secure cookies, automatic certificate
management, file-backed secrets, and restricted forwarded-header trust:

```bash
docker compose --env-file .env.production \
  -f docker-compose.yml \
  -f docker-compose.production.yml \
  --profile production up -d --build
```

Follow [deploy/README.md](deploy/README.md) to create the environment and secret
files. The Python service remains loopback-published; Caddy is the public
ingress.

### Full stack (scanner + Prometheus + Grafana)

```yaml
# docker-compose.yml is already in the repo
# Prometheus: http://localhost:9090
# Grafana:    http://localhost:3000  (admin / admin)
```

```bash
docker compose --profile dashboards up
```

If a default host port is occupied, override it without editing Compose:
`NET_SENTRY_PUBLISHED_PORT`, `PROMETHEUS_PUBLISHED_PORT`, or
`GRAFANA_PUBLISHED_PORT`.

### With PostgreSQL

```bash
$env:POSTGRES_PASSWORD = "replace-with-a-strong-password"  # PowerShell
$env:DATABASE_URL = "postgresql+pg8000://net-sentry:$env:POSTGRES_PASSWORD@postgres:5432/net-sentry"
docker compose --profile postgres up
```

### With SonarQube

```bash
docker compose --profile sonarqube up
# SonarQube: http://localhost:9000  (admin / admin)
# First login prompts you to change the password

# Run analysis from host (requires sonar-scanner CLI):
sonar-scanner

# Or use the CI GitHub Action which runs SonarCloud automatically
```

The project is configured with `sonar-project.properties` for static analysis. Check quality gate status with:

```bash
python scripts/check_sonarqube.py --url http://localhost:9000 --project tomassvensson_btwf --token <your-token>
```

---

## Database Migrations

Schema changes are managed with packaged Alembic revisions.

```bash
# Apply all pending migrations
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "my change"
```

Migrations run automatically at startup via `init_database()`. Databases from
pre-Alembic releases are aligned once and stamped; subsequent changes always
flow through versioned revisions under `src/migrations/`.

---

## Development

### Pre-commit hooks

Pre-commit hooks run Ruff, Ruff format, mypy, and Bandit before each commit.

```bash
# Install hooks (once per clone)
pre-commit install

# Run all hooks manually against all files
pre-commit run --all-files

# Update hook versions
pre-commit autoupdate
```

```bash
# Run all tests
pytest --timeout=60

# Run only fast unit tests (skip integration / E2E)
pytest -m "not integration and not e2e" --timeout=60

# Lint + type-check
ruff check .
mypy src/

# Coverage report
pytest --cov=src --cov-report=term-missing
```

---

## Security

- The default listener is `127.0.0.1`; authentication is disabled only for this
  local-development posture. Configuration validation rejects weak authenticated deployments.
- Auth covers the API, dashboard, uploaded media, metrics, and API documentation.
- Browser sessions use HttpOnly cookies plus CSRF checks; API automation uses bearer tokens.
- The default container drops every Linux capability, runs non-root with a read-only root
  filesystem, and publishes only on localhost. Monitor mode must be enabled deliberately
  through a private deployment override.
- Use the production Caddy profile for remote TLS, file-backed secrets, exact
  trusted hosts/origins, and restricted proxy-header trust. Add an OIDC-aware
  identity proxy before any direct public-internet use that requires MFA or
  centralized revocation.
- See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

---

## Architecture

```text
net-sentry/
├── src/
│   ├── main.py            # Entry point: CLI, scan orchestration, display
│   ├── config.py          # Dataclass-based config loader (config.yaml)
│   ├── models.py          # SQLAlchemy ORM models (Device, VisibilityWindow)
│   ├── database.py        # DB init, session factory, retention
│   ├── device_tracker.py  # Visibility window logic
│   ├── api.py             # FastAPI application (REST + live dashboard)
│   ├── auth.py            # JWT auth helpers
│   ├── migrations/        # Packaged Alembic environment and revisions
│   ├── metrics.py         # Prometheus metrics
│   ├── wifi_scanner.py    # WiFi scanning
│   ├── bluetooth_scanner.py  # Classic BT + BLE
│   ├── network_discovery.py  # ARP table + ping sweep (network_segment support)
│   ├── port_scanner.py    # TCP connect-scan with port name resolution
│   ├── home_assistant.py  # HA REST API client for device enrichment
│   ├── mdns_scanner.py    # mDNS/Bonjour
│   ├── ssdp_scanner.py    # SSDP/UPnP
│   ├── netbios_scanner.py # NetBIOS name resolution
│   ├── ipv6_scanner.py    # IPv6 NDP table
│   ├── monitor_scanner.py # 802.11 monitor mode (Scapy)
│   ├── snmp_scanner.py    # SNMP polling
│   ├── mqtt_publisher.py  # MQTT event publishing
│   ├── alert.py           # New-device alerting
│   ├── whitelist.py       # Known-device management
│   ├── categorizer.py     # Device type categorization
│   ├── fingerprint.py     # OS / device fingerprinting
│   └── oui_lookup.py      # MAC vendor resolution
├── tests/                 # pytest unit + integration + E2E tests
├── grafana/               # Grafana provisioning
├── prometheus/            # Prometheus config
├── docs/                  # Architecture decision records
└── docker-compose.yml
```

---

## Reviewer walkthrough

```bash
python -m pip install "uv==0.11.29"
uv lock --check
uv sync --locked --extra dev
uv run --no-sync pytest tests/ -m "not integration and not e2e" --cov=src --cov-report=term-missing
uv run --no-sync ruff check src tests
uv run --no-sync ruff format --check src tests
uv run --no-sync mypy src --ignore-missing-imports
uv run --no-sync bandit -r src -ll -q
uv export --quiet --locked --all-extras --no-hashes --no-emit-project --output-file .audit-requirements.txt
uv run --no-sync pip-audit --requirement .audit-requirements.txt --strict --desc on
uv run --no-sync python -m build
docker compose config
```

Then run `net-sentry --once`, open `http://127.0.0.1:8000`, and inspect
`/docs`. The focused cross-cutting security regression is
`tests/test_auth_integration.py`.

---

## ADRs

Architecture decision records live in [docs/adr/](docs/adr/).

For a full architecture description see [docs/architecture.md](docs/architecture.md).

---

## License

[MIT](LICENSE)
