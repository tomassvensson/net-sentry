# Net Sentry — Network Device Visibility Tracker

> GitHub repo: <https://github.com/tomassvensson/net-sentry>

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
|---|---|
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
| **Web dashboard** | HTMX-powered live table at `http://localhost:8000/` |
| **Prometheus metrics** | Scraped at `http://localhost:8000/metrics` |
| **Grafana dashboard** | Pre-provisioned dashboard (included in repo) |
| **MQTT** | Publishes device events to an MQTT broker |
| **Alerts** | Log / sound on new device discovery |
| **Whitelist** | Mark trusted devices; unknown devices are flagged |
| **Export** | CSV and JSON export via CLI flag or API endpoint |
| **Alembic migrations** | Schema is versioned; upgrades run automatically |
| **Docker** | Single-container scanner + optional Prometheus/Grafana stack |

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
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\Activate.ps1

pip install -e ".[dev]"
cp config.yaml.example config.yaml
# edit config.yaml as needed
```

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

### Export all known devices

```bash
net-sentry --export csv
net-sentry --export json --output devices.json
```

---

## CLI Reference

```
net-sentry [OPTIONS]

Options:
  --once            Run a single scan cycle and exit (overrides config.scan.continuous)
  --continuous      Run in continuous loop (overrides config.scan.continuous)
  --rescan-ports    Force fresh TCP port scan for all discovered network devices
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
  host: "0.0.0.0"
  port: 8000
  auth_enabled: false     # set true + configure api_users for production

mqtt:
  enabled: false
  broker_host: "localhost"
  broker_port: 1883
  topic_prefix: "net-sentry"
```

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
curl "http://localhost:8000/api/v1/devices?limit=20&offset=0"

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
|---|---|---|
| `GET` | `/api/v1/health` | Liveness check -> `{"status":"ok"}` |
| `GET` | `/api/v1/devices` | List all known devices (supports `limit`/`offset`) |
| `GET` | `/api/v1/devices/{mac}` | Single device with visibility history |
| `DELETE` | `/api/v1/devices/{mac}` | Remove a device record |
| `GET` | `/api/v1/windows` | List visibility windows |
| `GET` | `/api/v1/export/csv` | Export all devices as CSV |
| `GET` | `/api/v1/export/json` | Export all devices as JSON |
| `POST` | `/api/v1/auth/token` | Obtain JWT (when auth enabled) |
| `GET` | `/metrics` | Prometheus metrics (no auth) |
| `GET` | `/` | HTMX web dashboard |
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

```bash
docker compose up net-sentry
```

### Full stack (scanner + Prometheus + Grafana)

```yaml
# docker-compose.yml is already in the repo
# Prometheus: http://localhost:9090
# Grafana:    http://localhost:3000  (admin / admin)
```

```bash
docker compose --profile dashboards up
```

### With PostgreSQL

```bash
docker compose --profile postgres up
# Set DATABASE_URL=postgresql+pg8000://net-sentry:net-sentry@localhost:5432/net-sentry
```

---

## Database Migrations

Schema changes are managed with Alembic.

```bash
# Apply all pending migrations
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "my change"
```

Migrations run automatically at startup via `init_database()`.

---

## Development

### Pre-commit hooks

Pre-commit hooks run ruff, mypy, and trailing-whitespace checks before each commit.

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

- JWT authentication on the API is **disabled by default** for ease of local use.
  Enable it for any internet-facing deployment.
- The scanner requires `NET_ADMIN` / `NET_RAW` capabilities (or root) for raw-socket operations.
  The Docker container is **not** run in `privileged` mode by default.
- See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

---

## Architecture

```
net-sentry/
├── src/
│   ├── main.py            # Entry point: CLI, scan orchestration, display
│   ├── config.py          # Dataclass-based config loader (config.yaml)
│   ├── models.py          # SQLAlchemy ORM models (Device, VisibilityWindow)
│   ├── database.py        # DB init, session factory, retention
│   ├── device_tracker.py  # Visibility window logic
│   ├── api.py             # FastAPI application (REST + HTMX dashboard)
│   ├── auth.py            # JWT auth helpers
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
├── alembic/               # Database migrations
├── tests/                 # pytest unit + integration + E2E tests
├── grafana/               # Grafana provisioning
├── prometheus/            # Prometheus config
├── docs/                  # Architecture decision records
└── docker-compose.yml
```

---

## Demo

> **TODO**: A demo GIF/video (dashboard + new device alert + Grafana panel) will be added here.
> To record one yourself: start the full Docker stack, open `http://localhost:3000`, and use a tool such as [LICEcap](https://www.cockos.com/licecap/) or [asciinema](https://asciinema.org/) to capture a short clip.

---

## ADRs

Architecture decision records live in [docs/adr/](docs/adr/).

For a full architecture description see [docs/architecture.md](docs/architecture.md).

---

## License

[MIT](LICENSE)
