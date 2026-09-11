# Net Sentry — Architecture Overview

## Purpose

Net Sentry continuously (or on-demand) scans your wireless and wired environment for nearby devices — WiFi access points, Bluetooth/BLE peripherals, ARP-visible LAN hosts, mDNS/SSDP/UPnP services, IPv6 NDP neighbours — and persists **visibility windows** (start time, end time, signal strength) for every device into a local database.

---

## High-Level Components

```
┌──────────────────────────────────────────────────────────┐
│                      net-sentry CLI                      │
│  (src/main.py)  ─  scan loop, arg parsing, display       │
└────────────────────────────┬─────────────────────────────┘
                             │ orchestrates
            ┌────────────────▼──────────────────┐
            │         Scanner Pipeline          │
            │  wifi / bluetooth / arp /          │
            │  ping-sweep / mdns / ssdp /        │
            │  netbios / ipv6 / monitor / snmp   │
            └────────────────┬──────────────────┘
                             │ raw ScanResult list
            ┌────────────────▼──────────────────┐
            │      Device Tracker               │
            │  (src/device_tracker.py)          │
            │  - upsert Device rows             │
            │  - open / close VisibilityWindows │
            └────────────────┬──────────────────┘
                             │ SQLAlchemy ORM
            ┌────────────────▼──────────────────┐
            │       SQLite / PostgreSQL DB      │
            │  Device + VisibilityWindow tables │
            └──────────────────┬────────────────┘
                               │ read
     ┌─────────────────────────▼───────────────────────────┐
     │                  FastAPI Application                 │
     │  (src/api.py)  ─  REST /api/v1/  +  HTMX dashboard  │
     └──────────────────────────────────────────────────────┘
```

---

## Scanner Pipeline

Each scanner is an independent module that returns a typed list of results. Scanners run sequentially inside `_execute_all_scanners()` in `src/main.py`. Third-party scanners can be added via the `net_sentry.scanners` entry-point group (see `src/scanner_plugin.py`).

| Scanner | Module | Platform | Output type |
|---|---|---|---|
| WiFi | `wifi_scanner.py` | Win/Linux | `WifiNetwork` |
| Bluetooth classic | `bluetooth_scanner.py` | Win/Linux | `BluetoothDevice` |
| BLE | `bluetooth_scanner.py` | Linux | `BluetoothDevice` |
| ARP table | `network_discovery.py` | All | `NetworkDevice` |
| Ping sweep | `network_discovery.py` | All | `NetworkDevice` |
| mDNS | `mdns_scanner.py` | All | `MdnsDevice` |
| SSDP/UPnP | `ssdp_scanner.py` | All | `SsdpDevice` |
| NetBIOS | `netbios_scanner.py` | All | `NetBiosInfo` |
| IPv6 NDP | `ipv6_scanner.py` | All | `Ipv6Neighbor` |
| Monitor mode | `monitor_scanner.py` | Linux | `MonitorModeDevice` |
| SNMP | `snmp_scanner.py` | All | `ScanResult` |

### Error isolation

Every scanner call is wrapped in `_run_scanner(name, fn)` which catches all exceptions, logs an error, and returns an empty list so a single scanner failure never aborts the cycle.

---

## Database Model — Visibility Windows

The core design principle: **do not record every periodic observation**.  
Only the *start* and *end* of a continuous presence window is persisted, keeping the database small even after months of scanning.

### `Device` table

Stores static/slow-changing properties per unique MAC address.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | Auto |
| `mac_address` | String | Unique, normalised to lower-case colon-hex |
| `device_type` | String | `wifi_ap`, `wifi_client`, `bluetooth`, `network` |
| `ssid` | String | WiFi network name |
| `device_name` | String | BT/mDNS name, HA friendly name, hostname |
| `vendor` | String | OUI vendor lookup result |
| `hostname` | String | Reverse DNS / NetBIOS / mDNS hostname |
| `ip_address` | String | Last known IPv4/IPv6 address |
| `authentication` | String | WiFi auth (WPA2, Open, …) |
| `encryption` | String | WiFi encryption (CCMP, TKIP, …) |
| `radio_type` | String | 802.11ac, 802.11ax, … |
| `channel` | Integer | WiFi channel |
| `category` | String | Categorizer output (router, phone, iot, …) |
| `is_whitelisted` | Boolean | Matched whitelist entry |
| `network_segment` | String | Subnet label (e.g. "office", "IoT") |
| `open_ports` | String | Comma-separated `port/service` from port scan |
| `reconnect_count` | Integer | Number of visibility windows opened |
| `merged_into` | String | MAC of canonical device (de-randomisation) |
| `created_at` | DateTime | First seen |
| `updated_at` | DateTime | Last updated |

### `VisibilityWindow` table

One row per continuous presence window per device.

| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | Auto |
| `mac_address` | String FK→Device | |
| `first_seen` | DateTime | Window open time |
| `last_seen` | DateTime | Window close / last refresh |
| `signal_strength_dbm` | Float | RF signal (last reading in this window) |
| `device_type` | String | Snapshot of device_type at scan time |
| `network_segment` | String | Subnet label at scan time |

### Window lifecycle

```
scan sees device ──► open window exists?
                         │
                  Yes ◄──┴──► No
                   │            │
        last_seen  │     create new VisibilityWindow
        within gap?│     (first_seen = now)
                   │
          Yes ─────┴─── No
           │               │
      update last_seen   close old window (last_seen = now)
      + signal_dbm       open new window
```

`gap_seconds` (default 300 s, configurable) defines how long a device may be unobserved before its window is closed.

---

## API

FastAPI application at `src/api.py`.

- **Base URL**: `http://localhost:8000`
- **REST API**: `/api/v1/` (versioned)
- **Interactive docs**: `/docs` (Swagger UI), `/redoc`
- **OpenAPI schema**: `/openapi.json`
- **Prometheus metrics**: `/metrics`
- **HTMX dashboard**: `/`

Rate limiting is enforced via `slowapi` (key: client IP). Default limits:

| Route | Limit |
|---|---|
| `GET /api/v1/devices` | 100/minute |
| `GET /api/v1/devices/{mac}` | 200/minute |
| `GET /api/v1/windows` | 100/minute |
| `GET /api/v1/summary` | 60/minute |
| `POST /api/v1/auth/token` | 10/minute |

---

## Alerting

`src/alert.py` — `AlertManager` fires on new device discovery.

- Alerts are deduplicated: the same MAC address will not trigger a second alert within `alert_cooldown_seconds` (default 300 s).
- Supports log-to-file, console, and future webhook/notification channels.

---

## Observability

| Signal | Transport | Endpoint |
|---|---|---|
| Prometheus metrics | HTTP scrape | `/metrics` |
| Structured logs | stdout (JSON configurable) | — |
| Alert log | file (optional) | configured path |
| MQTT events | MQTT broker | configurable topic prefix |

### Key Prometheus metrics

| Metric | Type | Description |
|---|---|---|
| `net_sentry_devices_total` | Gauge | Total known devices by type |
| `net_sentry_devices_visible` | Gauge | Devices visible in last scan by type |
| `net_sentry_new_devices_total` | Counter | New devices discovered by type |
| `net_sentry_unknown_devices_total` | Counter | Non-whitelisted new devices by type |
| `net_sentry_scans_total` | Counter | Scan cycles completed |
| `net_sentry_scan_duration_seconds` | Histogram | Full scan cycle duration |
| `net_sentry_scanner_duration_seconds` | Histogram | Per-scanner duration |
| `net_sentry_scan_errors_total` | Counter | Scanner errors by type |
| `net_sentry_alerts_total` | Counter | Alerts raised by severity |

---

## Security Model

- The API is **unauthenticated by default** — intended for local-network or private use only.
- Enable JWT auth by setting `api.auth_enabled: true` in `config.yaml` (or `NET_SENTRY_AUTH_ENABLED=true`).
- The Docker container requests `NET_ADMIN` + `NET_RAW` capabilities for raw-socket operations but is **not** run with `privileged: true`.
- All scanning is **passive or initiator-only** — no data is forwarded to or from scanned devices.

---

## ADRs

See [docs/adr/](adr/) for architecture decision records.
