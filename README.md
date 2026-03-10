# BtWiFi - Device Visibility Tracker

Track which WiFi, Bluetooth, and network devices are and were visible, when, and how strongly.

## Overview

BtWiFi uses multiple discovery protocols to scan for nearby wireless and network devices, tracking their visibility over time. It translates MAC addresses to human-readable vendor/brand names and stores visibility windows in a local SQLite database.

## Features

- **WiFi Network Scanning** — Discovers nearby WiFi networks and access points
- **Bluetooth Device Scanning** — Discovers nearby Bluetooth devices
- **mDNS/Bonjour Discovery** — Finds devices advertising mDNS services (printers, IoT, Apple devices)
- **SSDP/UPnP Discovery** — Discovers UPnP devices on the network
- **NetBIOS Name Resolution** — Resolves Windows/SMB device names
- **ARP Network Discovery** — Discovers devices visible in the ARP table
- **Device Categorization** — Automatically categorizes devices (phone, laptop, IoT, router, etc.)
- **Device Fingerprinting** — Identifies device type, OS, and model from multiple data sources
- **Vendor Identification** — Translates MAC addresses to manufacturer names using the IEEE OUI database
- **Visibility Tracking** — Stores when devices were first/last seen with signal strength
- **Whitelist Management** — Tag known devices with custom names and trust levels
- **Alert System** — Log alerts when new unknown devices appear on the network
- **Continuous Scanning** — Run repeated scans with configurable intervals
- **YAML Configuration** — Configure all scanner options through `config.yaml`
- **Human-readable Output** — Displays results in a formatted table with categories and vendor names
- **Docker Support** — Dockerfile and docker-compose.yml for containerized deployment

## Technology Stack

- **Language:** Python 3.10+
- **Database:** SQLite via SQLAlchemy
- **WiFi Scanning:** Windows Native WiFi API (`netsh`)
- **Bluetooth Scanning:** Windows Bluetooth API via PowerShell
- **mDNS Discovery:** zeroconf library
- **OUI Lookup:** IEEE MA-L (OUI) database via mac-vendor-lookup
- **Configuration:** PyYAML
- **Testing:** pytest with 86%+ coverage
- **Linting:** ruff (lint + format)
- **Type Checking:** mypy
- **CI/CD:** GitHub Actions (lint, test matrix, Trivy, CodeQL)
- **Code Quality:** SonarQube

## Quick Start

```bash
# Create virtual environment
python -m venv .venv

# Activate (Windows)
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python -m src.main

# Run with custom config
cp config.yaml.example config.yaml
# Edit config.yaml to your needs
python -m src.main
```

## Configuration

Copy `config.yaml.example` to `config.yaml` and customize:

```yaml
scan:
  wifi_enabled: true
  bluetooth_enabled: true
  arp_enabled: true
  mdns_enabled: true
  ssdp_enabled: true
  netbios_enabled: true
  continuous: false
  interval_seconds: 60

whitelist:
  devices:
    - mac: "AA:BB:CC:DD:EE:FF"
      name: "My Router"
      trusted: true
      category: "router"

alert:
  enabled: true
  log_file: "alerts.log"
```

## Project Structure

```
btwf/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point and scan orchestration
│   ├── models.py             # SQLAlchemy database models
│   ├── database.py           # Database session management
│   ├── config.py             # YAML configuration loader
│   ├── wifi_scanner.py       # WiFi scanning (netsh)
│   ├── bluetooth_scanner.py  # Bluetooth scanning (PowerShell)
│   ├── network_discovery.py  # ARP table scanning
│   ├── mdns_scanner.py       # mDNS/Bonjour service discovery
│   ├── ssdp_scanner.py       # SSDP/UPnP device discovery
│   ├── netbios_scanner.py    # NetBIOS name resolution
│   ├── oui_lookup.py         # MAC-to-vendor translation
│   ├── device_tracker.py     # Visibility window tracking
│   ├── categorizer.py        # Device categorization engine
│   ├── fingerprint.py        # Device fingerprinting
│   ├── whitelist.py          # Known device management
│   ├── alert.py              # New device alert system
│   └── data/
│       └── .gitkeep
├── tests/                    # 282 tests, 86%+ coverage
│   ├── test_main.py
│   ├── test_config.py
│   ├── test_categorizer.py
│   ├── test_whitelist.py
│   ├── test_alert.py
│   ├── test_fingerprint.py
│   ├── test_mdns_scanner.py
│   ├── test_ssdp_scanner.py
│   ├── test_netbios_scanner.py
│   ├── test_wifi_scanner.py
│   ├── test_bluetooth_scanner.py
│   ├── test_network_discovery.py
│   ├── test_oui_lookup.py
│   └── test_database.py
├── .github/
│   └── workflows/
│       └── ci.yml            # GitHub Actions CI pipeline
├── docs/
│   └── adr/
│       └── 001-technology-choice.md
├── Dockerfile
├── docker-compose.yml
├── config.yaml.example
├── pyproject.toml
├── requirements.txt
├── sonar-project.properties
└── README.md
```

## Architecture

See [ADR-001](docs/adr/001-technology-choice.md) for the technology choice rationale.

## Security

- Scanned devices are never given access to the network or computer
- The system operates in read-only/passive scanning mode
- No connections are established with discovered devices

## License

Private project — not yet open source.
