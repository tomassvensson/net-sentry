"""MAC address to vendor/brand name translation using IEEE OUI database.

The lookup strategy (highest priority first):

1. ``mac-vendor-lookup`` library with its own cached database (best coverage).
2. Local IEEE OUI CSV at ``src/data/oui.csv`` downloaded by
   ``scripts/update_oui_db.py`` (fast, offline-capable, auto-updated weekly
   via the ``oui-update`` GitHub Actions workflow).
3. Built-in static fallback dict ``_BUILTIN_OUI`` (limited but always present).
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to the locally cached IEEE OUI CSV (populated by scripts/update_oui_db.py)
_OUI_CSV_PATH = Path(__file__).parent / "data" / "oui.csv"

# Try to use mac_vendor_lookup if available, otherwise fall back to built-in
_mac_lookup = None
_INIT_ATTEMPTED = False
# Vendors loaded from the local OUI CSV (populated lazily on first use)
_csv_vendors: dict[str, str] | None = None
_CSV_LOAD_ATTEMPTED = False


def _load_oui_csv() -> dict[str, str]:
    """Load vendor names from the locally cached IEEE OUI CSV.

    The CSV has this header::

        Registry,Assignment,Organization Name,Organization Address

    The ``Assignment`` column contains the 6-hex-digit OUI (no colons).

    Returns:
        Dict mapping ``XX:XX:XX`` (uppercase, colon-separated) to vendor name.
        Empty dict if the file does not exist or cannot be parsed.
    """
    global _csv_vendors, _CSV_LOAD_ATTEMPTED
    if _CSV_LOAD_ATTEMPTED:
        # _csv_vendors is always a dict after the first call (may be empty)
        return _csv_vendors if _csv_vendors is not None else {}
    _CSV_LOAD_ATTEMPTED = True
    _csv_vendors = {}

    if not _OUI_CSV_PATH.exists():
        logger.debug("Local OUI CSV not found at %s — using built-in fallback.", _OUI_CSV_PATH)
        return _csv_vendors
    try:
        with _OUI_CSV_PATH.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                assignment = row.get("Assignment", "").strip().upper()
                name = row.get("Organization Name", "").strip()
                if len(assignment) == 6 and name:
                    oui_key = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
                    _csv_vendors[oui_key] = name
        logger.info("Loaded %d OUI entries from %s.", len(_csv_vendors), _OUI_CSV_PATH)
    except Exception:
        logger.exception("Failed to load local OUI CSV.")

    return _csv_vendors


def _init_mac_lookup() -> None:
    """Initialize the MAC vendor lookup instance (lazy)."""
    global _mac_lookup, _INIT_ATTEMPTED
    if _INIT_ATTEMPTED:
        return
    _INIT_ATTEMPTED = True
    try:
        from mac_vendor_lookup import MacLookup

        _mac_lookup = MacLookup()
        logger.info("MAC vendor lookup database loaded.")
    except ImportError:
        logger.warning("mac-vendor-lookup not installed. Vendor lookup will use built-in fallback.")
    except Exception:
        logger.exception("Failed to initialize MAC vendor lookup.")


# Vendor name constants to avoid string duplication
_VENDOR_ATHEROS_QUALCOMM = "Atheros/Qualcomm"
_VENDOR_RASPBERRY_PI = "Raspberry Pi Foundation"

# Common OUI prefixes as fallback when the full database is unavailable.
# Format: first 3 bytes (uppercase, colon-separated) -> vendor name
_BUILTIN_OUI: dict[str, str] = {
    "00:50:F2": "Microsoft",
    "00:1A:2B": "Ayecom Technology",
    "00:1B:63": "Apple",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:10:FA": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "00:30:65": "Apple",
    "00:3E:E1": "Apple",
    "00:50:E4": "Apple",
    "00:56:CD": "Apple",
    "04:0C:CE": "Apple",
    "04:15:52": "Apple",
    "04:1E:64": "Apple",
    "04:26:65": "Apple",
    "04:48:9A": "Apple",
    "04:52:F3": "Apple",
    "04:54:53": "Apple",
    "04:DB:56": "Apple",
    "04:E5:36": "Apple",
    "04:F1:3E": "Apple",
    "04:F7:E4": "Apple",
    "08:00:07": "Apple",
    "08:66:98": "Apple",
    "08:6D:41": "Apple",
    "08:74:02": "Apple",
    "10:40:F3": "Apple",
    "14:10:9F": "Apple",
    "18:AF:61": "Apple",
    "20:78:F0": "Apple",
    "24:A0:74": "Apple",
    "28:6A:BA": "Apple",
    "28:CF:E9": "Apple",
    "2C:B4:3A": "Apple",
    "34:36:3B": "Apple",
    "38:C9:86": "Apple",
    "3C:07:54": "Apple",
    "3C:15:C2": "Apple",
    "40:A6:D9": "Apple",
    "44:2A:60": "Apple",
    "48:43:7C": "Apple",
    "48:74:6E": "Apple",
    "4C:32:75": "Apple",
    "4C:57:CA": "Apple",
    "50:EA:D6": "Apple",
    "54:26:96": "Apple",
    "54:72:4F": "Apple",
    "54:AE:27": "Apple",
    "58:1F:AA": "Apple",
    "58:55:CA": "Apple",
    "5C:59:48": "Apple",
    "5C:96:9D": "Apple",
    "5C:F7:E6": "Apple",
    "60:03:08": "Apple",
    "60:33:4B": "Apple",
    "60:69:44": "Apple",
    "60:C5:47": "Apple",
    "60:FA:CD": "Apple",
    "60:FE:C5": "Apple",
    "64:20:0C": "Apple",
    "64:A3:CB": "Apple",
    "64:B0:A6": "Apple",
    "64:E6:82": "Apple",
    "68:09:27": "Apple",
    "68:5B:35": "Apple",
    "68:96:7B": "Apple",
    "68:A8:6D": "Apple",
    "68:AB:1E": "Apple",
    "68:D9:3C": "Apple",
    "68:FE:F7": "Apple",
    "6C:3E:6D": "Apple",
    "6C:40:08": "Apple",
    "6C:70:9F": "Apple",
    "6C:72:E7": "Apple",
    "6C:94:F8": "Apple",
    "6C:C2:6B": "Apple",
    "70:11:24": "Apple",
    "70:56:81": "Apple",
    "70:73:CB": "Apple",
    "70:CD:60": "Apple",
    "70:DE:E2": "Apple",
    "74:E1:B6": "Apple",
    "78:31:C1": "Apple",
    "78:3A:84": "Apple",
    "78:7E:61": "Apple",
    "78:88:6D": "Apple",
    "78:CA:39": "Apple",
    "78:FD:94": "Apple",
    "7C:01:91": "Apple",
    "7C:04:D0": "Apple",
    "7C:11:BE": "Apple",
    "7C:6D:62": "Apple",
    "7C:D1:C3": "Apple",
    "7C:F0:5F": "Apple",
    "7C:FA:DF": "Apple",
    "80:00:6E": "Apple",
    "80:49:71": "Apple",
    "80:92:9F": "Apple",
    "80:E6:50": "Apple",
    "84:29:99": "Apple",
    "84:38:35": "Apple",
    "84:78:8B": "Apple",
    "84:85:06": "Apple",
    "84:FC:FE": "Apple",
    "88:53:95": "Apple",
    "88:63:DF": "Apple",
    "88:66:A5": "Apple",
    "88:C6:63": "Apple",
    "88:E8:7F": "Apple",
    "8C:00:6D": "Apple",
    "8C:29:37": "Apple",
    "8C:2D:AA": "Apple",
    "8C:58:77": "Apple",
    "8C:7B:9D": "Apple",
    "8C:7C:92": "Apple",
    "8C:85:90": "Apple",
    "8C:FA:BA": "Apple",
    "90:27:E4": "Apple",
    "90:72:40": "Apple",
    "90:84:0D": "Apple",
    "90:B2:1F": "Apple",
    "90:B9:31": "Apple",
    "90:FD:61": "Apple",
    "94:94:26": "Apple",
    "94:E9:6A": "Apple",
    "94:F6:A3": "Apple",
    "98:01:A7": "Apple",
    "98:03:D8": "Apple",
    "98:B8:E3": "Apple",
    "98:D6:BB": "Apple",
    "98:E0:D9": "Apple",
    "98:FE:94": "Apple",
    "9C:04:EB": "Apple",
    "9C:20:7B": "Apple",
    "9C:35:EB": "Apple",
    "9C:F3:87": "Apple",
    "A0:ED:CD": "Apple",
    "A4:5E:60": "Apple",
    "A4:67:06": "Apple",
    "A4:B1:97": "Apple",
    "A4:C3:61": "Apple",
    "A4:D1:8C": "Apple",
    "A4:D1:D2": "Apple",
    "A8:20:66": "Apple",
    "A8:51:AB": "Apple",
    "A8:5B:78": "Apple",
    "A8:5C:2C": "Apple",
    "A8:86:DD": "Apple",
    "A8:88:08": "Apple",
    "A8:96:8A": "Apple",
    "A8:BB:CF": "Apple",
    "A8:FA:D8": "Apple",
    "AC:29:3A": "Apple",
    "AC:3C:0B": "Apple",
    "AC:61:EA": "Apple",
    "AC:7F:3E": "Apple",
    "AC:87:A3": "Apple",
    "AC:BC:32": "Apple",
    "AC:CF:5C": "Apple",
    "AC:FD:EC": "Apple",
    "B0:34:95": "Apple",
    "B0:65:BD": "Apple",
    "B0:70:2D": "Apple",
    "B0:9F:BA": "Apple",
    "B4:18:D1": "Apple",
    "B4:F0:AB": "Apple",
    "B8:09:8A": "Apple",
    "B8:17:C2": "Apple",
    "B8:41:A4": "Apple",
    "B8:44:D9": "Apple",
    "B8:63:4D": "Apple",
    "B8:78:2E": "Apple",
    "B8:8D:12": "Apple",
    "B8:C1:11": "Apple",
    "B8:C7:5D": "Apple",
    "B8:E8:56": "Apple",
    "B8:F6:B1": "Apple",
    "B8:FF:61": "Apple",
    "BC:3B:AF": "Apple",
    "BC:52:B7": "Apple",
    "BC:54:36": "Apple",
    "BC:67:78": "Apple",
    "BC:92:6B": "Apple",
    "C0:1A:DA": "Apple",
    "C0:63:94": "Apple",
    "C0:84:7A": "Apple",
    "C0:9F:42": "Apple",
    "C0:A5:3E": "Apple",
    "C0:CC:F8": "Apple",
    "C0:CE:CD": "Apple",
    "C0:D0:12": "Apple",
    "C0:F2:FB": "Apple",
    "C4:2C:03": "Apple",
    "C8:1E:E7": "Apple",
    "C8:2A:14": "Apple",
    "C8:33:4B": "Apple",
    "C8:69:CD": "Apple",
    "C8:6F:1D": "Apple",
    "C8:85:50": "Apple",
    "C8:B5:B7": "Apple",
    "C8:BC:C8": "Apple",
    "C8:E0:EB": "Apple",
    "C8:F6:50": "Apple",
    "CC:08:E0": "Apple",
    "CC:20:E8": "Apple",
    "CC:25:EF": "Apple",
    "CC:29:F5": "Apple",
    "CC:78:5F": "Apple",
    "D0:03:4B": "Apple",
    "D0:23:DB": "Apple",
    "D0:25:98": "Apple",
    "D0:33:11": "Apple",
    "D0:4F:7E": "Apple",
    "D4:61:9D": "Apple",
    "D4:9A:20": "Apple",
    "D4:F4:6F": "Apple",
    "D8:00:4D": "Apple",
    "D8:1D:72": "Apple",
    "D8:30:62": "Apple",
    "D8:96:95": "Apple",
    "D8:9E:3F": "Apple",
    "D8:A2:5E": "Apple",
    "D8:BB:2C": "Apple",
    "D8:CF:9C": "Apple",
    "DC:2B:2A": "Apple",
    "DC:37:14": "Apple",
    "DC:41:5F": "Apple",
    "DC:56:E7": "Apple",
    "DC:86:D8": "Apple",
    "DC:9B:9C": "Apple",
    "DC:A4:CA": "Apple",
    "DC:A9:04": "Apple",
    "E0:5F:45": "Apple",
    "E0:66:78": "Apple",
    "E0:6F:13": "Apple",
    "E0:AC:CB": "Apple",
    "E0:B5:2D": "Apple",
    "E0:B9:BA": "Apple",
    "E0:C7:67": "Apple",
    "E0:C9:7A": "Apple",
    "E0:F5:C6": "Apple",
    "E4:25:E7": "Apple",
    "E4:8B:7F": "Apple",
    "E4:98:D6": "Apple",
    "E4:C6:3D": "Apple",
    "E4:CE:8F": "Apple",
    "E8:04:0B": "Apple",
    "E8:06:88": "Apple",
    "E8:80:2E": "Apple",
    "E8:8D:28": "Apple",
    "EC:35:86": "Apple",
    "EC:85:2F": "Apple",
    "F0:24:75": "Apple",
    "F0:99:BF": "Apple",
    "F0:B4:79": "Apple",
    "F0:C1:F1": "Apple",
    "F0:CB:A1": "Apple",
    "F0:D1:A9": "Apple",
    "F0:DB:E2": "Apple",
    "F0:DC:E2": "Apple",
    "F4:1B:A1": "Apple",
    "F4:37:B7": "Apple",
    "F4:F1:5A": "Apple",
    "F4:F9:51": "Apple",
    "F8:1E:DF": "Apple",
    "F8:27:93": "Apple",
    "F8:62:14": "Apple",
    "FC:25:3F": "Apple",
    "FC:E9:98": "Apple",
    # Samsung
    "00:07:AB": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:6C": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung",
    "00:1E:E1": "Samsung",
    "00:1E:E2": "Samsung",
    "00:1F:CC": "Samsung",
    "00:1F:CD": "Samsung",
    "00:21:19": "Samsung",
    "00:21:D1": "Samsung",
    "00:21:D2": "Samsung",
    "00:23:39": "Samsung",
    "00:23:3A": "Samsung",
    "00:23:99": "Samsung",
    "00:23:D6": "Samsung",
    "00:23:D7": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:24:91": "Samsung",
    "00:25:66": "Samsung",
    "00:25:67": "Samsung",
    "00:26:37": "Samsung",
    "00:E0:64": "Samsung",
    # Google/Nest
    "54:60:09": "Google",
    "F4:F5:D8": "Google",
    "F4:F5:E8": "Google",
    "94:EB:2C": "Google",
    "A4:77:33": "Google",
    "30:FD:38": "Google",
    # Intel
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0C:F1": "Intel",
    "00:0E:0C": "Intel",
    "00:0E:35": "Intel",
    "00:11:11": "Intel",
    "00:12:F0": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:13:CE": "Intel",
    "00:13:E8": "Intel",
    "00:15:00": "Intel",
    "00:15:17": "Intel",
    "00:16:6F": "Intel",
    "00:16:76": "Intel",
    "00:16:EA": "Intel",
    "00:16:EB": "Intel",
    "00:18:DE": "Intel",
    "00:19:D1": "Intel",
    "00:19:D2": "Intel",
    "00:1B:21": "Intel",
    "00:1B:77": "Intel",
    "00:1C:BF": "Intel",
    "00:1D:E0": "Intel",
    "00:1D:E1": "Intel",
    "00:1E:64": "Intel",
    "00:1E:65": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "00:20:7B": "Intel",
    "00:21:5C": "Intel",
    "00:21:5D": "Intel",
    "00:21:6A": "Intel",
    "00:21:6B": "Intel",
    "00:22:43": "Intel",
    "00:22:44": "Intel",
    "00:22:FA": "Intel",
    "00:22:FB": "Intel",
    "00:23:14": "Intel",
    "00:23:15": "Intel",
    "00:24:D6": "Intel",
    "00:24:D7": "Intel",
    "00:27:10": "Intel",
    # Qualcomm / Atheros (like the AR9271)
    "00:03:7F": _VENDOR_ATHEROS_QUALCOMM,
    "00:0B:6B": _VENDOR_ATHEROS_QUALCOMM,
    "00:0E:6D": _VENDOR_ATHEROS_QUALCOMM,
    "00:13:74": _VENDOR_ATHEROS_QUALCOMM,
    "00:15:AF": _VENDOR_ATHEROS_QUALCOMM,
    "00:1C:EF": _VENDOR_ATHEROS_QUALCOMM,
    "00:24:C3": _VENDOR_ATHEROS_QUALCOMM,
    "00:26:CB": _VENDOR_ATHEROS_QUALCOMM,
    "04:F0:21": _VENDOR_ATHEROS_QUALCOMM,
    "1C:4B:D6": _VENDOR_ATHEROS_QUALCOMM,
    "24:DE:C6": _VENDOR_ATHEROS_QUALCOMM,
    "40:A5:EF": _VENDOR_ATHEROS_QUALCOMM,
    "50:46:5D": _VENDOR_ATHEROS_QUALCOMM,
    "58:98:35": _VENDOR_ATHEROS_QUALCOMM,
    # TP-Link
    "00:1D:0F": "TP-Link",
    "14:CC:20": "TP-Link",
    "14:CF:92": "TP-Link",
    "18:A6:F7": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "24:69:68": "TP-Link",
    "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:C8:0F": "TP-Link",
    "5C:A6:E6": "TP-Link",
    "60:E3:27": "TP-Link",
    "64:56:01": "TP-Link",
    "64:70:02": "TP-Link",
    "6C:5A:B0": "TP-Link",
    "78:44:76": "TP-Link",
    "90:F6:52": "TP-Link",
    "98:DA:C4": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "AC:84:C6": "TP-Link",
    "B0:4E:26": "TP-Link",
    "B0:95:75": "TP-Link",
    "C0:25:E9": "TP-Link",
    "C0:4A:00": "TP-Link",
    "C0:E3:FB": "TP-Link",
    "D4:6E:0E": "TP-Link",
    "D8:07:B6": "TP-Link",
    "E4:D3:32": "TP-Link",
    "E8:94:F6": "TP-Link",
    "EC:08:6B": "TP-Link",
    "EC:17:2F": "TP-Link",
    "F0:A7:31": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "F4:EC:38": "TP-Link",
    # Netgear
    "00:09:5B": "Netgear",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",
    "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",
    "00:1F:33": "Netgear",
    "00:22:3F": "Netgear",
    "00:24:B2": "Netgear",
    "00:26:F2": "Netgear",
    "04:A1:51": "Netgear",
    "08:02:8E": "Netgear",
    "08:36:C9": "Netgear",
    "10:0D:7F": "Netgear",
    "10:DA:43": "Netgear",
    "20:0C:C8": "Netgear",
    "20:E5:2A": "Netgear",
    "28:C6:8E": "Netgear",
    "2C:B0:5D": "Netgear",
    "30:46:9A": "Netgear",
    "38:94:ED": "Netgear",
    "44:94:FC": "Netgear",
    "4C:60:DE": "Netgear",
    "6C:B0:CE": "Netgear",
    "84:1B:5E": "Netgear",
    "9C:3D:CF": "Netgear",
    "A0:04:60": "Netgear",
    "A0:21:B7": "Netgear",
    "A4:2B:8C": "Netgear",
    "B0:7F:B9": "Netgear",
    "B0:B9:8A": "Netgear",
    "C0:3F:0E": "Netgear",
    "C4:04:15": "Netgear",
    "C4:3D:C7": "Netgear",
    "CC:40:D0": "Netgear",
    "E0:46:9A": "Netgear",
    "E0:91:F5": "Netgear",
    "E4:F4:C6": "Netgear",
    "F8:73:94": "Netgear",
    # Huawei
    "00:1E:10": "Huawei",
    "00:25:68": "Huawei",
    "00:25:9E": "Huawei",
    "00:46:4B": "Huawei",
    "00:E0:FC": "Huawei",
    "04:02:1F": "Huawei",
    "04:25:C5": "Huawei",
    "04:BD:70": "Huawei",
    "04:C0:6F": "Huawei",
    "04:F9:38": "Huawei",
    "04:FE:8D": "Huawei",
    "08:19:A6": "Huawei",
    "08:63:61": "Huawei",
    "0C:37:DC": "Huawei",
    "0C:45:BA": "Huawei",
    "0C:96:BF": "Huawei",
    "10:1B:54": "Huawei",
    "10:44:00": "Huawei",
    "10:47:80": "Huawei",
    "10:C6:1F": "Huawei",
    # Sony
    "00:01:4A": "Sony",
    "00:04:1F": "Sony",
    "00:13:A9": "Sony",
    "00:14:A4": "Sony",
    "00:15:C1": "Sony",
    "00:16:20": "Sony",
    "00:18:13": "Sony",
    "00:19:63": "Sony",
    "00:1A:80": "Sony",
    "00:1C:A4": "Sony",
    "00:1D:0D": "Sony",
    "00:1D:BA": "Sony",
    "00:1E:4C": "Sony",
    "00:1E:A4": "Sony",
    # Microsoft / Xbox
    "28:18:78": "Microsoft",
    "58:82:A8": "Microsoft",
    "60:45:BD": "Microsoft",
    "7C:1E:52": "Microsoft",
    "7C:ED:8D": "Microsoft",
    "B4:0E:DE": "Microsoft",
    "C8:3F:26": "Microsoft",
    "DC:B4:C4": "Microsoft",
    # Raspberry Pi
    "B8:27:EB": _VENDOR_RASPBERRY_PI,
    "DC:A6:32": _VENDOR_RASPBERRY_PI,
    "E4:5F:01": _VENDOR_RASPBERRY_PI,
    # Amazon
    "00:FC:8B": "Amazon",
    "0C:47:C9": "Amazon",
    "10:CE:A9": "Amazon",
    "14:91:82": "Amazon",
    "18:74:2E": "Amazon",
    "34:D2:70": "Amazon",
    "38:F7:3D": "Amazon",
    "40:B4:CD": "Amazon",
    "44:65:0D": "Amazon",
    "4C:EF:C0": "Amazon",
    "50:DC:E7": "Amazon",
    "5C:41:5A": "Amazon",
    "68:37:E9": "Amazon",
    "68:54:FD": "Amazon",
    "6C:56:97": "Amazon",
    "74:75:48": "Amazon",
    "74:C2:46": "Amazon",
    "78:E1:03": "Amazon",
    "84:D6:D0": "Amazon",
    "A0:02:DC": "Amazon",
    "AC:63:BE": "Amazon",
    "B4:7C:9C": "Amazon",
    "F0:27:2D": "Amazon",
    "F0:D2:F1": "Amazon",
    "FC:65:DE": "Amazon",
    # Xiaomi
    "00:9E:C8": "Xiaomi",
    "04:CF:8C": "Xiaomi",
    "0C:1D:AF": "Xiaomi",
    "10:2A:B3": "Xiaomi",
    "14:F6:5A": "Xiaomi",
    "18:59:36": "Xiaomi",
    "20:47:DA": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "38:A4:ED": "Xiaomi",
    "3C:BD:3E": "Xiaomi",
    "50:64:2B": "Xiaomi",
    "58:44:98": "Xiaomi",
    "64:09:80": "Xiaomi",
    "64:B4:73": "Xiaomi",
    "68:B8:D3": "Xiaomi",
    "74:23:44": "Xiaomi",
    "78:02:F8": "Xiaomi",
    "78:11:DC": "Xiaomi",
    "7C:1D:D9": "Xiaomi",
    "84:F3:EB": "Xiaomi",
    "8C:DE:F9": "Xiaomi",
    "98:FA:E3": "Xiaomi",
    "9C:99:A0": "Xiaomi",
    "AC:C1:EE": "Xiaomi",
    "B0:E2:35": "Xiaomi",
    "C4:0B:CB": "Xiaomi",
    "CC:B5:D1": "Xiaomi",
    "D4:97:0B": "Xiaomi",
    "F0:B4:29": "Xiaomi",
    "F4:8B:32": "Xiaomi",
    "F8:A4:5F": "Xiaomi",
    "FC:64:BA": "Xiaomi",
}


def normalize_mac(mac_address: str) -> str:
    """Normalize a MAC address to uppercase colon-separated format.

    Args:
        mac_address: MAC address in any common format.

    Returns:
        Normalized MAC address (e.g., "AA:BB:CC:DD:EE:FF").

    Raises:
        ValueError: If the MAC address format is invalid.
    """
    # Remove common separators and whitespace
    cleaned = re.sub(r"[:\-.\s]", "", mac_address.strip().upper())
    if len(cleaned) != 12 or not re.match(r"^[0-9A-F]{12}$", cleaned):
        raise ValueError(f"Invalid MAC address: {mac_address}")
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def get_oui_prefix(mac_address: str) -> str:
    """Extract the OUI (first 3 bytes) from a MAC address.

    Args:
        mac_address: MAC address in any common format.

    Returns:
        OUI prefix in "XX:XX:XX" format.
    """
    normalized = normalize_mac(mac_address)
    return normalized[:8]


def lookup_vendor(mac_address: str) -> str | None:
    """Look up the vendor/manufacturer for a MAC address.

    Tries (in order):
    1. ``mac-vendor-lookup`` library with its cached database.
    2. Local IEEE OUI CSV (``src/data/oui.csv``) downloaded by the weekly
       ``oui-update`` workflow.
    3. Built-in static OUI table (limited but always available).

    Args:
        mac_address: MAC address in any common format.

    Returns:
        Vendor name string, or None if not found.
    """
    try:
        normalized = normalize_mac(mac_address)
    except ValueError:
        logger.warning("Cannot lookup vendor for invalid MAC input.")
        return None

    # 1 — Try the full mac-vendor-lookup library
    _init_mac_lookup()
    if _mac_lookup is not None:
        try:
            vendor: str | None = _mac_lookup.lookup(normalized)
            if vendor:
                return vendor
        except Exception:
            logger.debug("mac-vendor-lookup failed, trying CSV fallback.")

    # 2 — Try the local IEEE OUI CSV
    prefix = get_oui_prefix(normalized)
    csv_vendor = _load_oui_csv().get(prefix)
    if csv_vendor:
        return csv_vendor

    # 3 — Built-in static table
    vendor = _BUILTIN_OUI.get(prefix)
    if vendor:
        return vendor

    logger.debug("No vendor found for requested MAC.")
    return None


def is_randomized_mac(mac_address: str) -> bool:
    """Check if a MAC address appears to be locally administered (randomized).

    Modern devices often use randomized MAC addresses for privacy.
    The locally administered bit is the second-least-significant bit
    of the first octet.

    Args:
        mac_address: MAC address in any common format.

    Returns:
        True if the MAC appears to be randomized/locally administered.
    """
    try:
        normalized = normalize_mac(mac_address)
    except ValueError:
        return False

    first_byte = int(normalized[:2], 16)
    return bool(first_byte & 0x02)
