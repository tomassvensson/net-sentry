"""Scanner plugin interface for Net Sentry.

Third-party scanners can be registered via Python package entry points::

    # In the plugin's pyproject.toml:
    [project.entry-points."net_sentry.scanners"]
    my_scanner = "my_package.my_scanner:MyScanner"

Net Sentry loads all registered plugins at startup via
:func:`load_scanner_plugins`.

Implementing a plugin
---------------------
Subclass :class:`ScannerPlugin` and implement :meth:`scan`::

    from src.scanner_plugin import ScannerPlugin, ScanResult

    class MySuperScanner(ScannerPlugin):
        name = "my_super_scanner"
        description = "Detects ultra-secret devices"

        def scan(self, config) -> list[ScanResult]:
            return [
                ScanResult(
                    mac_address="aa:bb:cc:dd:ee:ff",
                    device_type="wifi",
                    source=self.name,
                    extra={"custom_field": "value"},
                )
            ]
"""

import importlib.metadata
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Entry-point group that plugins must register under.
ENTRY_POINT_GROUP = "net_sentry.scanners"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """A single device observation returned by a scanner plugin.

    Attributes:
        mac_address: Device MAC address (colon-separated lower-case hex).
        device_type: Type string (e.g. ``"wifi"``, ``"bluetooth"``, ``"snmp"``).
        source: Name of the plugin / scanner that produced this result.
        scan_time: UTC timestamp of the observation.
        signal_dbm: RF signal strength in dBm, or ``None`` if unavailable.
        vendor: Vendor name (from OUI lookup or device response).
        device_name: Human-readable device name / hostname.
        ip_address: IPv4 address if known.
        extra: Plugin-specific extra fields.
    """

    mac_address: str
    device_type: str
    source: str
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signal_dbm: int | None = None
    vendor: str | None = None
    device_name: str | None = None
    ip_address: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class ScannerPlugin(ABC):
    """Abstract base class for BtWiFi scanner plugins.

    Subclass this and register the subclass as an entry point under the
    ``net_sentry.scanners`` group.

    Class attributes
    ----------------
    name : str
        Short identifier used in logs and scan results.  Must be unique
        across all loaded plugins.
    description : str
        Human-readable description shown in the plugin listing.
    """

    #: Short unique identifier for this plugin.
    name: str = ""
    #: Human-readable description.
    description: str = ""

    @abstractmethod
    def scan(self, config: Any) -> list[ScanResult]:
        """Perform a scan and return a list of observed devices.

        This method may block for the duration of the scan.  It should
        return an empty list (not raise) when no devices are found or
        when the underlying scanner is unavailable.

        Args:
            config: The :class:`~src.config.AppConfig` instance for the
                    current run.  Plugin authors may read
                    ``config.scanner.<plugin_name>`` for plugin-specific
                    settings (if they add a section to config.yaml).

        Returns:
            List of :class:`ScanResult` instances.
        """

    def is_available(self) -> bool:
        """Return ``True`` if all prerequisites for this plugin are met.

        Override this to check for system capabilities (e.g. a required
        binary or Python package).  Plugins that return ``False`` are
        skipped at scan time without raising an error.

        Returns:
            ``True`` by default; override to add availability checks.
        """
        return True


# ---------------------------------------------------------------------------
# Plugin loader
# ---------------------------------------------------------------------------


def load_scanner_plugins() -> list[ScannerPlugin]:
    """Discover and instantiate all registered scanner plugins.

    Plugins are discovered via the ``net_sentry.scanners`` entry-point group
    (PEP 451 / importlib.metadata).  Only *available* plugins (where
    :meth:`ScannerPlugin.is_available` returns ``True``) are returned.

    Returns:
        List of instantiated :class:`ScannerPlugin` objects.
    """
    plugins: list[ScannerPlugin] = []

    try:
        entry_points = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception:
        logger.exception("Failed to load entry points for group %s", ENTRY_POINT_GROUP)
        return plugins

    for ep in entry_points:
        try:
            cls = ep.load()
            if not (isinstance(cls, type) and issubclass(cls, ScannerPlugin)):
                logger.warning(
                    "Entry point %r in group %s is not a ScannerPlugin subclass — skipping",
                    ep.name,
                    ENTRY_POINT_GROUP,
                )
                continue
            instance: ScannerPlugin = cls()
            if not instance.is_available():
                logger.info("Scanner plugin %r is not available — skipping", instance.name or ep.name)
                continue
            plugins.append(instance)
            logger.info("Loaded scanner plugin: %s (%s)", instance.name or ep.name, instance.description)
        except Exception:
            logger.exception("Failed to load scanner plugin from entry point %r", ep.name)

    return plugins
