"""Known/trusted device whitelist management.

Provides functions to check if a device is whitelisted, add/remove
devices from the whitelist, and persist the whitelist through configuration.
"""

import logging

from src.config import AppConfig, WhitelistEntry
from src.oui_lookup import normalize_mac

logger = logging.getLogger(__name__)


class WhitelistManager:
    """Manages a set of known/trusted devices.

    Devices on the whitelist are marked as trusted and can be
    filtered or highlighted differently in the output.
    """

    def __init__(self, config: AppConfig) -> None:
        """Initialize the whitelist from configuration.

        Args:
            config: Application configuration containing whitelist entries.
        """
        self._entries: dict[str, WhitelistEntry] = {}
        for entry in config.whitelist:
            try:
                mac = normalize_mac(entry.mac_address)
                self._entries[mac] = WhitelistEntry(
                    mac_address=mac,
                    name=entry.name,
                    category=entry.category,
                    trusted=entry.trusted,
                )
            except ValueError:
                logger.warning("Invalid MAC in whitelist entry; skipping entry.")

        logger.info("Whitelist loaded: %d known devices.", len(self._entries))

    def is_known(self, mac_address: str) -> bool:
        """Check if a device MAC is in the whitelist.

        Args:
            mac_address: MAC address to check.

        Returns:
            True if the device is known/whitelisted.
        """
        try:
            mac = normalize_mac(mac_address)
        except ValueError:
            return False
        return mac in self._entries

    def is_trusted(self, mac_address: str) -> bool:
        """Check if a device MAC is trusted.

        Args:
            mac_address: MAC address to check.

        Returns:
            True if the device is whitelisted and marked as trusted.
        """
        try:
            mac = normalize_mac(mac_address)
        except ValueError:
            return False
        entry = self._entries.get(mac)
        return entry is not None and entry.trusted

    def get_entry(self, mac_address: str) -> WhitelistEntry | None:
        """Get the whitelist entry for a MAC address.

        Args:
            mac_address: MAC address to look up.

        Returns:
            WhitelistEntry if found, None otherwise.
        """
        try:
            mac = normalize_mac(mac_address)
        except ValueError:
            return None
        return self._entries.get(mac)

    def get_custom_name(self, mac_address: str) -> str | None:
        """Get the custom name assigned to a device in the whitelist.

        Args:
            mac_address: MAC address to look up.

        Returns:
            Custom name string, or None if not whitelisted or no name set.
        """
        entry = self.get_entry(mac_address)
        if entry and entry.name:
            return entry.name
        return None

    def add_device(
        self,
        mac_address: str,
        name: str = "",
        category: str = "",
        trusted: bool = True,
    ) -> None:
        """Add a device to the whitelist.

        Args:
            mac_address: MAC address to add.
            name: Human-readable name for the device.
            category: Device category.
            trusted: Whether the device is trusted.
        """
        mac = normalize_mac(mac_address)
        self._entries[mac] = WhitelistEntry(
            mac_address=mac,
            name=name,
            category=category,
            trusted=trusted,
        )
        logger.info("Added device to whitelist.")

    def remove_device(self, mac_address: str) -> bool:
        """Remove a device from the whitelist.

        Args:
            mac_address: MAC address to remove.

        Returns:
            True if the device was found and removed.
        """
        try:
            mac = normalize_mac(mac_address)
        except ValueError:
            return False
        if mac in self._entries:
            del self._entries[mac]
            logger.info("Removed device from whitelist.")
            return True
        return False

    @property
    def entries(self) -> list[WhitelistEntry]:
        """Get all whitelist entries.

        Returns:
            List of all WhitelistEntry objects.
        """
        return list(self._entries.values())

    def __len__(self) -> int:
        """Return the number of whitelist entries."""
        return len(self._entries)
