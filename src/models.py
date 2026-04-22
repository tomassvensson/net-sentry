"""SQLAlchemy database models for device visibility tracking."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all database models."""


class Device(Base):
    """A discovered wireless device (WiFi AP, station, or Bluetooth device).

    Stores the device's identity and the most recent metadata.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String(17), unique=True, nullable=False, index=True)
    device_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "wifi_ap", "wifi_client", "bluetooth"
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ssid: Mapped[str | None] = mapped_column(String(255), nullable=True)
    network_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    authentication: Mapped[str | None] = mapped_column(String(100), nullable=True)
    encryption: Mapped[str | None] = mapped_column(String(100), nullable=True)
    radio_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    channel: Mapped[int | None] = mapped_column(Integer, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_whitelisted: Mapped[bool] = mapped_column(default=False, nullable=False)
    reconnect_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        """Return string representation of Device."""
        name = self.device_name or self.ssid or self.mac_address
        return f"<Device(mac={self.mac_address}, type={self.device_type}, name={name})>"


class VisibilityWindow(Base):
    """A time window during which a device was continuously visible.

    Instead of storing every scan result, we store the start and end
    of each continuous visibility period along with signal statistics.
    """

    __tablename__ = "visibility_windows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    signal_strength_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)
    min_signal_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)
    max_signal_dbm: Mapped[float | None] = mapped_column(Float, nullable=True)
    scan_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    def __repr__(self) -> str:
        """Return string representation of VisibilityWindow."""
        return (
            f"<VisibilityWindow(mac={self.mac_address}, "
            f"first={self.first_seen}, last={self.last_seen}, "
            f"signal={self.signal_strength_dbm}dBm)>"
        )
