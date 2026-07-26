"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2025-01-01 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create initial tables: devices and visibility_windows."""
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("device_type", sa.String(20), nullable=False),
        sa.Column("vendor", sa.String(255), nullable=True),
        sa.Column("device_name", sa.String(255), nullable=True),
        sa.Column("ssid", sa.String(255), nullable=True),
        sa.Column("network_type", sa.String(50), nullable=True),
        sa.Column("authentication", sa.String(100), nullable=True),
        sa.Column("encryption", sa.String(100), nullable=True),
        sa.Column("radio_type", sa.String(50), nullable=True),
        sa.Column("channel", sa.Integer(), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("category", sa.String(50), nullable=True),
        sa.Column("extra_info", sa.Text(), nullable=True),
        sa.Column("is_whitelisted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("mac_address"),
    )
    op.create_index("ix_devices_mac_address", "devices", ["mac_address"])

    op.create_table(
        "visibility_windows",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("mac_address", sa.String(17), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("signal_strength_dbm", sa.Float(), nullable=True),
        sa.Column("min_signal_dbm", sa.Float(), nullable=True),
        sa.Column("max_signal_dbm", sa.Float(), nullable=True),
        sa.Column("scan_count", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_visibility_windows_mac_address", "visibility_windows", ["mac_address"])


def downgrade() -> None:
    """Drop initial tables."""
    op.drop_index("ix_visibility_windows_mac_address", table_name="visibility_windows")
    op.drop_table("visibility_windows")
    op.drop_index("ix_devices_mac_address", table_name="devices")
    op.drop_table("devices")
