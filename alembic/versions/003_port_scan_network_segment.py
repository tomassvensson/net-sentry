"""Add open_ports and network_segment columns to devices table.

Revision ID: 003_port_scan_network_segment
Revises: 002_reconnect_count
Create Date: 2026-04-24 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "003_port_scan_network_segment"
down_revision = "002_reconnect_count"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add open_ports and network_segment columns to devices table."""
    op.add_column(
        "devices",
        sa.Column("open_ports", sa.Text(), nullable=True),
    )
    op.add_column(
        "devices",
        sa.Column("network_segment", sa.String(100), nullable=True),
    )


def downgrade() -> None:
    """Remove open_ports and network_segment columns from devices table."""
    op.drop_column("devices", "network_segment")
    op.drop_column("devices", "open_ports")
