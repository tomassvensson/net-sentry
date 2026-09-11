"""Add merged_into column to devices table for randomized-MAC merging.

Revision ID: 004_merged_into
Revises: 003_port_scan_network_segment
Create Date: 2026-04-26 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "004_merged_into"
down_revision = "003_port_scan_network_segment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add merged_into column to devices table."""
    op.add_column(
        "devices",
        sa.Column("merged_into", sa.String(17), nullable=True),
    )


def downgrade() -> None:
    """Remove merged_into column from devices table."""
    op.drop_column("devices", "merged_into")
