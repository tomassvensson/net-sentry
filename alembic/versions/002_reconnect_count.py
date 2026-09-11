"""Add reconnect_count to devices table.

Revision ID: 002_reconnect_count
Revises: 001_initial
Create Date: 2026-01-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "002_reconnect_count"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add reconnect_count column to devices table."""
    op.add_column(
        "devices",
        sa.Column("reconnect_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    """Remove reconnect_count column from devices table."""
    op.drop_column("devices", "reconnect_count")
