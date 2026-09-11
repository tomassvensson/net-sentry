"""Add fingerprint_confidence column to devices table.

Revision ID: 007_fingerprint_confidence
Revises: 006_device_notes_photo
Create Date: 2025-01-01
"""

import sqlalchemy as sa
from alembic import op

revision = "007_fingerprint_confidence"
down_revision = "006_device_notes_photo"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("fingerprint_confidence", sa.Float, nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "fingerprint_confidence")
