"""Add label, notes, photo_path to devices table.

Revision ID: 006_device_notes_photo
Revises: 005_visibility_window_indices
Create Date: 2025-01-01
"""

from alembic import op
import sqlalchemy as sa

revision = "006_device_notes_photo"
down_revision = "005_visibility_window_indices"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("label", sa.String(255), nullable=True))
    op.add_column("devices", sa.Column("notes", sa.Text, nullable=True))
    op.add_column("devices", sa.Column("photo_path", sa.String(512), nullable=True))


def downgrade() -> None:
    op.drop_column("devices", "photo_path")
    op.drop_column("devices", "notes")
    op.drop_column("devices", "label")
