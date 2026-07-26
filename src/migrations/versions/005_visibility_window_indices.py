"""Add indices on visibility_windows.first_seen, last_seen, and composite mac+last_seen.

These indices improve query performance for large deployments when filtering
visibility windows by time range or looking up the latest window for a device.

Revision ID: 005_visibility_window_indices
Revises: 004_merged_into
Create Date: 2026-04-29 00:00:00.000000
"""

from alembic import op

revision = "005_visibility_window_indices"
down_revision = "004_merged_into"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add indices on visibility_windows time columns (P: index audit)."""
    op.create_index("ix_visibility_windows_first_seen", "visibility_windows", ["first_seen"])
    op.create_index("ix_visibility_windows_last_seen", "visibility_windows", ["last_seen"])
    op.create_index(
        "ix_visibility_windows_mac_last_seen",
        "visibility_windows",
        ["mac_address", "last_seen"],
    )


def downgrade() -> None:
    """Remove the time-range indices from visibility_windows."""
    op.drop_index("ix_visibility_windows_mac_last_seen", table_name="visibility_windows")
    op.drop_index("ix_visibility_windows_last_seen", table_name="visibility_windows")
    op.drop_index("ix_visibility_windows_first_seen", table_name="visibility_windows")
