"""Add explicit scan interaction mode.

Revision ID: 20261022_0009_add_scan_mode
Revises: 20261022_0008_add_scan_jobs
"""

from alembic import op
import sqlalchemy as sa


revision = "20261022_0009_add_scan_mode"
down_revision = "20261022_0008_add_scan_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("scans")}
    if "scan_mode" not in columns:
        op.add_column(
            "scans",
            sa.Column(
                "scan_mode",
                sa.String(),
                server_default="validated",
                nullable=False,
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("scans")}
    if "scan_mode" in columns:
        op.drop_column("scans", "scan_mode")
