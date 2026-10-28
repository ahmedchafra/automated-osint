"""Add authenticated screenshot evidence records.

Revision ID: 20261023_0012_add_screenshot_evidence
Revises: 20261023_0011_add_scope_engine
"""
from alembic import op
import sqlalchemy as sa


revision = "20261023_0012_add_screenshot_evidence"
down_revision = "20261023_0011_add_scope_engine"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "screenshot_evidence" in inspector.get_table_names():
        return
    op.create_table(
        "screenshot_evidence",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("asset_id", sa.String(), nullable=True),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("height", sa.Integer(), nullable=False),
        sa.Column("page_title", sa.Text(), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("capture_metadata", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key"),
    )
    op.create_index("ix_screenshot_evidence_scan_id", "screenshot_evidence", ["scan_id"])
    op.create_index("ix_screenshot_evidence_asset_id", "screenshot_evidence", ["asset_id"])
    op.create_index("ix_screenshot_evidence_sha256", "screenshot_evidence", ["sha256"])


def downgrade() -> None:
    bind = op.get_bind()
    if "screenshot_evidence" in sa.inspect(bind).get_table_names():
        op.drop_table("screenshot_evidence")
