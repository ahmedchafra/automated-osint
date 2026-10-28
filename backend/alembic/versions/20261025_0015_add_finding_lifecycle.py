"""Add observation and revision lifecycle fields to findings.

Revision ID: 20261025_0015_add_finding_lifecycle
Revises: 20261025_0014_fix_asset_timestamps
"""

from alembic import op
import sqlalchemy as sa


revision = "20261025_0015_add_finding_lifecycle"
down_revision = "20261025_0014_fix_asset_timestamps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("observation_count", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("findings", sa.Column("revision", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("findings", sa.Column("last_observed_for", sa.String(), nullable=True))
    op.execute(sa.text("UPDATE findings SET first_seen_at = created_at, last_seen_at = created_at"))
    op.alter_column("findings", "first_seen_at", nullable=False)
    op.alter_column("findings", "last_seen_at", nullable=False)
    op.create_index("ix_findings_last_seen_at", "findings", ["last_seen_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_last_seen_at", table_name="findings")
    op.drop_column("findings", "last_observed_for")
    op.drop_column("findings", "revision")
    op.drop_column("findings", "observation_count")
    op.drop_column("findings", "last_seen_at")
    op.drop_column("findings", "first_seen_at")
