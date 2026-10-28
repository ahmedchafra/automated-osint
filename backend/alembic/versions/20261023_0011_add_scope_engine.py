"""Add persisted scan scope and asset decisions.

Revision ID: 20261023_0011_add_scope_engine
Revises: 20261022_0010_add_assets
"""
from alembic import op
import sqlalchemy as sa


revision = "20261023_0011_add_scope_engine"
down_revision = "20261022_0010_add_assets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    scan_columns = {column["name"] for column in inspector.get_columns("scans")}
    if "scope_manifest" not in scan_columns:
        op.add_column(
            "scans",
            sa.Column("scope_manifest", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        )
    asset_columns = {column["name"] for column in inspector.get_columns("assets")}
    if "scope_reason" not in asset_columns:
        op.add_column(
            "assets",
            sa.Column("scope_reason", sa.String(), nullable=False, server_default="allowed"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    asset_columns = {column["name"] for column in inspector.get_columns("assets")}
    if "scope_reason" in asset_columns:
        op.drop_column("assets", "scope_reason")
    scan_columns = {column["name"] for column in inspector.get_columns("scans")}
    if "scope_manifest" in scan_columns:
        op.drop_column("scans", "scope_manifest")
