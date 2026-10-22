"""Add canonical scan asset inventory.

Revision ID: 20261022_0010_add_assets
Revises: 20261022_0009_add_scan_mode
"""

from alembic import op
import sqlalchemy as sa


revision = "20261022_0010_add_assets"
down_revision = "20261022_0009_add_scan_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "assets" in inspector.get_table_names():
        return

    op.create_table(
        "assets",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("asset_type", sa.String(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("canonical_value", sa.Text(), nullable=False),
        sa.Column("registrable_domain", sa.String(), nullable=True),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("in_scope", sa.Boolean(), nullable=False),
        sa.Column("wildcard_suspected", sa.Boolean(), nullable=False),
        sa.Column("source_modules", sa.JSON(), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("dns_records", sa.JSON(), nullable=False),
        sa.Column("resolved_ips", sa.JSON(), nullable=False),
        sa.Column("http_metadata", sa.JSON(), nullable=False),
        sa.Column(
            "last_observed_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id", "asset_type", "canonical_value",
            name="uq_asset_scan_type_value",
        ),
    )
    op.create_index("ix_assets_scan_id", "assets", ["scan_id"])
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])
    op.create_index("ix_assets_registrable_domain", "assets", ["registrable_domain"])
    op.create_index("ix_assets_state", "assets", ["state"])
    op.create_index("ix_assets_scan_state", "assets", ["scan_id", "state"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "assets" in inspector.get_table_names():
        op.drop_table("assets")
