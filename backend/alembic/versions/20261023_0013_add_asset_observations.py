"""Add the append-only asset observation timeline.

Revision ID: 20261023_0013_add_asset_observations
Revises: 20261023_0012_add_screenshot_evidence
"""
import uuid

from alembic import op
import sqlalchemy as sa


revision = "20261023_0013_add_asset_observations"
down_revision = "20261023_0012_add_screenshot_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "asset_observations" in inspector.get_table_names():
        return

    op.create_table(
        "asset_observations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("asset_id", sa.String(), nullable=False),
        sa.Column("asset_type", sa.String(length=32), nullable=False),
        sa.Column("canonical_value", sa.Text(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("source_module", sa.String(length=128), nullable=True),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("in_scope", sa.Boolean(), nullable=False),
        sa.Column("wildcard_suspected", sa.Boolean(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_observations_scan_id", "asset_observations", ["scan_id"])
    op.create_index("ix_asset_observations_asset_id", "asset_observations", ["asset_id"])
    op.create_index("ix_asset_observations_asset_type", "asset_observations", ["asset_type"])
    op.create_index("ix_asset_observations_canonical_value", "asset_observations", ["canonical_value"])
    op.create_index("ix_asset_observations_state", "asset_observations", ["state"])
    op.create_index("ix_asset_observations_source_module", "asset_observations", ["source_module"])
    op.create_index("ix_asset_observations_event_type", "asset_observations", ["event_type"])
    op.create_index("ix_asset_observations_observed_at", "asset_observations", ["observed_at"])
    op.create_index(
        "ix_asset_observations_scan_time",
        "asset_observations",
        ["scan_id", "observed_at"],
    )

    assets = bind.execute(
        sa.text(
            "SELECT id, created_at, scan_id, asset_type, canonical_value, state, "
            "in_scope, wildcard_suspected, source_modules, last_observed_at FROM assets"
        )
    ).mappings()
    observation_table = sa.table(
        "asset_observations",
        sa.column("id", sa.String()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("scan_id", sa.String()),
        sa.column("asset_id", sa.String()),
        sa.column("asset_type", sa.String()),
        sa.column("canonical_value", sa.Text()),
        sa.column("state", sa.String()),
        sa.column("source_module", sa.String()),
        sa.column("event_type", sa.String()),
        sa.column("in_scope", sa.Boolean()),
        sa.column("wildcard_suspected", sa.Boolean()),
        sa.column("evidence", sa.JSON()),
        sa.column("observed_at", sa.DateTime(timezone=True)),
    )
    rows = [
        {
            "id": str(uuid.uuid4()),
            "created_at": asset["last_observed_at"] or asset["created_at"],
            "scan_id": asset["scan_id"],
            "asset_id": asset["id"],
            "asset_type": asset["asset_type"],
            "canonical_value": asset["canonical_value"],
            "state": asset["state"],
            "source_module": None,
            "event_type": "BASELINE",
            "in_scope": asset["in_scope"],
            "wildcard_suspected": asset["wildcard_suspected"],
            "evidence": {
                "backfilled": True,
                "source_modules": asset["source_modules"] or [],
            },
            "observed_at": asset["last_observed_at"] or asset["created_at"],
        }
        for asset in assets
    ]
    if rows:
        op.bulk_insert(observation_table, rows)


def downgrade() -> None:
    bind = op.get_bind()
    if "asset_observations" in sa.inspect(bind).get_table_names():
        op.drop_table("asset_observations")
