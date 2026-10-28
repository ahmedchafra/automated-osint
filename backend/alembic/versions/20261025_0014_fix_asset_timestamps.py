"""Use statement-time application values for asset lifecycle timestamps.

Revision ID: 20261025_0014_fix_asset_timestamps
Revises: 20261023_0013_add_asset_observations
"""

from alembic import op
import sqlalchemy as sa


revision = "20261025_0014_fix_asset_timestamps"
down_revision = "20261023_0013_add_asset_observations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PostgreSQL's now() is fixed at transaction start. Asset creation can
    # happen minutes into a scan transaction, so repair impossible ordering
    # before removing the misleading database-side defaults. The ORM supplies
    # UTC values for every future insert/update.
    op.execute(
        sa.text(
            "UPDATE assets SET updated_at = created_at "
            "WHERE updated_at < created_at"
        )
    )
    op.execute(
        sa.text(
            "UPDATE assets SET last_observed_at = created_at "
            "WHERE last_observed_at < created_at"
        )
    )
    op.alter_column(
        "assets",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=None,
    )
    op.alter_column(
        "assets",
        "last_observed_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=None,
    )


def downgrade() -> None:
    op.alter_column(
        "assets",
        "last_observed_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=sa.func.now(),
    )
    op.alter_column(
        "assets",
        "updated_at",
        existing_type=sa.DateTime(timezone=True),
        existing_nullable=False,
        server_default=sa.func.now(),
    )
