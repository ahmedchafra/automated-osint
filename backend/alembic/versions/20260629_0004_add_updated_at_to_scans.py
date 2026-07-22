"""Add updated_at column to scans for last-activity tracking

Revision ID: 20260629_0004_add_updated_at_to_scans
Revises: 20260620_0003_add_tsvector_to_findings
Create Date: 2026-06-29 19:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '20260629_0004_add_updated_at_to_scans'
down_revision: Union[str, Sequence[str], None] = '20260620_0003_add_tsvector_to_findings'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'scans',
        sa.Column(
            'updated_at',
            sa.DateTime(timezone=True),
            nullable=True,
            server_default=sa.func.now(),
        ),
    )
    # Backfill existing rows so they have a meaningful "last activity" time.
    op.execute("UPDATE scans SET updated_at = completed_at WHERE completed_at IS NOT NULL")
    op.execute("UPDATE scans SET updated_at = created_at WHERE updated_at IS NULL")


def downgrade() -> None:
    op.drop_column('scans', 'updated_at')
