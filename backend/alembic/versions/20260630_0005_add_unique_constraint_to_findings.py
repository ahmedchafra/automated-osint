"""Add unique constraint to prevent duplicate findings

Adds a UniqueConstraint on (scan_id, entity_type, entity_value, source_module)
to prevent concurrent Celery tasks from creating duplicate findings for the
same scan + source.

Revision ID: 20260630_0005_add_unique_constraint_to_findings
Revises: 20260629_0004_add_updated_at_to_scans
Create Date: 2026-06-30 20:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '20260630_0005_add_unique_constraint_to_findings'
down_revision: Union[str, Sequence[str], None] = '20260629_0004_add_updated_at_to_scans'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove any existing duplicates before adding the constraint
    # Keep the earliest-created row for each group
    op.execute("""
        DELETE FROM findings a
        USING findings b
        WHERE a.id > b.id
          AND a.scan_id = b.scan_id
          AND a.entity_type = b.entity_type
          AND a.entity_value = b.entity_value
          AND a.source_module = b.source_module
    """)
    op.create_unique_constraint(
        "uq_finding_scan_entity_source",
        "findings",
        ["scan_id", "entity_type", "entity_value", "source_module"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_finding_scan_entity_source", "findings", type_="unique")
