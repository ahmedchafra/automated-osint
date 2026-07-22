"""Add scan target usernames

Revision ID: 20260618_0002
Revises: 5441414d9d07
Create Date: 2026-06-18
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "20260618_0002"
down_revision: Union[str, Sequence[str], None] = "5441414d9d07"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("target_usernames", sa.JSON(), nullable=False, server_default="[]"))
    op.alter_column("scans", "target_usernames", server_default=None)


def downgrade() -> None:
    op.drop_column("scans", "target_usernames")
