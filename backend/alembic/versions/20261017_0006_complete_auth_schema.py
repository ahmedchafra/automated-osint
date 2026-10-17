"""Complete authentication, ownership, and collaboration schema.

Revision ID: 20261017_0006_complete_auth_schema
Revises: 20260630_0005_add_unique_constraint_to_findings
Create Date: 2026-10-17

This migration is intentionally drift-tolerant. Earlier development databases
received these tables and columns through ``metadata.create_all`` and manual
changes, while fresh Alembic databases did not. Conditional checks make the
migration safe for both histories.
"""

from __future__ import annotations

import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20261017_0006_complete_auth_schema"
down_revision: Union[str, Sequence[str], None] = (
    "20260630_0005_add_unique_constraint_to_findings"
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _inspector():
    return sa.inspect(op.get_bind())


def _columns(table_name: str) -> set[str]:
    return {column["name"] for column in _inspector().get_columns(table_name)}


def upgrade() -> None:
    inspector = _inspector()
    tables = set(inspector.get_table_names())

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("username", sa.String(), nullable=False),
            sa.Column("email", sa.String(), nullable=False),
            sa.Column("hashed_password", sa.String(), nullable=False),
            sa.Column("role", sa.String(), nullable=True, server_default="user"),
            sa.Column("is_active", sa.Boolean(), nullable=True, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("email", name="uq_users_email"),
            sa.UniqueConstraint("username", name="uq_users_username"),
        )
        op.create_index("ix_users_username", "users", ["username"], unique=True)

    scan_columns = _columns("scans")
    if "target_type" not in scan_columns:
        op.add_column(
            "scans",
            sa.Column("target_type", sa.String(), nullable=False, server_default="domain"),
        )

    if "owner_id" not in scan_columns:
        legacy_owner_id = str(uuid.uuid4())
        users = sa.table(
            "users",
            sa.column("id", sa.String()),
            sa.column("username", sa.String()),
            sa.column("email", sa.String()),
            sa.column("hashed_password", sa.String()),
            sa.column("role", sa.String()),
            sa.column("is_active", sa.Boolean()),
        )
        op.bulk_insert(
            users,
            [{
                "id": legacy_owner_id,
                "username": "__legacy__",
                "email": "legacy-owner@local.invalid",
                "hashed_password": "!",
                "role": "user",
                "is_active": False,
            }],
        )
        op.add_column("scans", sa.Column("owner_id", sa.String(), nullable=True))
        op.execute(
            sa.text("UPDATE scans SET owner_id = :owner_id WHERE owner_id IS NULL")
            .bindparams(owner_id=legacy_owner_id)
        )
        op.alter_column("scans", "owner_id", nullable=False)
        op.create_foreign_key(
            "fk_scans_owner_id_users", "scans", "users", ["owner_id"], ["id"]
        )
        op.create_index("ix_scans_owner_id", "scans", ["owner_id"], unique=False)

    if "scan_collaborators" not in set(_inspector().get_table_names()):
        op.create_table(
            "scan_collaborators",
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("user_id", sa.String(), nullable=False),
            sa.Column("permission", sa.String(), nullable=False, server_default="read"),
            sa.Column("invited_by", sa.String(), nullable=True),
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["invited_by"], ["users.id"]),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("scan_id", "user_id", name="uq_scan_collaborator"),
        )
        op.create_index(
            "ix_scan_collaborators_scan_id",
            "scan_collaborators",
            ["scan_id"],
            unique=False,
        )
        op.create_index(
            "ix_scan_collaborators_user_id",
            "scan_collaborators",
            ["user_id"],
            unique=False,
        )


def downgrade() -> None:
    tables = set(_inspector().get_table_names())
    if "scan_collaborators" in tables:
        op.drop_table("scan_collaborators")

    scan_columns = _columns("scans")
    if "owner_id" in scan_columns:
        op.drop_column("scans", "owner_id")
    if "target_type" in scan_columns:
        op.drop_column("scans", "target_type")

    if "users" in tables:
        op.drop_table("users")
