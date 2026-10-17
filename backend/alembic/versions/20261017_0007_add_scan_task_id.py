"""Store the Celery task ID used by each top-level scan.

Revision ID: 20261017_0007_add_scan_task_id
Revises: 20261017_0006_complete_auth_schema
"""

from alembic import op
import sqlalchemy as sa


revision = "20261017_0007_add_scan_task_id"
down_revision = "20261017_0006_complete_auth_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("scans")}
    if "celery_task_id" not in columns:
        op.add_column("scans", sa.Column("celery_task_id", sa.String(), nullable=True))

    inspector = sa.inspect(bind)
    indexes = {index["name"] for index in inspector.get_indexes("scans")}
    if "ix_scans_celery_task_id" not in indexes:
        op.create_index(
            "ix_scans_celery_task_id", "scans", ["celery_task_id"], unique=False
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    indexes = {index["name"] for index in inspector.get_indexes("scans")}
    if "ix_scans_celery_task_id" in indexes:
        op.drop_index("ix_scans_celery_task_id", table_name="scans")
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("scans")}
    if "celery_task_id" in columns:
        op.drop_column("scans", "celery_task_id")
