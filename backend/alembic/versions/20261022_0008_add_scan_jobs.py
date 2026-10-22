"""Add persistent scan job execution ledger.

Revision ID: 20261022_0008_add_scan_jobs
Revises: 20261017_0007_add_scan_task_id
"""

from alembic import op
import sqlalchemy as sa


revision = "20261022_0008_add_scan_jobs"
down_revision = "20261017_0007_add_scan_task_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "scan_jobs" in inspector.get_table_names():
        return

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("parent_job_id", sa.String(), nullable=True),
        sa.Column("celery_task_id", sa.String(), nullable=False),
        sa.Column("job_type", sa.String(), nullable=False),
        sa.Column("stage", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("input_type", sa.String(), nullable=True),
        sa.Column("input_value", sa.Text(), nullable=True),
        sa.Column("progress", sa.JSON(), nullable=False),
        sa.Column("result_summary", sa.JSON(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["parent_job_id"], ["scan_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("celery_task_id"),
    )
    op.create_index("ix_scan_jobs_scan_id", "scan_jobs", ["scan_id"])
    op.create_index("ix_scan_jobs_parent_job_id", "scan_jobs", ["parent_job_id"])
    op.create_index("ix_scan_jobs_celery_task_id", "scan_jobs", ["celery_task_id"])
    op.create_index("ix_scan_jobs_job_type", "scan_jobs", ["job_type"])
    op.create_index("ix_scan_jobs_stage", "scan_jobs", ["stage"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_scan_status", "scan_jobs", ["scan_id", "status"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "scan_jobs" in inspector.get_table_names():
        op.drop_table("scan_jobs")
