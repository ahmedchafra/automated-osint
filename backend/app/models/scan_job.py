from sqlalchemy import Column, DateTime, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class ScanJob(BaseModel):
    """Persistent execution record for a Celery task belonging to a scan."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_scan_status", "scan_id", "status"),
    )

    scan_id = Column(
        String,
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_job_id = Column(
        String,
        ForeignKey("scan_jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    celery_task_id = Column(String, nullable=False, unique=True, index=True)
    job_type = Column(String, nullable=False, index=True)
    stage = Column(String, nullable=False, default="on_demand", index=True)
    status = Column(String, nullable=False, default="QUEUED", index=True)
    input_type = Column(String, nullable=True)
    input_value = Column(Text, nullable=True)
    progress = Column(JSON, nullable=False, default=dict)
    result_summary = Column(JSON, nullable=False, default=dict)
    error = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    scan = relationship("Scan", back_populates="jobs")
    parent = relationship("ScanJob", remote_side="ScanJob.id")
