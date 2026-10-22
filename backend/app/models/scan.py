from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, func
from sqlalchemy.orm import relationship

from app.models.base import BaseModel

class Scan(BaseModel):
    __tablename__ = "scans"

    target_domain = Column(String, nullable=False, index=True)
    target_type = Column(
        String, nullable=False, default="domain", server_default="domain"
    )
    status = Column(String, nullable=False, default="PENDING") # PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    celery_task_id = Column(String, nullable=True, index=True)
    selected_vectors = Column(JSON, nullable=False, default=list)
    target_usernames = Column(JSON, nullable=False, default=list)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    owner_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    # Tracks last activity on the scan (enrichment tasks, pivots, etc.) so the
    # dashboard can sort by "last active" rather than only creation time.
    # Updated via a server_default/onupdate trigger so any row write refreshes it.
    updated_at = Column(
        DateTime(timezone=True),
        nullable=True,
        server_default=func.now(),
        onupdate=func.now(),
    )

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    jobs = relationship("ScanJob", back_populates="scan", cascade="all, delete-orphan")
    owner = relationship("User", foreign_keys=[owner_id])
    collaborators = relationship("ScanCollaborator", back_populates="scan", cascade="all, delete-orphan")

    findings_count: int = 0
