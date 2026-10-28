from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import TSVECTOR
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class Finding(BaseModel):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "entity_type", "entity_value", "source_module",
                         name="uq_finding_scan_entity_source"),
    )

    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    vector_type = Column(String, nullable=False, index=True) # INFRASTRUCTURE, SERVICES, IDENTITY, USERNAME, SEARCH
    entity_type = Column(String, nullable=False, index=True) # SUBDOMAIN, IP_ADDRESS, PORT_SERVICE, CVE, EMAIL, BREACH, PROFILE, DORK_RESULT
    entity_value = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="INFO") # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False, default=1.0)
    source_module = Column(String, nullable=False)
    raw_data = Column(JSON, nullable=False, default=dict)
    normalized_data = Column(JSON, nullable=False, default=dict)
    tags = Column(JSON, nullable=True, default=list) # SQLite doesn't have ARRAY, so use JSON
    first_seen_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    last_seen_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True
    )
    observation_count = Column(Integer, nullable=False, default=1)
    revision = Column(Integer, nullable=False, default=1)
    last_observed_for = Column(String, nullable=True)

    # Mirrors the Alembic migration `20260620_0003_add_tsvector_to_findings`.
    # Postgres-only; ignored on SQLite (no full-text search there). The
    # trigger installed by the migration keeps this populated on insert
    # and update, so callers only ever query it.
    search_vector = Column(TSVECTOR().with_variant(Text(), "sqlite"), nullable=True)

    scan = relationship("Scan", back_populates="findings")

    # Relationships for EntityLinks where this finding is source or target
    source_links = relationship(
        "EntityLink",
        foreign_keys="EntityLink.source_finding_id",
        back_populates="source_finding",
        cascade="all, delete-orphan",
    )
    target_links = relationship(
        "EntityLink",
        foreign_keys="EntityLink.target_finding_id",
        back_populates="target_finding",
        cascade="all, delete-orphan",
    )
