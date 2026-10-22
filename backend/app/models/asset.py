from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class Asset(BaseModel):
    """Canonical target asset and its highest verified lifecycle state."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "asset_type", "canonical_value",
            name="uq_asset_scan_type_value",
        ),
    )

    scan_id = Column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_type = Column(String, nullable=False, index=True)
    value = Column(Text, nullable=False)
    canonical_value = Column(Text, nullable=False)
    registrable_domain = Column(String, nullable=True, index=True)
    state = Column(String, nullable=False, default="CANDIDATE", index=True)
    in_scope = Column(Boolean, nullable=False, default=True)
    wildcard_suspected = Column(Boolean, nullable=False, default=False)
    source_modules = Column(JSON, nullable=False, default=list)
    evidence_count = Column(Integer, nullable=False, default=1)
    dns_records = Column(JSON, nullable=False, default=dict)
    resolved_ips = Column(JSON, nullable=False, default=list)
    http_metadata = Column(JSON, nullable=False, default=dict)
    last_observed_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    scan = relationship("Scan", back_populates="assets")
