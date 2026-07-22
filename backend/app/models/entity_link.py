from sqlalchemy import Column, String, Float, ForeignKey
from sqlalchemy.orm import relationship

from app.models.base import BaseModel

class EntityLink(BaseModel):
    __tablename__ = "entity_links"

    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    source_finding_id = Column(String, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    target_finding_id = Column(String, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    link_type = Column(String, nullable=False) # RESOLVES_TO, HAS_PORT, MATCHES_CVE, BREACHED_IN
    confidence = Column(Float, nullable=False, default=1.0)

    source_finding = relationship("Finding", foreign_keys=[source_finding_id], back_populates="source_links")
    target_finding = relationship("Finding", foreign_keys=[target_finding_id], back_populates="target_links")
