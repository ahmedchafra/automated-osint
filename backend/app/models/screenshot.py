from sqlalchemy import Column, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class ScreenshotEvidence(BaseModel):
    """Rendered web evidence captured from a verified, in-scope live URL."""

    __tablename__ = "screenshot_evidence"

    scan_id = Column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id = Column(
        String, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    url = Column(Text, nullable=False)
    storage_key = Column(Text, nullable=False, unique=True)
    sha256 = Column(String(64), nullable=False, index=True)
    width = Column(Integer, nullable=False)
    height = Column(Integer, nullable=False)
    page_title = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    capture_metadata = Column(JSON, nullable=False, default=dict)

    scan = relationship("Scan", back_populates="screenshots")
    asset = relationship("Asset")
