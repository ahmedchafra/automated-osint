from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String, Text, func
from sqlalchemy.orm import relationship

from app.models.base import BaseModel


class AssetObservation(BaseModel):
    """Append-only evidence that an asset was observed at a point in time."""

    __tablename__ = "asset_observations"

    scan_id = Column(
        String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id = Column(
        String, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_type = Column(String(32), nullable=False, index=True)
    canonical_value = Column(Text, nullable=False, index=True)
    state = Column(String(16), nullable=False, index=True)
    source_module = Column(String(128), nullable=True, index=True)
    event_type = Column(String(32), nullable=False, index=True)
    in_scope = Column(Boolean, nullable=False, default=True)
    wildcard_suspected = Column(Boolean, nullable=False, default=False)
    evidence = Column(JSON, nullable=False, default=dict)
    observed_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    scan = relationship("Scan", back_populates="asset_observations")
    asset = relationship("Asset", back_populates="observations")
