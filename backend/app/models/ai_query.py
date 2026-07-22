from sqlalchemy import Column, String, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.models.base import BaseModel

class AIQuery(BaseModel):
    __tablename__ = "ai_queries"

    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_prompt = Column(String, nullable=False)
    generated_dork = Column(String, nullable=False)
    model_used = Column(String, nullable=False)
    search_results = Column(JSON, nullable=False, default=list)
