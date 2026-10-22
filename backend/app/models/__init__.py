from app.models.base import BaseModel, Base
from app.models.user import User
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.entity_link import EntityLink
from app.models.ai_query import AIQuery
from app.models.scan_collaborator import ScanCollaborator
from app.models.scan_job import ScanJob

# Explicitly import all models to ensure they are registered with Base.metadata
__all__ = [
    "BaseModel",
    "Base",
    "User",
    "Scan",
    "Finding",
    "EntityLink",
    "AIQuery",
    "ScanCollaborator",
    "ScanJob",
]

