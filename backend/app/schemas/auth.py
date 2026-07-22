"""Pydantic schemas for authentication."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """User registration payload."""

    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=6, max_length=128)


class LoginRequest(BaseModel):
    """Login payload — accepts username or email in the username field."""

    username: str = Field(..., min_length=1, description="Username or email address")
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    """Public user data returned by the API."""

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AddScanCollaboratorRequest(BaseModel):
    """Request body for adding a collaborator to a scan."""

    user_id: str = Field(..., description="User ID of the collaborator to add")
    permission: str = Field(
        "read",
        pattern="^(read|modify)$",
        description="Permission level: 'read' or 'modify'",
    )


class ScanCollaboratorResponse(BaseModel):
    """Collaborator info returned by the API."""

    id: str
    scan_id: str
    user_id: str
    username: str = ""
    permission: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ChangePasswordRequest(BaseModel):
    """Payload for changing a user's password."""

    old_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=6, max_length=128)


class ScanPermissionResponse(BaseModel):
    """Permission level for the current user on a scan."""

    permission: str  # "owner", "modify", "read"
    is_admin: bool = False
