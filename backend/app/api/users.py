"""User endpoints: profile and search for authenticated users."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.database import get_db
from app.models.user import User
from app.schemas.auth import UserResponse
from app.core.auth import get_authenticated_user

router = APIRouter()


@router.get("/search", response_model=List[UserResponse])
async def search_users(
    q: str = Query(..., min_length=1, max_length=100, description="Username or email prefix to search"),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Search for users by username (prefix match).

    Returns matching users with id, username, email, role, is_active.
    Non-admin users only see active users. Admin users see all users.

    Any authenticated user can search — needed for adding collaborators.
    """
    filters = [User.username.ilike(f"{q}%")]

    # Non-admin users should only see active users to avoid leaking
    # inactive account info during collaborator search.
    if not current_user or current_user.role != "admin":
        filters.append(User.is_active == True)

    stmt = (
        select(User)
        .where(*filters)
        .order_by(User.username.asc())
        .limit(limit)
    )

    result = await db.execute(stmt)
    users = result.scalars().all()
    return users
