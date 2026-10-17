"""Admin endpoints: user management, system administration.

All endpoints require admin role. Provides user listing, role changes,
and account activation/deactivation.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import UserResponse
from app.core.auth import get_authenticated_user, hash_password, require_role

router = APIRouter(dependencies=[Depends(require_role("admin"))])


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """List all registered users.

    Returns id, username, email, role, is_active, created_at for every user.
    Requires admin role.
    """
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.patch("/users/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Change a user's role (e.g. promote to admin, demote to user).

    Request body: { "role": "admin" | "user" }
    Cannot change your own role (prevents lockout).
    """
    new_role = body.get("role")
    if new_role not in ("admin", "user"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Role must be 'admin' or 'user'",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot change your own role",
        )

    user.role = new_role
    await db.commit()
    await db.refresh(user)
    return user


@router.patch("/users/{user_id}/status", response_model=UserResponse)
async def toggle_user_status(
    user_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Activate or deactivate a user account.

    Request body: { "is_active": true | false }
    Cannot deactivate your own account.
    """
    is_active = body.get("is_active")
    if not isinstance(is_active, bool):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="is_active must be a boolean",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot change your own status",
        )

    user.is_active = is_active
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/users/pending", response_model=list[UserResponse])
async def list_pending_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """List all users pending admin approval (is_active=False, role='user')."""
    result = await db.execute(
        select(User).where(User.is_active == False, User.role == "user")
        .order_by(User.created_at.asc())
    )
    return result.scalars().all()


@router.post("/users/{user_id}/approve", response_model=UserResponse)
async def approve_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Approve a pending user account by setting is_active=True."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already active",
        )

    user.is_active = True
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Permanently delete a user account and all associated data.

    Cannot delete your own account.

    Orphaned scans are reassigned to the API system user so they remain
    accessible by other collaborators and admins.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot delete your own account",
        )

    # Reassign orphaned scans to the __api__ user so they don't break
    api_result = await db.execute(select(User).where(User.username == "__api__"))
    api_user = api_result.scalar_one_or_none()

    from app.models.scan import Scan
    scans_result = await db.execute(select(Scan).where(Scan.owner_id == user_id))
    orphan_scans = scans_result.scalars().all()
    for scan in orphan_scans:
        scan.owner_id = api_user.id if api_user else current_user.id
        db.add(scan)

    await db.delete(user)
    await db.commit()
    return None


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Admin-only: reset any user's password.

    Request body: { "new_password": "new-password-value" }
    The new password must be at least 12 characters.
    """
    new_password = body.get("new_password")
    if not new_password or not isinstance(new_password, str) or len(new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="new_password must be a string with at least 12 characters",
        )

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    user.hashed_password = hash_password(new_password)
    await db.commit()

    return {"message": f"Password reset for user '{user.username}'"}
