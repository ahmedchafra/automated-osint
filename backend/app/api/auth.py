"""Authentication endpoints: register, login, and user profile."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.core.auth import (
    create_access_token,
    get_authenticated_user,
    hash_password,
    verify_password,
)
from app.core.rate_limit import enforce_rate_limit

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account.

    Username must be 3-50 alphanumeric characters (underscores allowed).
    Email must be a valid email address.
    Password must be at least 12 characters.

    New accounts are created with is_active=False and require admin approval
    before they can log in.
    """
    await enforce_rate_limit(
        request, bucket="register", limit=5, window_seconds=3600
    )

    # Check username uniqueness
    result = await db.execute(select(User).where(User.username == body.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    # Check email uniqueness
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Create user (inactive — pending admin approval)
    user = User(
        username=body.username,
        email=body.email,
        hashed_password=hash_password(body.password),
        role="user",
        is_active=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    return {
        "message": "Account created. An administrator will review and activate your account.",
        "user": UserResponse.model_validate(user),
    }


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with username/email and password. Returns a JWT token."""
    await enforce_rate_limit(
        request,
        bucket="login",
        limit=10,
        window_seconds=300,
        subject=body.username,
    )
    # Look up by username or email
    result = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.username)
        )
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated",
        )

    # Create JWT
    token = create_access_token(
        data={
            "sub": user.id,
            "username": user.username,
            "role": user.role,
        }
    )

    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_authenticated_user)):
    """Return the currently authenticated user's profile.

    Requires a valid JWT (API key auth returns 401 for this endpoint
    since there's no user context).
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key auth has no user context. Use JWT auth.",
        )
    return current_user


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Change the currently authenticated user's password.

    Requires the old password for verification. The new password must be
    at least 12 characters.
    """
    if not verify_password(body.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    current_user.hashed_password = hash_password(body.new_password)
    db.add(current_user)
    await db.commit()

    return {"message": "Password updated successfully"}
