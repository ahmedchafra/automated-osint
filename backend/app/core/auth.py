"""JWT authentication, password hashing, and combined API key + JWT dependency.

Supports two authentication methods:
  1. X-API-Key header  — used by Celery workers and dev scripts
  2. Authorization: Bearer <JWT>  — used by the frontend after login
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import exists, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User

# ── Password hashing ────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ── JWT tokens ──────────────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token.

    Args:
        data: Claims to embed (must include 'sub' for user_id).
        expires_delta: Token lifetime. Defaults to ACCESS_TOKEN_EXPIRE_MINUTES.

    Returns:
        Encoded JWT string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token.

    Raises:
        HTTPException 401 if the token is invalid or expired.
    """
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def accessible_scan_ids_stmt(current_user: User):
    """Return a SELECT of scan IDs visible to ``current_user``.

    Keeping this as a SQL subquery avoids loading every accessible scan ID
    into Python and gives findings, links, exports, AI history, and future
    endpoints one consistent tenant boundary.
    """
    from app.models.scan import Scan
    from app.models.scan_collaborator import ScanCollaborator

    stmt = select(Scan.id)
    if current_user.role == "admin":
        return stmt

    collaborator_access = exists(
        select(ScanCollaborator.id).where(
            ScanCollaborator.scan_id == Scan.id,
            ScanCollaborator.user_id == current_user.id,
        )
    )
    return stmt.where(
        or_(Scan.owner_id == current_user.id, collaborator_access)
    )


# ── Dependencies ────────────────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


async def get_authenticated_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
    api_key: str = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[User]:
    """Combined auth dependency that accepts X-API-Key OR JWT Bearer token.

    - X-API-Key: skips user lookup, just validates against settings.API_KEY.
    - JWT: decodes the token, fetches the User from DB, returns it.

    Returns:
        User object if JWT auth was used (for endpoint user introspection).
        None if API key auth was used (no user context available).

    Raises:
        401 if neither method provides valid credentials.
    """
    # Allow CORS preflight through
    if request.method == "OPTIONS":
        return None

    # Try API key first (used by Celery workers, dev scripts, frontend pre-login)
    if api_key and api_key == settings.API_KEY:
        # Return a system user so endpoints that need current_user.id work
        result = await db.execute(
            select(User).where(User.username == "__api__")
        )
        api_user = result.scalar_one_or_none()
        if not api_user:
            api_user = User(
                username="__api__",
                email="api@local",
                hashed_password=hash_password("__api__"),
                role="admin",
            )
            db.add(api_user)
            await db.commit()
            await db.refresh(api_user)
        return api_user

    # Try JWT bearer token (used by frontend)
    if bearer:
        payload = verify_token(bearer.credentials)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token: missing subject")

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")

        return user

    # Neither method provided valid credentials
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated. Provide X-API-Key or Authorization: Bearer <token>",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Role-based access control ─────────────────────────────────────────
from typing import Callable, Awaitable


def require_role(role: str) -> Callable[[User], Awaitable[User]]:
    """Dependency factory that restricts access to users with a specific role.

    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(user: User = Depends(require_role("admin"))):
            ...

    Raises 403 if the user is missing, has no role context (API key), or
    does not have the required role.
    """
    async def _role_checker(
        current_user: Optional[User] = Depends(get_authenticated_user),
    ) -> User:
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key auth has no user context. Use JWT auth with an admin account.",
            )
        if current_user.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{role}', but user has role '{current_user.role}'.",
            )
        return current_user

    return _role_checker


# ── Scan-level permission dependencies ────────────────────────────────
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.scan import Scan
from app.models.scan_collaborator import ScanCollaborator


async def check_scan_access(
    db: AsyncSession,
    scan_id: str,
    current_user: User,
    require_modify: bool = False,
) -> Scan:
    """Check whether *current_user* can access *scan_id* and at what level.

    Args:
        db: An active DB session.
        scan_id: The scan to look up.
        current_user: The authenticated user (must be a JWT user, not API key).
        require_modify: If True, the user must have "modify"-level access.
            If False, "read"-level access suffices.

    Returns:
        The authorized Scan object. Findings are intentionally not loaded;
        callers must use the paginated findings API.

    Raises:
        404 if the scan doesn't exist or the user has no access.
        403 if the user has read-only access but modify is required.
    """
    # Admins can access any scan
    if current_user.role == "admin":
        stmt = select(Scan).where(Scan.id == scan_id)
        result = await db.execute(stmt)
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    # Non-admin: check ownership or collaborator permission
    stmt = (
        select(Scan)
        .options(selectinload(Scan.collaborators))
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Owner has full access
    if scan.owner_id == current_user.id:
        return scan

    # Check collaborator permissions
    if scan.collaborators:
        for collab in scan.collaborators:
            if collab.user_id == current_user.id:
                if require_modify and collab.permission != "modify":
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="You have read-only access to this scan. Modify permission is required.",
                    )
                return scan

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Scan not found",
    )


def _can_access_scan(require_modify: bool = False) -> Callable:
    """Shared factory for scan-level permission dependencies.

    Args:
        require_modify: If True, the user must be owner, admin, or have
            "modify" collaborator permission. If False, "read" suffices.

    Returns a FastAPI dependency that yields the Scan object (so endpoints
    don't re-fetch it) or raises 403/404.
    """
    async def _checker(
        scan_id: str,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_authenticated_user),
    ) -> Scan:
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key auth has no user context for scan-level permissions.",
            )
        return await check_scan_access(db, scan_id, current_user, require_modify)

    return _checker


def can_read_scan(scan_id_param: str = "scan_id"):
    """Dependency factory: user must have read access to the scan.

    Allows owner, admin, and collaborators with 'read' or 'modify' permission.
    Returns the Scan object.

    Usage:
        @router.get("/{scan_id}")
        async def get_scan(scan: Scan = Depends(can_read_scan())):
            ...
    """
    return _can_access_scan(require_modify=False)


def can_modify_scan(scan_id_param: str = "scan_id"):
    """Dependency factory: user must have modify access to the scan.

    Allows owner, admin, and collaborators with 'modify' permission.
    Returns the Scan object.

    Usage:
        @router.post("/{scan_id}/deep-analysis")
        async def deep_analysis(scan: Scan = Depends(can_modify_scan())):
            ...
    """
    return _can_access_scan(require_modify=True)
