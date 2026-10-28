from contextlib import asynccontextmanager

import redis.asyncio as redis
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from app.api.router import api_router
from app.api.ws import router as ws_router
from app.database import AsyncSessionLocal, Base, engine
from app.core.exceptions import sqlalchemy_exception_handler, generic_exception_handler
from app.config import settings
from app.core.logging_security import suppress_http_client_request_logs


suppress_http_client_request_logs()


async def _bootstrap_initial_admin() -> None:
    """Create the first admin from environment variables when requested."""
    values = (
        settings.INITIAL_ADMIN_USERNAME,
        settings.INITIAL_ADMIN_EMAIL,
        settings.INITIAL_ADMIN_PASSWORD,
    )
    if not any(values):
        return
    if not all(values):
        raise RuntimeError(
            "INITIAL_ADMIN_USERNAME, INITIAL_ADMIN_EMAIL, and "
            "INITIAL_ADMIN_PASSWORD must be provided together"
        )
    if len(settings.INITIAL_ADMIN_PASSWORD or "") < 12:
        raise RuntimeError("INITIAL_ADMIN_PASSWORD must be at least 12 characters")

    from app.core.auth import hash_password
    from app.models.user import User

    async with AsyncSessionLocal() as session:
        existing_admin = (
            await session.execute(select(User).where(User.role == "admin"))
        ).scalars().first()
        if existing_admin:
            return

        existing_user = (
            await session.execute(
                select(User).where(
                    (User.username == settings.INITIAL_ADMIN_USERNAME)
                    | (User.email == settings.INITIAL_ADMIN_EMAIL)
                )
            )
        ).scalar_one_or_none()
        if existing_user:
            existing_user.role = "admin"
            existing_user.is_active = True
            existing_user.hashed_password = hash_password(
                settings.INITIAL_ADMIN_PASSWORD or ""
            )
        else:
            session.add(
                User(
                    username=settings.INITIAL_ADMIN_USERNAME,
                    email=settings.INITIAL_ADMIN_EMAIL,
                    hashed_password=hash_password(
                        settings.INITIAL_ADMIN_PASSWORD or ""
                    ),
                    role="admin",
                    is_active=True,
                )
            )
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.AUTO_CREATE_DB:
        import app.models  # noqa: F401

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    await _bootstrap_initial_admin()
    yield


app = FastAPI(title="OSINT Platform API", lifespan=lifespan)

# Exception handlers
app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# Include routers
app.include_router(api_router, prefix="/api")
app.include_router(ws_router)

# Configure CORS for local frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    database_status = "ok"
    redis_status = "ok"

    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        database_status = "error"

    client = None
    try:
        client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        await client.ping()
    except Exception:
        redis_status = "error"
    finally:
        if client is not None:
            try:
                await client.aclose()
            except Exception:
                pass

    return {
        "status": "ok" if database_status == "ok" and redis_status == "ok" else "degraded",
        "database": database_status,
        "redis": redis_status,
        "message": "OSINT Platform API is running",
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
