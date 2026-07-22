#!/usr/bin/env python3
"""Seed the first admin user directly via the database.

Usage:
    python scripts/seed_admin.py --username admin --email admin@example.com --password s3cur3

Creates a user with role="admin" if one doesn't already exist.
Runs offline (no server needed) — connects directly to the database
using the DATABASE_URL from the environment or the default local dev URL.

Environment variables:
    DATABASE_URL — PostgreSQL connection string (asyncpg)
                   Default: postgresql+asyncpg://postgres:postgres@localhost:5432/osint_platform
"""

import argparse
import asyncio
import os
import sys

# Ensure the backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__))))


async def seed_admin(username: str, email: str, password: str, database_url: str):
    """Create an admin user if one doesn't exist."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy import select

    from app.database import Base
    from app.models.user import User
    from app.core.auth import hash_password

    engine = create_async_engine(database_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    Session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with Session() as session:
        # Check existing admin
        result = await session.execute(
            select(User).where((User.username == username) | (User.role == "admin"))
        )
        existing = result.scalar_one_or_none()
        if existing:
            print(f"User already exists: {existing.username} (role={existing.role})")
            if existing.role == "admin" and existing.username == username:
                print("Admin user already seeded. Nothing to do.")
            else:
                print(f"Promoting {existing.username} to admin...")
                existing.role = "admin"
                await session.commit()
                print("Done.")
            await engine.dispose()
            return

        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            role="admin",
            is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

    await engine.dispose()
    print(f"✅ Admin user created: {user.username} (id={user.id}, role={user.role})")


def main():
    parser = argparse.ArgumentParser(description="Seed the first admin user")
    parser.add_argument("--username", default="admin", help="Admin username")
    parser.add_argument("--email", default="admin@example.com", help="Admin email")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument(
        "--database-url",
        default=None,
        help="PostgreSQL DSN (default: DATABASE_URL env or dev default)",
    )
    args = parser.parse_args()

    database_url = args.database_url or os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/osint_platform",
    )

    asyncio.run(seed_admin(args.username, args.email, args.password, database_url))


if __name__ == "__main__":
    main()
