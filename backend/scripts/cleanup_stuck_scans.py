#!/usr/bin/env python3
"""Clean up zombie scans stuck in RUNNING / QUEUED / PENDING status.

Scans can get stuck in a non-terminal status if a Celery worker crashes
mid-execution (especially with acks_late=False). This script finds them
and marks them as FAILED so they stop appearing as active scans.

Usage:
    python scripts/cleanup_stuck_scans.py                        # dry-run
    python scripts/cleanup_stuck_scans.py --apply                # actually update
    python scripts/cleanup_stuck_scans.py --hours 12 --apply     # older than 12h

Environment variables:
    DATABASE_URL — PostgreSQL connection string (asyncpg)
                   Default: postgresql+asyncpg://postgres:postgres@localhost:5432/osint_platform
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__))))


async def cleanup_stuck_scans(hours: int, apply: bool, status_filter: list[str]):
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy import select

    from app.database import Base
    from app.models.scan import Scan

    database_url = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://postgres:postgres@localhost:5432/osint_platform",
    )

    engine = create_async_engine(database_url, echo=False)
    Session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    async with Session() as session:
        stmt = select(Scan).where(
            Scan.status.in_(status_filter),
            Scan.created_at < cutoff,
        )
        result = await session.execute(stmt)
        stuck = result.scalars().all()

        if not stuck:
            print(f"No stuck scans older than {hours}h found. ✓")
            await engine.dispose()
            return

        print(f"Found {len(stuck)} stuck scan(s) older than {hours}h:")
        print()

        for scan in stuck:
            age_hours = (datetime.now(timezone.utc) - scan.created_at.replace(tzinfo=timezone.utc)).total_seconds() / 3600
            print(f"  [{scan.status:8}] {scan.id[:12]}...  target={scan.target_domain:20}  "
                  f"created={scan.created_at.strftime('%Y-%m-%d %H:%M')}  "
                  f"age={age_hours:.1f}h")

        print()

        if not apply:
            print("Dry-run mode. Pass --apply to actually mark these scans as FAILED.")
            await engine.dispose()
            return

        count = 0
        for scan in stuck:
            scan.status = "FAILED"
            scan.completed_at = datetime.now(timezone.utc)
            count += 1

        await session.commit()
        print(f"✅ Marked {count} scan(s) as FAILED.")

    await engine.dispose()


def main():
    parser = argparse.ArgumentParser(description="Clean up stuck (zombie) scans")
    parser.add_argument(
        "--hours", type=int, default=6,
        help="Mark scans older than N hours as FAILED (default: 6)",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Actually update the DB. Without this, runs in dry-run mode.",
    )
    parser.add_argument(
        "--status", nargs="+", default=["RUNNING", "QUEUED", "PENDING"],
        help="Statuses to consider stuck (default: RUNNING QUEUED PENDING)",
    )
    args = parser.parse_args()

    asyncio.run(cleanup_stuck_scans(args.hours, args.apply, args.status))


if __name__ == "__main__":
    main()
