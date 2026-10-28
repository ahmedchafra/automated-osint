"""Thin orchestrator that dispatches to per-vector strategies.

The heavy lifting lives in `app.services.vectors.*` (one module per
reconnaissance vector). This file is just a coordinator: it loads the
scan, runs the requested strategies in order, runs the correlation
engine, and marks the scan COMPLETED or FAILED.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.services.correlation import CorrelationEngine
from app.services.progress import ScanProgressPublisher
from app.services.vectors import STRATEGIES
from app.services.vectors.context import VectorContext

logger = logging.getLogger("osint.scan_service")


class ScanOrchestrator:
    def __init__(
        self,
        db: AsyncSession,
        scan_id: str,
        progress_publisher: ScanProgressPublisher | None = None,
    ):
        self.db = db
        self.scan_id = scan_id
        self.publisher = progress_publisher or ScanProgressPublisher()

    async def run(self) -> dict[str, str | int]:
        scan = await self.db.get(Scan, self.scan_id)
        if not scan:
            return {"scan_id": self.scan_id, "status": "missing"}

        ctx = VectorContext(
            db=self.db,
            scan_id=self.scan_id,
            target_domain=scan.target_domain,
            target_usernames=list(scan.target_usernames or []),
            publisher=self.publisher,
            target_type=scan.target_type,
            scan_mode=scan.scan_mode,
            scope_manifest=dict(scan.scope_manifest or {}),
        )

        scan.status = "RUNNING"
        await self.db.commit()
        await ctx.load_seen_findings()

        # Tell the UI exactly how much work is queued so the live progress
        # bar can render an accurate fraction. USERNAME is dropped from
        # the displayed total when no handles were supplied so a queued
        # USERNAME vector never blocks the bar at 0%.
        requested = sorted({v.upper() for v in (scan.selected_vectors or [])})
        runnable = [v for v in requested if not (v == "USERNAME" and not ctx.target_usernames)]
        await ctx.publish(
            "scan_started",
            target_domain=scan.target_domain,
            selected_vectors=runnable,
            total_vectors=len(runnable),
        )

        try:
            completed_vectors: list[str] = []
            total = len(runnable)
            for idx, vector_name in enumerate(STRATEGIES, start=1):
                if vector_name not in requested:
                    continue
                if vector_name == "USERNAME" and not ctx.target_usernames:
                    continue
                await ctx.publish(
                    "vector_started",
                    vector_type=vector_name,
                    index=idx,
                    total=total,
                )
                try:
                    # Run each vector inside a savepoint so a failure only
                    # rolls back that vector's work, not prior vectors'.
                    async with self.db.begin_nested():
                        await STRATEGIES[vector_name](ctx)
                except Exception as vec_exc:
                    # The savepoint was rolled back on error — outer
                    # transaction and prior vectors' work is untouched.
                    logger.warning("Vector %s failed: %s", vector_name, vec_exc)
                    await ctx.publish(
                        "vector_error",
                        vector_type=vector_name,
                        error=str(vec_exc),
                    )
                    # Reload seen findings so dedup state is consistent
                    await ctx.load_seen_findings()
                    continue
                completed_vectors.append(vector_name)
                await ctx.publish(
                    "vector_completed",
                    vector_type=vector_name,
                    index=idx,
                    total=total,
                    completed_vectors=completed_vectors,
                )

            links_created = await CorrelationEngine(self.db, self.scan_id).run()
            await self.db.commit()
            await ctx.publish(
                "correlation_completed",
                links_created=links_created,
                findings_created=ctx.findings_created,
            )

            scan.status = "COMPLETED"
            scan.completed_at = datetime.now(timezone.utc)
            await self.db.commit()
            await ctx.publish(
                "scan_completed",
                status="COMPLETED",
                findings_created=ctx.findings_created,
                links_created=links_created,
            )
            return {
                "scan_id": self.scan_id,
                "status": "COMPLETED",
                "findings_created": ctx.findings_created,
                "links_created": links_created,
            }

        except Exception as exc:
            scan.status = "FAILED"
            scan.completed_at = datetime.now(timezone.utc)
            await self.db.commit()
            await ctx.publish(
                "scan_failed",
                status="FAILED",
                error=str(exc),
                findings_created=ctx.findings_created,
            )
            raise
