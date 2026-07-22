"""Per-email pivot sweep task.

Triggered when an analyst clicks "Pivot Sweep" on an email in the workspace.
Runs holehe, maigret, and hibp_breach on the selected email, persists
findings to the scan, and publishes events via Redis pubsub so the
workspace UI updates in real-time.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="pivot_sweep", bind=True, max_retries=1, default_retry_delay=10)
def pivot_sweep_task(self, scan_id: str, email: str):
    """Celery task: run holehe + maigret + hibp_breach on a single email."""

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "pivot_started", {"email": email})

            total = 0
            for collector_name in ("holehe", "maigret"):
                try:
                    found = await run_collector_for_scan(
                        collector_name, email, scan_id, session, publisher
                    )
                    total += len(found)
                except Exception as e:
                    await publisher.publish(scan_id, "pivot_error", {
                        "email": email,
                        "collector": collector_name,
                        "error": str(e),
                    })

            await session.commit()
            await publisher.publish(scan_id, "pivot_completed", {
                "email": email,
                "total_findings": total,
            })
            return {"scan_id": scan_id, "email": email, "total_findings": total}

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise


