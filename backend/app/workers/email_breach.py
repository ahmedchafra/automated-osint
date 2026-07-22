"""Per-email breach check task.

Triggered when an analyst selects one or more emails in the workspace and
clicks "Check Breaches". Runs XposedOrNot on each selected email,
persists findings to the scan, and publishes events via Redis pubsub so
the workspace UI updates in real-time.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="email_breach_check", bind=True, max_retries=1, default_retry_delay=10)
def email_breach_task(self, scan_id: str, emails: list[str]):
    """Celery task: run XposedOrNot breach check on selected emails."""

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "breach_check_started", {
                "emails": emails,
                "count": len(emails),
            })

            total = 0
            for idx, email in enumerate(emails, 1):
                await publisher.publish(scan_id, "breach_check_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "status": "checking",
                })

                try:
                    found = await run_collector_for_scan(
                        "xposedornot_breach", email, scan_id, session, publisher
                    )
                    total += len(found)
                except Exception as e:
                    await publisher.publish(scan_id, "breach_check_error", {
                        "email": email,
                        "error": str(e),
                    })

                await publisher.publish(scan_id, "breach_check_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "status": "done",
                    "found": total,
                })

                # XposedOrNot rate limit: 2 req/sec
                await asyncio.sleep(0.6)

            await session.commit()
            await publisher.publish(scan_id, "breach_check_completed", {
                "emails": emails,
                "total_findings": total,
            })
            return {"scan_id": scan_id, "emails": emails, "total_findings": total}

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise


