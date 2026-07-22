"""Per-IP Censys Host enrichment task.

Triggered when an analyst clicks "Enrich with Censys" on a specific IP
in the Infrastructure tab. Runs the Censys Host API to get detailed
port/service/vulnerability data for a single IP.

Censys free tier allows ~50 queries/hour with a rate limit window
of ~20 minutes. This task enriches one IP at a time with a small delay.
Query credits should be monitored as they are used: the Censys platform
pads 80-100 credits on the free plan (~12.5 searches).
"""
from __future__ import annotations

import asyncio
import logging

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run

logger = logging.getLogger("osint.censys_enrich")


async def _run_pipeline(scan_id: str, ip: str) -> dict:
    """Run Censys Host API enrichment on a single IP."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return {"scan_id": scan_id, "status": "missing"}

        publisher = ScanProgressPublisher()
        await publisher.publish(scan_id, "censys_enrich_started", {
            "ip": ip,
        })

        total = 0
        try:
            found = await run_collector_for_scan(
                "censys_host", ip, scan_id, session, publisher
            )
            total = len(found)
        except Exception as e:
            logger.exception("Censys enrich failed for %s: %s", ip, e)
            await publisher.publish(scan_id, "censys_enrich_error", {
                "ip": ip,
                "error": str(e),
            })

        await session.commit()
        await publisher.publish(scan_id, "censys_enrich_completed", {
            "ip": ip,
            "total_findings": total,
        })

        return {"scan_id": scan_id, "ip": ip, "total_findings": total}


@celery_app.task(name="censys_enrich", bind=True, max_retries=1, default_retry_delay=10)
def censys_enrich_task(self, scan_id: str, ip: str):
    """Celery task: run Censys Host API on one IP."""
    try:
        return _run(_run_pipeline(scan_id, ip))
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
