"""Per-IP Shodan Host enrichment task.

Triggered when an analyst clicks "Enrich with Shodan" on a specific IP
in the Infrastructure tab. Runs the paid Shodan Host API to get detailed
port/service/vulnerability data for a single IP.

Shodan Host API is rate-limited (~1 request per second on paid plans),
so this task enriches one IP at a time with a small delay.
"""
from __future__ import annotations

import asyncio
import logging

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run

logger = logging.getLogger("osint.shodan_enrich")


async def _run_pipeline(scan_id: str, ip: str) -> dict:
    """Run Shodan Host API enrichment on a single IP."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return {"scan_id": scan_id, "status": "missing"}

        publisher = ScanProgressPublisher()
        await publisher.publish(scan_id, "shodan_enrich_started", {
            "ip": ip,
        })

        total = 0
        try:
            found = await run_collector_for_scan(
                "shodan_host", ip, scan_id, session, publisher
            )
            total = len(found)
        except Exception as e:
            logger.exception("Shodan enrich failed for %s: %s", ip, e)
            await publisher.publish(scan_id, "shodan_enrich_error", {
                "ip": ip,
                "error": str(e),
            })

        await session.commit()
        await publisher.publish(scan_id, "shodan_enrich_completed", {
            "ip": ip,
            "total_findings": total,
        })

        return {"scan_id": scan_id, "ip": ip, "total_findings": total}


@celery_app.task(name="shodan_enrich", bind=True, max_retries=1, default_retry_delay=5)
def shodan_enrich_task(self, scan_id: str, ip: str):
    """Celery task: run Shodan Host API on one IP."""
    try:
        return _run(_run_pipeline(scan_id, ip))
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
