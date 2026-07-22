"""Ahmia dark web search task.

Triggered when the analyst clicks "Search Dark Web" in the Threat Intel tab.
Queries Ahmia.fi for .onion sites mentioning the target domain and
persists findings to the scan.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="ahmia_search", bind=True, max_retries=1, default_retry_delay=10)
def ahmia_search_task(self, scan_id: str, domain: str):
    """Celery task: search Ahmia.fi for .onion mentions of a domain."""

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "ahmia_search_started", {
                "domain": domain,
            })

            try:
                found = await run_collector_for_scan(
                    "ahmia", domain, scan_id, session, publisher
                )
                total = len(found)
            except Exception as e:
                await publisher.publish(scan_id, "ahmia_search_error", {
                    "domain": domain,
                    "error": str(e),
                })
                total = 0

            await session.commit()
            await publisher.publish(scan_id, "ahmia_search_completed", {
                "domain": domain,
                "total_findings": total,
            })
            return {"scan_id": scan_id, "domain": domain, "total_findings": total}

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise


