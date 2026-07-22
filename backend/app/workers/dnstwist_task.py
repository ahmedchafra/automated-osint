"""Standalone dnstwist lookalike detection task.

Triggered when an analyst clicks "Run dnstwist" in the Threat Intel or
Brand Protection tab. Runs ONLY the dnstwist collector (no github_secrets,
no hunter). Results appear in Brand Protection tab as LOOKALIKE_DOMAIN findings.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="dnstwist_only", bind=True, max_retries=1, default_retry_delay=10)
def dnstwist_only_task(self, scan_id: str, domain: str):
    """Celery task: run dnstwist lookalike detection on a domain."""

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "dnstwist_started", {
                "domain": domain,
            })

            total = 0
            try:
                found = await run_collector_for_scan(
                    "dnstwist", domain, scan_id, session, publisher
                )
                total = len(found)
            except Exception as e:
                await publisher.publish(scan_id, "dnstwist_error", {
                    "domain": domain,
                    "error": str(e),
                })

            await session.commit()
            await publisher.publish(scan_id, "dnstwist_completed", {
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


