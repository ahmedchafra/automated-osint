"""Threat intel task for a domain.

Triggered when an analyst clicks "Run Threat Intel" on a domain in the
workspace. Runs GitHub secrets scan + dnstwist lookalike detection.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="threat_intel_scan", bind=True, max_retries=1, default_retry_delay=10)
def threat_intel_task(self, scan_id: str, domain: str):
    """Celery task: run GitHub secrets + dnstwist on a domain."""

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "threat_intel_started", {
                "domain": domain,
            })

            total = 0

            # 1. GitHub secrets scan
            await publisher.publish(scan_id, "threat_intel_progress", {
                "collector": "github_secrets",
                "status": "running",
            })
            try:
                found = await run_collector_for_scan(
                    "github_secrets", domain, scan_id, session, publisher
                )
                total += len(found)
            except Exception as e:
                await publisher.publish(scan_id, "threat_intel_error", {
                    "collector": "github_secrets",
                    "error": str(e),
                })

            await asyncio.sleep(1)

            # 2. dnstwist lookalike detection
            await publisher.publish(scan_id, "threat_intel_progress", {
                "collector": "dnstwist",
                "status": "running",
            })
            try:
                found = await run_collector_for_scan(
                    "dnstwist", domain, scan_id, session, publisher
                )
                total += len(found)
            except Exception as e:
                await publisher.publish(scan_id, "threat_intel_error", {
                    "collector": "dnstwist",
                    "error": str(e),
                })

            await session.commit()
            await publisher.publish(scan_id, "threat_intel_completed", {
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


