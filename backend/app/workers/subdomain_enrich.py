"""Per subdomain enrichment task.

Triggered when an analyst selects subdomains in the workspace and clicks
"Enrich Selected". Runs Hunter + XposedOrNot on each selected subdomain,
persists findings to the scan, and publishes events via Redis pubsub so the
workspace UI updates in real-time.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="subdomain_enrich", bind=True, max_retries=1, default_retry_delay=10)
def subdomain_enrich_task(self, scan_id: str, subdomains: list[str]):
    """Celery task: run Hunter + XposedOrNot on selected subdomains."""

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "enrich_started", {
                "subdomains": subdomains,
                "count": len(subdomains),
            })

            total = 0
            for subdomain in subdomains:
                await publisher.publish(scan_id, "enrich_subdomain", {
                    "subdomain": subdomain,
                    "status": "running",
                })

                for collector_name in ("hunter_domain", "xposedornot_breach"):
                    try:
                        found = await run_collector_for_scan(
                            collector_name, subdomain, scan_id, session, publisher
                        )
                        total += len(found)
                    except Exception as e:
                        await publisher.publish(scan_id, "enrich_error", {
                            "subdomain": subdomain,
                            "collector": collector_name,
                            "error": str(e),
                        })

                await publisher.publish(scan_id, "enrich_subdomain", {
                    "subdomain": subdomain,
                    "status": "completed",
                })

            await session.commit()
            await publisher.publish(scan_id, "enrich_completed", {
                "subdomains": subdomains,
                "total_findings": total,
            })
            return {"scan_id": scan_id, "subdomains": subdomains, "total_findings": total}

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise


