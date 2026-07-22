"""Standalone Telegram monitor task.

Triggered when an analyst clicks "Monitor Telegram" in the Threat Intel tab.
Runs ONLY the telegram_monitor collector with a keyword. Results appear in
Threat Intel tab as TELEGRAM_MESSAGE and TELEGRAM_CHANNEL findings.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="telegram_monitor", bind=True, max_retries=1, default_retry_delay=10)
def telegram_monitor_task(self, scan_id: str, keyword: str):
    """Celery task: run telegram_monitor collector with a keyword."""

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "telegram_monitor_started", {
                "keyword": keyword,
            })

            total = 0
            try:
                found = await run_collector_for_scan(
                    "telegram_monitor", keyword, scan_id, session, publisher
                )
                total = len(found)
            except Exception as e:
                await publisher.publish(scan_id, "telegram_monitor_error", {
                    "keyword": keyword,
                    "error": str(e),
                })

            await session.commit()
            await publisher.publish(scan_id, "telegram_monitor_completed", {
                "keyword": keyword,
                "total_findings": total,
            })
            return {"scan_id": scan_id, "keyword": keyword, "total_findings": total}

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise


