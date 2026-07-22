"""Per-email deep analysis task.

Triggered when an analyst selects one or more emails and clicks
"Deep Analyze Selected". For each email, runs four collectors
sequentially (breach check → h8mail → platform discovery → profile discovery):

  1. xposedornot_breach — ALL breach records + pastes + risk score
  2. h8mail             — emailrep.io + scylla.sh breach/reputation data
  3. holehe             — ALL platforms where email is registered
  4. maigret            — ALL social media profiles (3166+ sites)

Maigret runs on the username part (before @) and can take up to 5 min.
Progress events are published per email and per collector so the frontend
can show a live progress bar.
"""
from __future__ import annotations

import asyncio

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


@celery_app.task(name="email_deep_analysis", bind=True, max_retries=1, default_retry_delay=10)
def email_deep_analysis_task(self, scan_id: str, emails: list[str]):
    """Celery task: deep analyze selected emails.

    For each email, runs: xposedornot_breach → holehe → maigret.
    All results are persisted and progress is published per email.
    """

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "email_deep_analysis_started", {
                "emails": emails,
                "count": len(emails),
            })

            total = 0

            for idx, email in enumerate(emails, 1):
                username = email.split("@")[0]

                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "xposedornot_breach",
                    "status": "running",
                })

                # 1. XposedOrNot breach check
                try:
                    found = await run_collector_for_scan(
                        "xposedornot_breach", email, scan_id, session, publisher
                    )
                    total += len(found)
                except Exception as e:
                    await publisher.publish(scan_id, "email_deep_analysis_error", {
                        "email": email, "collector": "xposedornot_breach", "error": str(e),
                    })

                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "xposedornot_breach",
                    "status": "done",
                    "findings_count": len(found),
                })

                # 2. h8mail breach/reputation check
                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "h8mail",
                    "status": "running",
                })

                try:
                    found = await run_collector_for_scan(
                        "h8mail", email, scan_id, session, publisher
                    )
                    total += len(found)
                except Exception as e:
                    await publisher.publish(scan_id, "email_deep_analysis_error", {
                        "email": email, "collector": "h8mail", "error": str(e),
                    })

                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "h8mail",
                    "status": "done",
                    "findings_count": len(found),
                })

                # 3. Holehe platform discovery
                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "holehe",
                    "status": "running",
                })

                try:
                    found = await run_collector_for_scan(
                        "holehe", email, scan_id, session, publisher
                    )
                    total += len(found)
                except Exception as e:
                    await publisher.publish(scan_id, "email_deep_analysis_error", {
                        "email": email, "collector": "holehe", "error": str(e),
                    })

                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "holehe",
                    "status": "done",
                    "findings_count": len(found),
                })

                # 4. Maigret username profile discovery
                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "maigret",
                    "status": "running",
                })

                try:
                    found = await run_collector_for_scan(
                        "maigret", username, scan_id, session, publisher
                    )
                    total += len(found)
                except Exception as e:
                    await publisher.publish(scan_id, "email_deep_analysis_error", {
                        "email": email, "collector": "maigret", "error": str(e),
                    })

                await publisher.publish(scan_id, "email_deep_analysis_progress", {
                    "email": email,
                    "index": idx,
                    "total": len(emails),
                    "collector": "maigret",
                    "status": "done",
                    "findings_count": len(found),
                })

                await session.commit()

            await publisher.publish(scan_id, "email_deep_analysis_completed", {
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


