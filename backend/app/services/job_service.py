from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import database
from app.models.scan import Scan
from app.models.scan_job import ScanJob


logger = logging.getLogger("osint.jobs")

ACTIVE_JOB_STATUSES = ("QUEUED", "RUNNING", "RETRYING")
TERMINAL_JOB_STATUSES = ("COMPLETED", "FAILED", "CANCELLED")


def _serialize_input(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value[:4096]
    return json.dumps(value, default=str, ensure_ascii=False)[:4096]


def _result_summary(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    candidate = value if isinstance(value, dict) else {"result": value}
    try:
        encoded = json.dumps(candidate, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return {"result": str(value)[:2000]}
    if len(encoded) > 16000:
        return {"summary": encoded[:16000], "truncated": True}
    return json.loads(encoded)


async def dispatch_scan_job(
    db: AsyncSession,
    task: Any,
    scan_id: str,
    *,
    job_type: str,
    stage: str,
    input_type: str | None = None,
    input_value: Any = None,
    task_args: Sequence[Any] = (),
    task_kwargs: dict[str, Any] | None = None,
    parent_job_id: str | None = None,
) -> ScanJob:
    """Persist a QUEUED job before placing its task on the broker."""
    celery_task_id = str(uuid.uuid4())
    job = ScanJob(
        scan_id=scan_id,
        parent_job_id=parent_job_id,
        celery_task_id=celery_task_id,
        job_type=job_type,
        stage=stage,
        status="QUEUED",
        input_type=input_type,
        input_value=_serialize_input(input_value),
        progress={},
        result_summary={},
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    try:
        task.apply_async(
            args=(scan_id, *tuple(task_args)),
            kwargs=task_kwargs or {},
            task_id=celery_task_id,
        )
    except Exception as exc:
        job.status = "FAILED"
        job.error = f"Broker dispatch failed: {exc}"[:8000]
        job.completed_at = datetime.now(timezone.utc)
        await db.commit()
        logger.exception("failed to dispatch %s for scan %s", job_type, scan_id)
        raise

    return job


async def update_job_status(
    celery_task_id: str,
    status: str,
    *,
    scan_id: str | None = None,
    job_type: str | None = None,
    error: str | None = None,
    result: Any = None,
) -> None:
    """Update a job from Celery lifecycle hooks.

    A fallback row is created for tasks dispatched by older code paths so the
    ledger remains complete during migration.
    """
    now = datetime.now(timezone.utc)
    async with database.AsyncSessionLocal() as db:
        job = (
            await db.execute(
                select(ScanJob).where(ScanJob.celery_task_id == celery_task_id)
            )
        ).scalar_one_or_none()

        if job is None:
            if not scan_id:
                logger.warning(
                    "cannot track Celery task %s without a scan id", celery_task_id
                )
                return
            scan = await db.get(Scan, scan_id)
            if scan is None:
                logger.warning(
                    "cannot track Celery task %s: scan %s is missing",
                    celery_task_id,
                    scan_id,
                )
                return
            job = ScanJob(
                scan_id=scan_id,
                celery_task_id=celery_task_id,
                job_type=job_type or "unknown",
                stage="legacy",
                status="QUEUED",
                progress={},
                result_summary={},
            )
            db.add(job)

        if job.status == "CANCELLED" and status != "CANCELLED":
            return

        job.status = status
        if status == "RUNNING" and job.started_at is None:
            job.started_at = now
        if status in TERMINAL_JOB_STATUSES:
            job.completed_at = now
        if error:
            job.error = error[:8000]
        elif status == "COMPLETED":
            job.error = None
        if result is not None:
            job.result_summary = _result_summary(result)

        scan = await db.get(Scan, job.scan_id)
        if scan is not None:
            scan.updated_at = now
        await db.commit()


async def update_job_progress(
    celery_task_id: str,
    event: str,
    payload: dict[str, Any],
) -> None:
    """Persist the latest pipeline event for refresh/reconnect recovery."""
    async with database.AsyncSessionLocal() as db:
        job = (
            await db.execute(
                select(ScanJob).where(ScanJob.celery_task_id == celery_task_id)
            )
        ).scalar_one_or_none()
        if job is None or job.status in TERMINAL_JOB_STATUSES:
            return

        safe_payload = _result_summary(payload)
        job.progress = {
            "event": event,
            "payload": safe_payload,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        await db.commit()
