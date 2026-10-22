import logging

from celery import Task


logger = logging.getLogger("osint.jobs")


def _scan_id(args) -> str | None:
    if not args:
        return None
    value = args[0]
    return str(value) if value is not None else None


def _update(task_id: str, status: str, **kwargs) -> None:
    """Run lifecycle persistence without allowing it to break collector work."""
    try:
        from app.services.job_service import update_job_status
        from app.workers.task_utils import run_task

        run_task(update_job_status, task_id, status, **kwargs)
    except Exception:
        logger.exception("failed to persist job lifecycle for task %s", task_id)


class TrackedTask(Task):
    """Celery task base that mirrors task lifecycle into ``scan_jobs``."""

    abstract = True

    def before_start(self, task_id, args, kwargs):
        _update(
            task_id,
            "RUNNING",
            scan_id=_scan_id(args),
            job_type=self.name,
        )
        return super().before_start(task_id, args, kwargs)

    def on_success(self, retval, task_id, args, kwargs):
        _update(
            task_id,
            "COMPLETED",
            scan_id=_scan_id(args),
            job_type=self.name,
            result=retval,
        )
        return super().on_success(retval, task_id, args, kwargs)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        _update(
            task_id,
            "RETRYING",
            scan_id=_scan_id(args),
            job_type=self.name,
            error=str(exc),
        )
        return super().on_retry(exc, task_id, args, kwargs, einfo)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        _update(
            task_id,
            "FAILED",
            scan_id=_scan_id(args),
            job_type=self.name,
            error=str(exc),
        )
        return super().on_failure(exc, task_id, args, kwargs, einfo)
