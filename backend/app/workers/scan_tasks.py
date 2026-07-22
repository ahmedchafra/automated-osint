from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.workers.task_utils import _run


@celery_app.task(name="execute_scan", bind=True, max_retries=2, default_retry_delay=5)
def execute_scan_task(self, scan_id: str):
    """Celery task to run a scan asynchronously."""

    async def run_orchestrator():
        from app.services.scan_service import ScanOrchestrator
        async with AsyncSessionLocal() as session:
            orchestrator = ScanOrchestrator(session, scan_id)
            return await orchestrator.run()

    try:
        return _run(run_orchestrator())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
