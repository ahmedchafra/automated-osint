from celery import Celery
from app.config import settings

celery_app = Celery(
    "osint_worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    # ── Zombie protection ────────────────────────────────────────────
    # acks_late: task is re-queued if the worker crashes mid-execution
    # reject_on_worker_lost: reject (and re-queue) tasks from lost workers
    # task_soft_time_limit: raises SoftTimeLimitExceeded after N seconds
    # task_time_limit: hard SIGKILL after N seconds if soft limit ignored
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_soft_time_limit=1800,   # 30 minutes
    task_time_limit=2100,        # 35 minutes (grace period after soft limit)
)

# Eagerly import scan_tasks at startup so the @celery_app.task decorator runs
# before any task is dispatched (defensive in case `include` is overridden).
import app.workers.scan_tasks  # noqa: F401, E402
import app.workers.pivot_tasks  # noqa: F401, E402
import app.workers.subdomain_enrich  # noqa: F401, E402
import app.workers.email_breach  # noqa: F401, E402
import app.workers.deep_pivot  # noqa: F401, E402
import app.workers.domain_deep_analysis  # noqa: F401, E402
import app.workers.threat_intel  # noqa: F401, E402
import app.workers.unified_scan  # noqa: F401, E402
import app.workers.initial_scan  # noqa: F401, E402
import app.workers.ip_scan  # noqa: F401, E402
import app.workers.org_scan  # noqa: F401, E402
import app.workers.shodan_enrich  # noqa: F401, E402
import app.workers.censys_enrich  # noqa: F401, E402
import app.workers.ai_tasks  # noqa: F401, E402
import app.workers.dnstwist_task  # noqa: F401, E402
import app.workers.telegram_task  # noqa: F401, E402
import app.workers.ahmia_task  # noqa: F401, E402

# Pre-import the collectors registry in the worker parent process so the
# forked children inherit it on sys.path. Without this, `from collectors...`
# inside scan_service.py can fail in Celery prefork workers because the
# collectors package lives at the project root (not inside app/).
import collectors.registry  # noqa: F401, E402

# Auto-discover any future tasks in the workers package
celery_app.autodiscover_tasks(["app.workers"])
