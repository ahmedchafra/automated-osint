"""Dashboard statistics endpoint.

Returns aggregate stats scoped to the current user's accessible scans
(owned + collaborated). Admin users see global system-wide stats.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.database import get_db
from app.models.scan import Scan
from app.models.finding import Finding
from app.models.scan_collaborator import ScanCollaborator
from app.core.auth import get_authenticated_user
from app.models.user import User

router = APIRouter(dependencies=[Depends(get_authenticated_user)])


async def _accessible_scan_ids(
    db: AsyncSession, user: User | None
) -> tuple[list[str], bool]:
    """Return (scan_ids, is_admin).

    Admin users get no restriction (empty list = scan all). Non-admin users
    get the list of scan IDs they own or are a collaborator on.
    """
    if not user or user.role == "admin":
        return [], True

    # Owned scans
    owned = (await db.execute(
        select(Scan.id).where(Scan.owner_id == user.id)
    )).scalars().all()

    # Collaborated scans
    collab = (await db.execute(
        select(ScanCollaborator.scan_id).where(
            ScanCollaborator.user_id == user.id
        )
    )).scalars().all()

    return list(set(owned) | set(collab)), False


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Return aggregate statistics for the dashboard.

    Admin users see global stats across all scans.
    Non-admin users only see stats for scans they own or collaborate on.
    """
    scan_ids, is_admin = await _accessible_scan_ids(db, current_user)
    scan_filter = Scan.id.in_(scan_ids) if scan_ids else None
    # Admin with no filter: True == no-op
    no_filter = True if is_admin else (scan_filter is not None)

    # ── Scans ──────────────────────────────────────────────────────────
    total_scans_stmt = select(func.count(Scan.id))
    if not is_admin and scan_filter is not None:
        total_scans_stmt = total_scans_stmt.where(
            or_(Scan.owner_id == current_user.id, scan_filter)
        )
    total_scans = (await db.execute(total_scans_stmt)).scalar_one()

    # Scans by type
    type_stmt = select(Scan.target_type, func.count(Scan.id))
    if not is_admin and scan_filter is not None:
        type_stmt = type_stmt.where(
            or_(Scan.owner_id == current_user.id, scan_filter)
        )
    type_stmt = type_stmt.group_by(Scan.target_type)
    type_result = await db.execute(type_stmt)
    scans_by_type = {row[0]: row[1] for row in type_result.all()}

    # Scans by status
    status_stmt = select(Scan.status, func.count(Scan.id))
    if not is_admin and scan_filter is not None:
        status_stmt = status_stmt.where(
            or_(Scan.owner_id == current_user.id, scan_filter)
        )
    status_stmt = status_stmt.group_by(Scan.status)
    status_result = await db.execute(status_stmt)
    scans_by_status = {row[0]: row[1] for row in status_result.all()}

    # ── Findings (scoped to user's accessible scans) ───────────────────
    f_total = select(func.count(Finding.id))
    f_severity = select(Finding.severity, func.count(Finding.id))
    f_vector = select(Finding.vector_type, func.count(Finding.id))
    f_entity = select(Finding.entity_type, func.count(Finding.id))

    if not is_admin:
        if scan_ids:
            f_total = f_total.where(Finding.scan_id.in_(scan_ids))
            f_severity = f_severity.where(Finding.scan_id.in_(scan_ids))
            f_vector = f_vector.where(Finding.scan_id.in_(scan_ids))
            f_entity = f_entity.where(Finding.scan_id.in_(scan_ids))
        else:
            # User has no accessible scans — return empty
            return {
                "total_scans": total_scans,
                "total_findings": 0,
                "scans_by_type": scans_by_type,
                "scans_by_status": scans_by_status,
                "findings_by_severity": {},
                "findings_by_vector": {},
                "findings_by_entity": {},
                "recent_scans": [],
            }

    total_findings = (await db.execute(f_total)).scalar_one()

    severity_result = await db.execute(f_severity.group_by(Finding.severity))
    severity_counts = {row[0]: row[1] for row in severity_result.all()}

    vector_result = await db.execute(f_vector.group_by(Finding.vector_type))
    vector_counts = {row[0]: row[1] for row in vector_result.all()}

    entity_result = await db.execute(f_entity.group_by(Finding.entity_type))
    entity_counts = {row[0]: row[1] for row in entity_result.all()}

    # ── Recent scans (scoped) ──────────────────────────────────────────
    recent_stmt = (
        select(
            Scan.id,
            Scan.target_domain,
            Scan.target_type,
            Scan.status,
            Scan.created_at,
            func.count(Finding.id).label("findings_count"),
        )
        .outerjoin(Finding, Finding.scan_id == Scan.id)
    )
    if not is_admin and scan_filter is not None:
        recent_stmt = recent_stmt.where(
            or_(Scan.owner_id == current_user.id, scan_filter)
        )
    recent_stmt = (
        recent_stmt
        .group_by(Scan.id)
        .order_by(Scan.created_at.desc())
        .limit(5)
    )
    recent_scans = (await db.execute(recent_stmt)).all()
    recent_scans_list = [
        {
            "id": row.id,
            "target_domain": row.target_domain,
            "target_type": row.target_type or "domain",
            "status": row.status,
            "findings_count": row.findings_count,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in recent_scans
    ]

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "scans_by_type": scans_by_type,
        "scans_by_status": scans_by_status,
        "findings_by_severity": severity_counts,
        "findings_by_vector": vector_counts,
        "findings_by_entity": entity_counts,
        "recent_scans": recent_scans_list,
    }


@router.get("/queue")
async def get_celery_queue_info():
    """Return Celery worker queue status — active/reserved tasks, worker count.

    Uses Celery inspect API to query worker state. Returns null for each
    field when no workers are reachable (e.g. all workers down during
    development).
    """
    from app.workers.celery_app import celery_app

    try:
        inspect = celery_app.control.inspect()

        # Active tasks
        active_raw = inspect.active() or {}
        active_tasks = []
        for worker, tasks in active_raw.items():
            for t in tasks:
                active_tasks.append({
                    "task_id": t.get("id"),
                    "name": t.get("name", "unknown"),
                    "args": t.get("args", []),
                    "worker": worker,
                    "started": t.get("time_start", 0),
                })

        # Reserved (queued but not yet running)
        reserved_raw = inspect.reserved() or {}
        reserved_count = sum(len(tasks) for tasks in reserved_raw.values())

        # Registered workers
        stats_raw = inspect.stats() or {}
        worker_count = len(stats_raw)
        active_worker_count = sum(
            1 for s in stats_raw.values()
            if s and s.get("total", {}).get("task-received", 0) > 0
        )

        return {
            "worker_count": worker_count,
            "active_worker_count": active_worker_count,
            "active_tasks": active_tasks,
            "active_task_count": len(active_tasks),
            "reserved_task_count": reserved_count,
        }
    except Exception as e:
        return {
            "worker_count": 0,
            "active_worker_count": 0,
            "active_tasks": [],
            "active_task_count": 0,
            "reserved_task_count": 0,
            "error": str(e),
        }
