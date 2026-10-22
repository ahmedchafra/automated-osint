import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from sqlalchemy.orm import selectinload
from typing import List, Optional

import redis.asyncio as aioredis

from app.models.user import User
from app.models.finding import Finding
from app.models.scan_collaborator import ScanCollaborator
from app.config import settings
from app.database import get_db
from app.schemas.base import AIDorkRequest, CensysEnrichRequest, DomainDeepAnalysisRequest, DnstwistRequest, EmailBreachRequest, EmailDeepAnalysisRequest, PivotRequest, ScanCreate, ScanCreateSimple, ScanCreateV2, ScanCreateResponse, ScanDetailResponse, ScanJobResponse, ScanResponse, SetPrimaryDomainRequest, ShodanEnrichRequest, SubdomainEnrichRequest, TelegramMonitorRequest, ThreatIntelRequest
from app.models.scan import Scan
from app.models.scan_job import ScanJob
from app.core.auth import get_authenticated_user, can_read_scan, can_modify_scan
from app.schemas.auth import AddScanCollaboratorRequest, ScanCollaboratorResponse, ScanPermissionResponse
from app.workers.scan_tasks import execute_scan_task
# from app.workers.unified_scan import execute_unified_scan_task  # disabled — no frontend calls POST /simple
from app.workers.initial_scan import execute_initial_scan_task
from app.workers.shodan_enrich import shodan_enrich_task
from app.workers.censys_enrich import censys_enrich_task
from app.workers.ai_tasks import run_ai_dork_task
from app.workers.pivot_tasks import pivot_sweep_task
from app.workers.subdomain_enrich import subdomain_enrich_task
from app.workers.email_breach import email_breach_task
from app.workers.deep_pivot import email_deep_analysis_task
from app.workers.domain_deep_analysis import domain_deep_analysis_task, github_secrets_scan_task
from app.workers.threat_intel import threat_intel_task
from app.workers.dnstwist_task import dnstwist_only_task
from app.workers.telegram_task import telegram_monitor_task
from app.workers.ahmia_task import ahmia_search_task
from app.workers.ip_scan import execute_ip_scan_task
from app.workers.org_scan import execute_org_scan_task, execute_org_infra_task
from app.services.job_service import dispatch_scan_job

logger = logging.getLogger("osint.api.scans")

# ── Redis-backed running-task lock ─────────────────────────────────────
# Prevents duplicate deep analysis dispatches for the same scan+domain
# by atomically checking a TTL-bearing key in Redis (SET NX).


async def _check_and_set_running_lock(
    lock_key: str, ttl_seconds: int = 3600
) -> bool:
    """Atomically check and set a Redis lock key.

    Returns True if the lock was acquired (no duplicate), False if already locked.
    Uses Redis ``SET NX`` to ensure atomicity across concurrent requests.
    """
    try:
        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            acquired = await client.set(lock_key, "1", nx=True, ex=ttl_seconds)
            return acquired is True  # None when key already exists
        finally:
            await client.aclose()
    except Exception:
        logger.exception("failed to check running lock %s", lock_key)
        # On Redis failure, allow the request through rather than blocking work
        return True


async def _clear_running_lock(lock_key: str) -> None:
    try:
        client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            await client.delete(lock_key)
        finally:
            await client.aclose()
    except Exception:
        logger.exception("failed to clear running lock %s", lock_key)


router = APIRouter(dependencies=[Depends(get_authenticated_user)])

@router.post("/", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    scan_in: ScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    db_scan = Scan(
        target_domain=scan_in.target_domain,
        scan_mode=scan_in.scan_mode.value,
        selected_vectors=scan_in.selected_vectors,
        target_usernames=scan_in.target_usernames,
        status="QUEUED",
        owner_id=current_user.id,
    )
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)
    
    job = await dispatch_scan_job(
        db,
        execute_scan_task,
        db_scan.id,
        job_type="execute_scan",
        stage="full_scan",
        input_type="domain",
        input_value=db_scan.target_domain,
    )
    db_scan.celery_task_id = job.celery_task_id
    await db.commit()
    await db.refresh(db_scan)

    return {
        "task_id": job.celery_task_id,
        "scan": db_scan,
    }

# ── DISABLED: POST /simple ──────────────────────────────────────────────
# No frontend code calls this endpoint. The unified scan task that ran all 5
# phases automatically was replaced by the phased approach:
#   POST /initial  → Phase 1 only (free APIs, infra discovery)
#   POST /org      → Phase 1 only (org name → domain discovery via Serper + Whoxy)
#   POST /ip       → IP-focused scan (reverse DNS → services → search)
#   On-demand enrichment buttons in the workspace for the remaining phases.
#
# @router.post("/simple", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
# async def create_simple_scan(
#     scan_in: ScanCreateSimple,
#     db: AsyncSession = Depends(get_db),
#     current_user: User = Depends(get_authenticated_user),
# ):
#     db_scan = Scan(
#         target_domain=scan_in.target_domain,
#         selected_vectors=["INFRASTRUCTURE", "SERVICES", "IDENTITY", "SEARCH", "USERNAME"],
#         target_usernames=[],
#         status="QUEUED",
#         owner_id=current_user.id,
#     )
#     db.add(db_scan)
#     await db.commit()
#     await db.refresh(db_scan)
#     async_result = execute_unified_scan_task.delay(db_scan.id)
#     return {"task_id": async_result.id, "scan": db_scan}


@router.post("/initial", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_initial_scan(
    scan_in: ScanCreateSimple,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Create a Phase 1 scan (crt.sh + subfinder + DNS + Shodan InternetDB).

    Runs only free APIs so the scan completes quickly without rate limits.
    After completion, the analyst can trigger additional enrichment
    on-demand from the workspace (Shodan Host, Hunter, XposedOrNot, etc.).
    """
    db_scan = Scan(
        target_domain=scan_in.target_domain,
        scan_mode=scan_in.scan_mode.value,
        selected_vectors=["INFRASTRUCTURE"],
        target_usernames=[],
        status="QUEUED",
        owner_id=current_user.id,
    )
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)

    job = await dispatch_scan_job(
        db,
        execute_initial_scan_task,
        db_scan.id,
        job_type="execute_initial_scan",
        stage="discovery",
        input_type="domain",
        input_value=db_scan.target_domain,
    )
    db_scan.celery_task_id = job.celery_task_id
    await db.commit()
    await db.refresh(db_scan)

    return {
        "task_id": job.celery_task_id,
        "scan": db_scan,
    }


@router.post("/ip", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_ip_scan(
    scan_in: ScanCreateV2,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Create an IP address scan.

    Runs reverse DNS, Shodan InternetDB, Shodan Host, Censys, ASN lookup,
    NVD CVE, and Serper search on the target IP. If reverse DNS discovers
    a domain, the pipeline converges into the domain discovery flow.

    The ``target_type`` is automatically set to ``"ip"`` regardless of
    what the caller sends.
    """
    import ipaddress
    try:
        ipaddress.ip_address(scan_in.target_value)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="target_value must be a valid IPv4 or IPv6 address",
        )

    db_scan = Scan(
        target_domain=scan_in.target_value,
        target_type="ip",
        scan_mode=scan_in.scan_mode.value,
        selected_vectors=scan_in.selected_vectors or ["INFRASTRUCTURE"],
        target_usernames=scan_in.target_usernames or [],
        status="QUEUED",
        owner_id=current_user.id,
    )
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)

    job = await dispatch_scan_job(
        db,
        execute_ip_scan_task,
        db_scan.id,
        job_type="execute_ip_scan",
        stage="discovery",
        input_type="ip",
        input_value=db_scan.target_domain,
    )
    db_scan.celery_task_id = job.celery_task_id
    await db.commit()
    await db.refresh(db_scan)

    return {
        "task_id": job.celery_task_id,
        "scan": db_scan,
    }


@router.post("/organization", response_model=ScanCreateResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_org_scan(
    scan_in: ScanCreateV2,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Create an organization name scan.

    Searches for domains associated with the organization name, then runs
    the full reconnaissance pipeline on the primary discovered domain:
    infrastructure discovery → services → identity → search.

    The ``target_type`` is automatically set to ``"organization"``
    regardless of what the caller sends.
    """
    db_scan = Scan(
        target_domain=scan_in.target_value,
        target_type="organization",
        scan_mode=scan_in.scan_mode.value,
        selected_vectors=scan_in.selected_vectors or ["INFRASTRUCTURE"],
        target_usernames=scan_in.target_usernames or [],
        status="QUEUED",
        owner_id=current_user.id,
    )
    db.add(db_scan)
    await db.commit()
    await db.refresh(db_scan)

    job = await dispatch_scan_job(
        db,
        execute_org_scan_task,
        db_scan.id,
        job_type="execute_org_scan",
        stage="organization_discovery",
        input_type="organization",
        input_value=db_scan.target_domain,
    )
    db_scan.celery_task_id = job.celery_task_id
    await db.commit()
    await db.refresh(db_scan)

    return {
        "task_id": job.celery_task_id,
        "scan": db_scan,
    }


@router.post("/{scan_id}/run-infra", status_code=status.HTTP_202_ACCEPTED)
async def trigger_org_infra(
    scan_id: str,
    body: SetPrimaryDomainRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Run the full infrastructure pipeline on a user-selected domain.

    For org scans: after Phase 1 discovers domains, the user selects one
    and this endpoint triggers the full pipeline (infrastructure, services,
    identity, search) on that domain.  The scan's target_domain is updated
    to the selected domain.
    """
    if scan.target_type != "organization":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="run-infra is only supported for organization scans",
        )

    scan.target_domain = body.domain
    scan.status = "RUNNING"
    scan.completed_at = None
    job = await dispatch_scan_job(
        db,
        execute_org_infra_task,
        scan_id,
        job_type="execute_org_infra",
        stage="infrastructure_enrichment",
        input_type="domain",
        input_value=body.domain,
        task_args=(body.domain,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "domain": body.domain,
    }


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    q: Optional[str] = Query(None, description="Search target_domain by prefix"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    from app.models.finding import Finding

    # Optional text search filter
    base_filter = Scan.target_domain.ilike(f"%{q}%") if q else None

    # Admin sees all scans; non-admin sees own + collaborated scans
    if current_user and current_user.role == "admin":
        stmt = select(Scan)
        if base_filter is not None:
            stmt = stmt.where(base_filter)
        stmt = stmt.order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    else:
        # Subquery: scan IDs the user has collaborator access to
        collab_subq = (
            select(ScanCollaborator.scan_id)
            .where(ScanCollaborator.user_id == current_user.id)
            .subquery()
        )
        filters = [
            or_(
                Scan.owner_id == current_user.id,
                Scan.id.in_(select(collab_subq.c.scan_id)),
            )
        ]
        if base_filter is not None:
            filters.append(base_filter)
        stmt = (
            select(Scan)
            .where(*filters)
            .order_by(Scan.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
    result = await db.execute(stmt)
    scans = result.scalars().all()

    if not scans:
        return []

    scan_ids = [s.id for s in scans]
    count_stmt = (
        select(Finding.scan_id, func.count(Finding.id))
        .where(Finding.scan_id.in_(scan_ids))
        .group_by(Finding.scan_id)
    )
    count_result = await db.execute(count_stmt)
    counts = {row[0]: row[1] for row in count_result.all()}

    from app.models.entity_link import EntityLink
    link_stmt = (
        select(EntityLink.scan_id, func.count(EntityLink.id))
        .where(EntityLink.scan_id.in_(scan_ids))
        .group_by(EntityLink.scan_id)
    )
    link_result = await db.execute(link_stmt)
    link_counts = {row[0]: row[1] for row in link_result.all()}

    for scan in scans:
        scan.findings_count = counts.get(scan.id, 0)
        scan.links_count = link_counts.get(scan.id, 0)

    return scans

@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Get scan metadata and aggregate counts.

    Requires read access to the scan (owner, admin, or collaborator).
    Findings are served separately through the paginated findings endpoint.
    """
    # Permission check — use the same logic as can_read_scan but inline
    # to avoid duplicate db sessions
    from app.core.auth import check_scan_access
    db_scan = await check_scan_access(db, scan_id, current_user, require_modify=False)

    finding_count_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.scan_id == scan_id)
    )
    findings_count = finding_count_result.scalar_one()
    from app.models.entity_link import EntityLink
    link_stmt = select(func.count(EntityLink.id)).where(EntityLink.scan_id == scan_id)
    link_result = await db.execute(link_stmt)
    links_count = link_result.scalar_one()
    return {
        "id": db_scan.id,
        "target_domain": db_scan.target_domain,
        "target_type": db_scan.target_type,
        "status": db_scan.status,
        "celery_task_id": db_scan.celery_task_id,
        "selected_vectors": db_scan.selected_vectors,
        "target_usernames": db_scan.target_usernames,
        "created_at": db_scan.created_at,
        "completed_at": db_scan.completed_at,
        "updated_at": db_scan.updated_at,
        "findings_count": findings_count,
        "links_count": links_count,
        "findings": [],
    }


@router.get("/{scan_id}/jobs", response_model=List[ScanJobResponse])
async def list_scan_jobs(
    scan_id: str,
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_read_scan()),
):
    """Return persisted background jobs for a scan, newest first."""
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.scan_id == scan_id)
        .order_by(ScanJob.created_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


@router.post("/{scan_id}/pivot", status_code=status.HTTP_202_ACCEPTED)
async def trigger_pivot(
    scan_id: str,
    body: PivotRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger a per-email pivot sweep (holehe + maigret + hibp)."""
    job = await dispatch_scan_job(
        db,
        pivot_sweep_task,
        scan_id,
        job_type="pivot_sweep",
        stage="identity",
        input_type="email",
        input_value=body.email,
        task_args=(body.email,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "email": body.email,
    }


@router.post("/{scan_id}/enrich", status_code=status.HTTP_202_ACCEPTED)
async def trigger_subdomain_enrich(
    scan_id: str,
    body: SubdomainEnrichRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger Hunter + XposedOrNot on user-selected subdomains."""
    job = await dispatch_scan_job(
        db,
        subdomain_enrich_task,
        scan_id,
        job_type="subdomain_enrich",
        stage="identity",
        input_type="domain_list",
        input_value=body.subdomains,
        task_args=(body.subdomains,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "subdomains": body.subdomains,
    }


@router.post("/{scan_id}/check-breaches", status_code=status.HTTP_202_ACCEPTED)
async def trigger_email_breach(
    scan_id: str,
    body: EmailBreachRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger XposedOrNot breach check on selected emails."""
    job = await dispatch_scan_job(
        db,
        email_breach_task,
        scan_id,
        job_type="email_breach_check",
        stage="identity",
        input_type="email_list",
        input_value=body.emails,
        task_args=(body.emails,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "emails": body.emails,
    }


@router.post("/{scan_id}/domain-deep-analysis", status_code=status.HTTP_202_ACCEPTED)
async def trigger_domain_deep_analysis(
    scan_id: str,
    body: DomainDeepAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger hunter + theharvester + github_secrets + dnstwist on a domain (all in parallel).

    The theHarvester supports ``quick`` mode (free-only sources, ~30s) and
    ``full`` mode (all API-key sources, ~900s).

    Duplicate prevention: a Redis-backed lock per (scan_id, domain) pair
    prevents multiple dispatch from UI race conditions or rapid clicks.
    The lock auto-expires after 30 minutes (sufficient for any deep analysis).
    """
    lock_key = f"deep_analysis:running:{scan_id}:{body.domain}"
    acquired = await _check_and_set_running_lock(lock_key, ttl_seconds=1800)
    if not acquired:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Deep analysis already running for domain '{body.domain}'",
        )

    try:
        job = await dispatch_scan_job(
            db,
            domain_deep_analysis_task,
            scan_id,
            job_type="domain_deep_analysis",
            stage="deep_analysis",
            input_type="domain",
            input_value=body.domain,
            task_args=(body.domain,),
            task_kwargs={"theharvester_mode": body.theharvester_mode},
        )
    except Exception:
        await _clear_running_lock(lock_key)
        raise
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "domain": body.domain,
        "theharvester_mode": body.theharvester_mode,
    }


@router.post("/{scan_id}/secrets-scan", status_code=status.HTTP_202_ACCEPTED)
async def trigger_secrets_scan(
    scan_id: str,
    body: DomainDeepAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Lightweight endpoint: only runs github_secrets collector (no full deep analysis).

    Much faster than /domain-deep-analysis — searches GitHub public repos for
    leaked secrets and repos mentioning the target domain. Used by the Secrets tab.
    """
    job = await dispatch_scan_job(
        db,
        github_secrets_scan_task,
        scan_id,
        job_type="github_secrets_scan",
        stage="secrets",
        input_type="domain",
        input_value=body.domain,
        task_args=(body.domain,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "domain": body.domain,
    }


@router.post("/{scan_id}/email-deep-analysis", status_code=status.HTTP_202_ACCEPTED)
async def trigger_email_deep_analysis(
    scan_id: str,
    body: EmailDeepAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger xposedornot + holehe + maigret on selected emails."""
    job = await dispatch_scan_job(
        db,
        email_deep_analysis_task,
        scan_id,
        job_type="email_deep_analysis",
        stage="identity",
        input_type="email_list",
        input_value=body.emails,
        task_args=(body.emails,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "emails": body.emails,
    }


@router.post("/{scan_id}/threat-intel", status_code=status.HTTP_202_ACCEPTED)
async def trigger_threat_intel(
    scan_id: str,
    body: ThreatIntelRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger GitHub secrets + dnstwist scan on a domain."""
    job = await dispatch_scan_job(
        db,
        threat_intel_task,
        scan_id,
        job_type="threat_intel_scan",
        stage="threat_intelligence",
        input_type="domain",
        input_value=body.domain,
        task_args=(body.domain,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "domain": body.domain,
    }


@router.post("/{scan_id}/shodan-enrich", status_code=status.HTTP_202_ACCEPTED)
async def trigger_shodan_enrich(
    scan_id: str,
    body: ShodanEnrichRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger Shodan and/or Censys Host API enrichment on a specific IP.

    provider field controls which APIs are called:
    - "shodan": runs Shodan Host API only
    - "censys": runs Censys Host API only
    - "both": runs both sequentially
    """
    provider = body.provider or "shodan"
    task_ids = []

    if provider in ("shodan", "both"):
        job = await dispatch_scan_job(
            db,
            shodan_enrich_task,
            scan_id,
            job_type="shodan_enrich",
            stage="service_enrichment",
            input_type="ip",
            input_value=body.ip,
            task_args=(body.ip,),
        )
        task_ids.append(job.celery_task_id)
    if provider in ("censys", "both"):
        job = await dispatch_scan_job(
            db,
            censys_enrich_task,
            scan_id,
            job_type="censys_enrich",
            stage="service_enrichment",
            input_type="ip",
            input_value=body.ip,
            task_args=(body.ip,),
        )
        task_ids.append(job.celery_task_id)

    return {
        "task_ids": task_ids,
        "scan_id": scan_id,
        "ip": body.ip,
        "provider": provider,
    }


@router.post("/{scan_id}/censys-enrich", status_code=status.HTTP_202_ACCEPTED)
async def trigger_censys_enrich(
    scan_id: str,
    body: CensysEnrichRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger Censys Host API enrichment on a specific IP.

    Runs the Censys Host API to get detailed port/service/vulnerability
    data for a single IP. Uses Censys search credits.
    """
    job = await dispatch_scan_job(
        db,
        censys_enrich_task,
        scan_id,
        job_type="censys_enrich",
        stage="service_enrichment",
        input_type="ip",
        input_value=body.ip,
        task_args=(body.ip,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "ip": body.ip,
    }


@router.post("/{scan_id}/dnstwist", status_code=status.HTTP_202_ACCEPTED)
async def trigger_dnstwist(
    scan_id: str,
    body: DnstwistRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger dnstwist lookalike domain detection on a domain.

    Generates permutations of the domain and checks which are actively
    registered (DNS resolution). Results appear in Brand Protection tab.
    """
    job = await dispatch_scan_job(
        db,
        dnstwist_only_task,
        scan_id,
        job_type="dnstwist_only",
        stage="brand_protection",
        input_type="domain",
        input_value=body.domain,
        task_args=(body.domain,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "domain": body.domain,
    }


@router.post("/{scan_id}/ahmia-search", status_code=status.HTTP_202_ACCEPTED)
async def trigger_ahmia_search(
    scan_id: str,
    body: DnstwistRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Search Ahmia.fi for .onion sites mentioning the domain.

    Queries the Ahmia search API for dark web mentions of the given
    domain or keyword. Results appear in the Threat Intel tab as
    ONION_SITE findings.
    """
    job = await dispatch_scan_job(
        db,
        ahmia_search_task,
        scan_id,
        job_type="ahmia_search",
        stage="threat_intelligence",
        input_type="domain",
        input_value=body.domain,
        task_args=(body.domain,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "domain": body.domain,
    }


@router.post("/{scan_id}/telegram-monitor", status_code=status.HTTP_202_ACCEPTED)
async def trigger_telegram_monitor(
    scan_id: str,
    body: TelegramMonitorRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger Telegram monitoring for a keyword.

    Runs the telegram_monitor collector which searches Telegram channels
    and messages for mentions of the keyword. Results appear in Threat
    Intel tab as TELEGRAM_MESSAGE and TELEGRAM_CHANNEL findings.
    """
    job = await dispatch_scan_job(
        db,
        telegram_monitor_task,
        scan_id,
        job_type="telegram_monitor",
        stage="threat_intelligence",
        input_type="keyword",
        input_value=body.keyword,
        task_args=(body.keyword,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
        "keyword": body.keyword,
    }


@router.post("/{scan_id}/ai-dork", status_code=status.HTTP_202_ACCEPTED)
async def trigger_ai_dork(
    scan_id: str,
    body: AIDorkRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Trigger an AI-powered Google Dork generation and search for a scan."""
    job = await dispatch_scan_job(
        db,
        run_ai_dork_task,
        scan_id,
        job_type="run_ai_dork_task",
        stage="search",
        input_type="prompt",
        input_value=body.prompt,
        task_args=(body.prompt,),
    )
    return {
        "task_id": job.celery_task_id,
        "scan_id": scan_id,
    }


@router.post("/{scan_id}/cancel", status_code=status.HTTP_200_OK)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Cancel every active Celery job belonging to a scan."""
    active_jobs = list(
        (
            await db.execute(
                select(ScanJob).where(
                    ScanJob.scan_id == scan_id,
                    ScanJob.status.in_(("QUEUED", "RUNNING", "RETRYING")),
                )
            )
        )
        .scalars()
        .all()
    )

    scan_is_active = scan.status in ("RUNNING", "QUEUED", "PENDING")
    if not scan_is_active and not active_jobs:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan {scan_id} has no active work to cancel.",
        )

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    if scan_is_active:
        scan.status = "CANCELLED"
        scan.completed_at = now

    task_ids = {job.celery_task_id for job in active_jobs}
    if scan_is_active and scan.celery_task_id:
        task_ids.add(scan.celery_task_id)
    for job in active_jobs:
        job.status = "CANCELLED"
        job.completed_at = now
    await db.commit()

    from app.workers.celery_app import celery_app

    revoked_task_ids = []
    for task_id in sorted(task_ids):
        try:
            celery_app.control.revoke(
                task_id, terminate=True, signal="SIGTERM"
            )
            revoked_task_ids.append(task_id)
        except Exception:
            logger.exception("failed to revoke Celery task %s", task_id)

    return {
        "status": "cancelled",
        "scan_id": scan_id,
        "revoked": bool(revoked_task_ids),
        "revoked_task_ids": revoked_task_ids,
    }


@router.get("/{scan_id}/report")
async def export_scan_report(
    scan_id: str,
    format: str = Query("csv", pattern="^(csv|json|pdf)$"),
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_read_scan()),
):
    """Export all findings for a scan as CSV, JSON, or PDF.

    Convenience wrapper around GET /findings/export filtered to this scan.
    Requires read access to the scan.
    """
    from app.services.export_service import ExportService

    result = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = list(result.scalars().all())

    if not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No findings found for this scan",
        )

    if format == "csv":
        content = ExportService.export_findings_csv(findings)
        fname = f"scan_{scan_id[:8]}_report.csv"
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={fname}"},
        )
    if format == "json":
        content = ExportService.export_findings_json(findings)
        fname = f"scan_{scan_id[:8]}_report.json"
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={fname}"},
        )
    content = ExportService.export_findings_pdf(findings)
    fname = f"scan_{scan_id[:8]}_report.pdf"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@router.get("/{scan_id}/export/emails")
async def export_scan_emails(
    scan_id: str,
    format: str = Query("csv", pattern="^(txt|csv)$"),
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_read_scan()),
):
    """Export discovered emails for a scan as TXT or CSV.

    TXT format: one email per line.
    CSV format: email, source_module, severity, created_at.

    Emails come from both entity_type=EMAIL findings and from the
    normalized_data.email / entity_value of BREACH findings.
    Requires read access to the scan.
    """
    import io as io_module
    import csv as csv_module

    result = await db.execute(
        select(Finding).where(
            Finding.scan_id == scan_id,
            Finding.entity_type.in_(["EMAIL", "BREACH"]),
        )
    )
    findings = list(result.scalars().all())

    # Deduplicate emails: EMAIL entity_value first, then BREACH extracted
    seen: set[str] = set()
    email_rows: list[dict[str, str]] = []
    for f in findings:
        if f.entity_type == "EMAIL":
            email = f.entity_value
        elif f.entity_type == "BREACH":
            nd = f.normalized_data or {}
            email = nd.get("email") or f.entity_value.split("::")[0]
        else:
            continue
        if not email or email in seen:
            continue
        seen.add(email)
        email_rows.append({
            "email": email,
            "source_module": f.source_module or "",
            "severity": f.severity or "",
            "confidence": str(f.confidence or ""),
            "created_at": str(f.created_at or ""),
        })

    if not email_rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No email findings found for this scan",
        )

    if format == "txt":
        lines = "\n".join(r["email"] for r in email_rows)
        fname = f"scan_{scan_id[:8]}_emails.txt"
        return Response(
            content=lines,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename={fname}"},
        )

    output = io_module.StringIO()
    writer = csv_module.writer(output)
    writer.writerow(["email", "source_module", "severity", "confidence", "created_at"])
    for r in email_rows:
        writer.writerow([
            r["email"],
            r["source_module"],
            r["severity"],
            r["confidence"],
            r["created_at"],
        ])
    fname = f"scan_{scan_id[:8]}_emails.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@router.post("/{scan_id}/collaborators", status_code=status.HTTP_201_CREATED, response_model=ScanCollaboratorResponse)
async def add_collaborator(
    scan_id: str,
    body: AddScanCollaboratorRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Add a collaborator to a scan.

    Only the scan owner or an admin can add collaborators.
    """
    # Verify the scan exists and the current user is owner or admin
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if current_user.role != "admin" and scan.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the scan owner or an admin can add collaborators.",
        )

    # Verify the target user exists
    result = await db.execute(select(User).where(User.id == body.user_id))
    target_user = result.scalar_one_or_none()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check for existing collaborator entry
    result = await db.execute(
        select(ScanCollaborator).where(
            ScanCollaborator.scan_id == scan_id,
            ScanCollaborator.user_id == body.user_id,
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a collaborator on this scan",
        )

    collab = ScanCollaborator(
        scan_id=scan_id,
        user_id=body.user_id,
        permission=body.permission,
        invited_by=current_user.id,
    )
    db.add(collab)
    await db.commit()
    await db.refresh(collab)

    return ScanCollaboratorResponse(
        id=collab.id,
        scan_id=collab.scan_id,
        user_id=collab.user_id,
        username=target_user.username,
        permission=collab.permission,
        created_at=collab.created_at,
    )


@router.patch("/{scan_id}/collaborators/{user_id}", response_model=ScanCollaboratorResponse)
async def update_collaborator_permission(
    scan_id: str,
    user_id: str,
    body: AddScanCollaboratorRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Update a collaborator's permission level on a scan.

    Only the scan owner or an admin can change collaborator permissions.
    """
    # Verify the scan exists and the current user is owner or admin
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if current_user.role != "admin" and scan.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the scan owner or an admin can change collaborator permissions.",
        )

    # Find the existing collaborator entry
    result = await db.execute(
        select(ScanCollaborator).where(
            ScanCollaborator.scan_id == scan_id,
            ScanCollaborator.user_id == user_id,
        )
    )
    collab = result.scalar_one_or_none()
    if not collab:
        raise HTTPException(status_code=404, detail="Collaborator not found")

    # Update permission
    collab.permission = body.permission
    await db.commit()
    await db.refresh(collab)

    # Fetch username for response
    user_result = await db.execute(select(User).where(User.id == collab.user_id))
    target_user = user_result.scalar_one_or_none()

    return ScanCollaboratorResponse(
        id=collab.id,
        scan_id=collab.scan_id,
        user_id=collab.user_id,
        username=target_user.username if target_user else "",
        permission=collab.permission,
        created_at=collab.created_at,
    )


@router.get("/{scan_id}/collaborators", response_model=list[ScanCollaboratorResponse])
async def list_collaborators(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_read_scan()),
):
    """List all collaborators on a scan.

    Requires read access to the scan.
    """
    result = await db.execute(
        select(ScanCollaborator).where(ScanCollaborator.scan_id == scan_id)
    )
    collabs = result.scalars().all()

    # Enrich with usernames
    user_ids = [c.user_id for c in collabs]
    if user_ids:
        users_result = await db.execute(
            select(User.id, User.username).where(User.id.in_(user_ids))
        )
        usernames = {row[0]: row[1] for row in users_result.all()}
    else:
        usernames = {}

    return [
        ScanCollaboratorResponse(
            id=c.id,
            scan_id=c.scan_id,
            user_id=c.user_id,
            username=usernames.get(c.user_id, ""),
            permission=c.permission,
            created_at=c.created_at,
        )
        for c in collabs
    ]


@router.get("/{scan_id}/permissions", response_model=ScanPermissionResponse)
async def get_scan_permissions(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Get the current user's permission level on a scan."""
    stmt = (
        select(Scan)
        .options(selectinload(Scan.collaborators))
        .where(Scan.id == scan_id)
    )
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if current_user.role == "admin":
        return ScanPermissionResponse(permission="owner", is_admin=True)

    if scan.owner_id == current_user.id:
        return ScanPermissionResponse(permission="owner")

    if scan.collaborators:
        for collab in scan.collaborators:
            if collab.user_id == current_user.id:
                return ScanPermissionResponse(permission=collab.permission)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Scan not found",
    )


@router.delete("/{scan_id}/collaborators/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_collaborator(
    scan_id: str,
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Remove a collaborator from a scan.

    Only the scan owner or an admin can remove collaborators.
    """
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if current_user.role != "admin" and scan.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the scan owner or an admin can remove collaborators.",
        )

    result = await db.execute(
        select(ScanCollaborator).where(
            ScanCollaborator.scan_id == scan_id,
            ScanCollaborator.user_id == user_id,
        )
    )
    collab = result.scalar_one_or_none()
    if not collab:
        raise HTTPException(status_code=404, detail="Collaborator not found")

    await db.delete(collab)
    await db.commit()
    return None


@router.patch("/{scan_id}/primary-domain", response_model=ScanResponse)
async def set_primary_domain(
    scan_id: str,
    body: SetPrimaryDomainRequest,
    db: AsyncSession = Depends(get_db),
    scan: Scan = Depends(can_modify_scan()),
):
    """Set the primary domain for an organization scan.

    Owners, admins, and collaborators with modify permission may change it.
    Intended for org scans where the auto-picked domain needs correction.
    """
    if scan.target_type != "organization":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Primary-domain selection is only supported for organization scans.",
        )

    scan.target_domain = body.domain
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Recalculate findings_count for the response
    from app.models.finding import Finding
    cnt = await db.execute(
        select(Finding.scan_id, func.count(Finding.id))
        .where(Finding.scan_id == scan.id)
        .group_by(Finding.scan_id)
    )
    row = cnt.one_or_none()
    scan.findings_count = row[1] if row else 0

    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Delete a scan and all its associated findings.

    Only the scan owner or an admin can delete scans. RUNNING scans cannot
    be deleted — cancel them first or wait for completion.
    """
    # Verify ownership or admin
    stmt = select(Scan).where(Scan.id == scan_id)
    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    if current_user.role != "admin" and scan.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the scan owner or an admin can delete scans.",
        )

    if scan.status in ("RUNNING", "QUEUED", "PENDING"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot delete a scan with status {scan.status}. Wait for completion or reset it first.",
        )

    await db.delete(scan)
    await db.commit()
    return None
