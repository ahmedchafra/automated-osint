"""Shared helper for Celery worker tasks.

Provides `run_collector_for_scan` — the canonical pattern for running a
collector, deduping against the scan's existing findings, persisting new
rows, and publishing a Redis pubsub event. Every per-item task
(subdomain_enrich, pivot_sweep, email_breach, deep_pivot, threat_intel)
imports this instead of duplicating the logic.
"""
from __future__ import annotations

import asyncio

from celery.exceptions import SoftTimeLimitExceeded
from app.database import AsyncSessionLocal
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.services.discovery import process_discovery_findings
from app.services.finding_contract import prepare_finding
from app.services.finding_service import upsert_finding
from collectors.registry import registry


def _run_collector_in_loop(collector_name: str, target: str,
                           collector_kwargs: dict | None = None) -> list[dict]:
    """Run a collector in a fresh, properly configured event loop.

    Some collectors (holehe, maigret) use ``asyncio.get_event_loop()``
    internally, so we must set the new loop as current BEFORE running.

    Args:
        collector_name:  Name in the registry.
        target:          Domain, IP, or email to scan.
        collector_kwargs: Optional dict of kwargs forwarded to the collector
                          constructor. Example: ``{"free_only": True}`` for
                          theHarvester's quick mode.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        cls = registry.get_collector(collector_name)
        collector = cls(**(collector_kwargs or {}))
        return loop.run_until_complete(collector.execute(target))
    finally:
        loop.close()


async def run_collector_for_scan(
    collector_name: str,
    target: str,
    scan_id: str,
    db: AsyncSessionLocal,
    publisher: ScanProgressPublisher,
    collector_kwargs: dict | None = None,
) -> list[dict]:
    """Run a single collector against a target and persist findings.

    ``collector.execute()`` already returns normalized findings (it calls
    ``collect()`` + ``normalize()`` internally).  We read those directly
    instead of calling ``normalize()`` a second time.

    Args:
        collector_name:  Name in the collector registry.
        target:          Domain, IP, or email to scan.
        scan_id:         Scan UUID for persisting findings.
        db:              Async DB session.
        publisher:       Redis progress publisher.
        collector_kwargs: Optional kwargs forwarded to the collector
                          constructor (e.g. ``free_only`` for theHarvester).
    """
    # Run the collector in a separate thread with its own event loop
    # to avoid "Future attached to a different loop" errors from
    # subprocess-based collectors (holehe, maigret).
    loop = asyncio.get_event_loop()
    normalized_findings = await loop.run_in_executor(
        None, _run_collector_in_loop, collector_name, target, collector_kwargs or {}
    )

    if collector_name in {"crtsh", "subfinder", "theharvester", "common_crawl"}:
        normalized_findings = process_discovery_findings(
            normalized_findings,
            root_domain=target,
        ).findings

    if not normalized_findings:
        return []

    persisted: list[dict] = []
    for normalized in normalized_findings:
        safe = prepare_finding(normalized, default_source=collector_name)

        _, created, _ = await upsert_finding(
            db,
            scan_id,
            safe,
            observed_for=target,
        )
        if created:
            persisted.append(normalized)

    if normalized_findings:
        await db.flush()

    return persisted


def _run(coro):
    """Run an async coroutine in a new event loop, cleaning up async state.

    Celery worker tasks run in a sync context (ForkPool). This helper creates
    a fresh event loop, runs the coroutine, then properly shuts down
    async generators and the default executor before closing the loop.

    ForkPool event-loop fix
    -----------------------
    ``app.database`` creates the async engine at import time, *before* the
    ForkPool forks workers.  Each worker process inherits a connection pool
    that was created on the **parent process's** event loop.

    The fix lives in ``app.database.get_engine()``, which checks
    ``os.getpid()`` on every call.  When a forked worker first tries to
    create a session, the PID won't match the engine's creation PID, so
    ``get_engine()`` disposes the inherited pool (best-effort) and returns
    the same engine — SQLAlchemy lazily creates a **new** pool on the
    current event loop the first time a connection is needed.

    However, even within the same process, each ``_run()`` call creates a
    *new* event loop.  If the engine's pool has connections bound to a
    *previous* loop (which was closed), we'd get "Event loop is closed" /
    "Future attached to a different loop" errors on the next ``_run()``.

    We solve this by bumping a generation counter _before_ running the
    coroutine.  ``app.database.get_engine()`` compares this counter on
    every call and creates a **fresh engine** (with a new pool on the
    current loop) whenever it changes.  This is cheaper and more reliable
    than trying to dispose/recreate the pool on a closing loop.
    """
    from app.database import _bump_engine_gen
    _bump_engine_gen()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        return loop.run_until_complete(coro)
    except SoftTimeLimitExceeded:
        # The Celery worker's soft time limit was hit. The task will be
        # marked as FAILED by the worker. The scan's status will be
        # updated to FAILED by the orchestration layer's error handling.
        # Re-raise so Celery records the failure properly.
        raise
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        try:
            loop.run_until_complete(loop.shutdown_default_executor())
        except Exception:
            pass
        loop.close()


def run_task(coro_factory, *args, **kwargs):
    """Synchronous entry point for Celery tasks."""
    return _run(coro_factory(*args, **kwargs))


async def persist_findings(
    db: AsyncSessionLocal,
    scan_id: str,
    findings: list[dict],
    default_vector: str = "INFRASTRUCTURE",
    default_severity: str = "INFO",
    default_confidence: float = 0.5,
    observed_for: str | None = None,
) -> int:
    """Persist normalized findings, refreshing duplicates. Returns new-row count.

    Dedup key: (scan_id, entity_type, entity_value, source_module).
    This is the canonical persist function — kept here so every task file
    (unified_scan, initial_scan, deep_pivot, etc.) uses the same logic.
    """
    new_count = 0
    for finding in findings:
        safe = prepare_finding(
            finding,
            default_vector=default_vector,
            default_severity=default_severity,
            default_confidence=default_confidence,
        )

        _, created, _ = await upsert_finding(
            db,
            scan_id,
            safe,
            observed_for=observed_for,
        )
        if created:
            new_count += 1

    if findings:
        await db.flush()

    return new_count


async def get_scan(scan_id: str) -> Scan | None:
    async with AsyncSessionLocal() as session:
        return await session.get(Scan, scan_id)
