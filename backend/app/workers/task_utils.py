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
from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
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

    if not normalized_findings:
        return []

    persisted: list[dict] = []
    for normalized in normalized_findings:
        entity_value = normalized.get("entity_value")
        if not entity_value:
            continue

        source_module = normalized.get("source_module", collector_name)
        entity_type = normalized.get("entity_type", "")

        existing = await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.entity_type == entity_type,
                Finding.entity_value == entity_value,
                Finding.source_module == source_module,
            )
        )
        if existing.scalar_one_or_none():
            continue

        finding = Finding(
            scan_id=scan_id,
            vector_type=normalized.get("vector_type", "IDENTITY"),
            entity_type=entity_type,
            entity_value=entity_value,
            severity=normalized.get("severity", "LOW"),
            confidence=normalized.get("confidence", 0.5),
            source_module=source_module,
            raw_data=normalized.get("raw_data", {}),
            normalized_data=normalized.get("normalized_data", {}),
            tags=normalized.get("tags", []),
        )
        db.add(finding)
        persisted.append(normalized)

    if persisted:
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
) -> int:
    """Persist normalized findings, skipping duplicates. Returns count of new rows.

    Dedup key: (scan_id, entity_type, entity_value, source_module).
    This is the canonical persist function — kept here so every task file
    (unified_scan, initial_scan, deep_pivot, etc.) uses the same logic.
    """
    new_count = 0
    for finding in findings:
        entity_value = finding.get("entity_value")
        if not entity_value:
            continue
        if isinstance(entity_value, dict):
            entity_value = str(entity_value.get("sha256", entity_value.get("value", str(entity_value))))
        if not isinstance(entity_value, str):
            entity_value = str(entity_value)

        source_module = finding.get("source_module", "")
        entity_type = finding.get("entity_type", "")

        result = await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.entity_type == entity_type,
                Finding.entity_value == entity_value,
                Finding.source_module == source_module,
            )
        )
        if result.scalar_one_or_none():
            continue

        db_finding = Finding(
            scan_id=scan_id,
            vector_type=finding.get("vector_type", default_vector),
            entity_type=entity_type,
            entity_value=entity_value,
            severity=finding.get("severity", default_severity),
            confidence=finding.get("confidence", default_confidence),
            source_module=source_module,
            raw_data=finding.get("raw_data", {}),
            normalized_data=finding.get("normalized_data", {}),
            tags=finding.get("tags", []),
        )
        db.add(db_finding)
        new_count += 1

    if new_count:
        await db.flush()

    return new_count


async def get_scan(scan_id: str) -> Scan | None:
    async with AsyncSessionLocal() as session:
        return await session.get(Scan, scan_id)
