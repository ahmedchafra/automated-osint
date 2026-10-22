"""Progress publisher backed by Redis pub/sub.

A fresh Redis connection is created per `publish()` call. The previous
implementation cached a module-level client, which breaks under Celery's
fork-pool + per-task `asyncio.new_event_loop()` pattern: the first task to
publish binds the client to loop A, then every task on loop B reuses that
same client and crashes with
``RuntimeError: got Future attached to a different loop``. The exception
was caught and logged, so progress events silently dropped.

Creating a connection per publish is cheap relative to the collector work
surrounding each call, and guarantees the client is bound to the running
loop. Failures are logged but never raised — a dropped progress event must
not fail the scan.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator

import redis.asyncio as aioredis

from app.config import settings

logger = logging.getLogger("osint.progress")


def _is_worker_shutdown_error(exc: BaseException) -> bool:
    """Identify expected Redis failures while Celery terminates a child."""
    current: BaseException | None = exc
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, SystemExit):
            return True
        if "executor shutdown has been called" in str(current).lower():
            return True
        current = current.__cause__ or current.__context__
    return False


@asynccontextmanager
async def _redis_client() -> AsyncIterator[aioredis.Redis]:
    """Open a fresh Redis connection for the current loop and close it on exit."""
    client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        yield client
    finally:
        try:
            await client.aclose()
        except Exception as exc:
            if not _is_worker_shutdown_error(exc):
                logger.exception("failed to close redis progress client")


class ScanProgressPublisher:
    """Publish scan progress events to a Redis pub/sub channel.

    Each ``publish()`` call opens its own connection bound to the current
    event loop, so the same publisher instance can safely be reused across
    tasks that each run in their own loop.
    """

    async def publish(self, scan_id: str, event: str, payload: dict[str, Any]) -> None:
        message = {
            "event": event,
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        try:
            async with _redis_client() as client:
                await client.publish(f"scan:{scan_id}", json.dumps(message))
        except Exception as exc:
            if _is_worker_shutdown_error(exc):
                logger.debug(
                    "skipped progress event %s during worker shutdown for scan %s",
                    event,
                    scan_id,
                )
                return
            logger.exception("failed to publish progress event %s for scan %s", event, scan_id)
