"""Small Redis-backed fixed-window rate limiter for authentication routes."""

from __future__ import annotations

import hashlib

import redis.asyncio as redis
from fastapi import HTTPException, Request, status

from app.config import settings


async def enforce_rate_limit(
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
    subject: str = "",
) -> None:
    """Reject requests that exceed a fixed-window limit.

    Redis failures are deliberately fail-open so an infrastructure outage does
    not lock every user out. Subjects are hashed before becoming Redis keys.
    """
    client_ip = request.client.host if request.client else "unknown"
    identity = f"{client_ip}:{subject.strip().lower()}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    key = f"rate-limit:{bucket}:{digest}"
    client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window_seconds)
        if count > limit:
            retry_after = await client.ttl(key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Try again later.",
                headers={"Retry-After": str(max(retry_after, 1))},
            )
    except HTTPException:
        raise
    except Exception:
        return
    finally:
        await client.aclose()
