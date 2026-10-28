"""Finding persistence with observation and revision tracking."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding


FINDING_CONTENT_FIELDS = (
    "vector_type",
    "severity",
    "confidence",
    "raw_data",
    "normalized_data",
    "tags",
)


def refresh_finding(
    finding: Finding,
    safe: dict[str, Any],
    *,
    observed_for: str | None = None,
    observed_at: datetime | None = None,
) -> bool:
    """Record another observation and refresh changed collector evidence.

    Returns ``True`` when evidence content changed. Identity fields used by the
    unique key are intentionally immutable; a different identity is a new row.
    """
    now = observed_at or datetime.now(timezone.utc)
    changed = any(getattr(finding, field) != safe[field] for field in FINDING_CONTENT_FIELDS)
    for field in FINDING_CONTENT_FIELDS:
        setattr(finding, field, safe[field])
    finding.last_seen_at = now
    finding.observation_count = int(finding.observation_count or 0) + 1
    finding.last_observed_for = observed_for or finding.last_observed_for
    if changed:
        finding.revision = int(finding.revision or 1) + 1
    return changed


async def upsert_finding(
    db: AsyncSession,
    scan_id: str,
    safe: dict[str, Any],
    *,
    observed_for: str | None = None,
) -> tuple[Finding, bool, bool]:
    """Insert or refresh a finding.

    Returns ``(finding, created, changed)``. A repeated observation is not a
    duplicate no-op: timestamps/counts always advance and revised normalized
    evidence replaces the older representation.
    """
    existing = (
        await db.execute(
            select(Finding).where(
                Finding.scan_id == scan_id,
                Finding.entity_type == safe["entity_type"],
                Finding.entity_value == safe["entity_value"],
                Finding.source_module == safe["source_module"],
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        changed = refresh_finding(existing, safe, observed_for=observed_for)
        return existing, False, changed

    now = datetime.now(timezone.utc)
    finding = Finding(
        scan_id=scan_id,
        **safe,
        first_seen_at=now,
        last_seen_at=now,
        observation_count=1,
        revision=1,
        last_observed_for=observed_for,
    )
    db.add(finding)
    return finding, True, True
