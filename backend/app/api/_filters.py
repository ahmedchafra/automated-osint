"""Shared filter builder for the findings API.

The `/findings/` (list) and `/findings/export` endpoints accept the same
filter parameters. Build the SQLAlchemy statement once and call it from
both places so the two never drift apart.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding


async def build_findings_query(
    db: AsyncSession,
    scan_id: Optional[str] = None,
    vector_type: Optional[str] = None,
    entity_type: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    skip: int = 0,
    limit: Optional[int] = None,
    accessible_scan_ids: Optional[Select] = None,
) -> Select:
    """Compose the filtered `Finding` SELECT used by list + export endpoints."""
    stmt = select(Finding)

    if accessible_scan_ids is not None:
        stmt = stmt.where(Finding.scan_id.in_(accessible_scan_ids))

    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if vector_type:
        stmt = stmt.where(Finding.vector_type == vector_type)
    if entity_type:
        stmt = stmt.where(Finding.entity_type == entity_type)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if q:
        # Postgres full-text search via the GIN-indexed tsvector column
        # populated by the `findings_search_vector_trigger`. The plainto_tsquery
        # form is safe because it ignores punctuation and treats the input as
        # AND-separated terms — no operator injection.
        stmt = stmt.where(
            Finding.search_vector.op("@@")(func.plainto_tsquery("english", q))
        )

    stmt = stmt.order_by(Finding.created_at.desc()).offset(skip)
    if limit is not None:
        stmt = stmt.limit(limit)
    return stmt
