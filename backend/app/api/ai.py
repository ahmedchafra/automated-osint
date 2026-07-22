"""AI dork and AIQuery history endpoints.

The platform records every AI-driven dork generation in the `ai_queries`
table so the operator gets both an audit trail and a way to re-render
previously generated dorks with their inline search results.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_api_key
from app.database import get_db
from app.models.ai_query import AIQuery
from app.schemas.base import AIDorkRequest, AIQueryResponse

router = APIRouter(dependencies=[Depends(get_api_key)])


class GenerateDorkResponse(BaseModel):
    dork: str


@router.post("/generate-dork", response_model=GenerateDorkResponse)
async def generate_dork(body: AIDorkRequest) -> GenerateDorkResponse:
    """Generate a Google Dork from a natural language prompt (preview only).

    Returns the generated dork string without executing a search. The
    frontend uses this to show the dork before the operator decides to
    run it against a scan.
    """
    from app.services.ai_service import AIService

    ai_service = AIService()
    try:
        dork = ai_service.generate_dork(body.prompt)
    except Exception:
        import re
        words = body.prompt.strip().split()
        domain = None
        for w in reversed(words):
            if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z]{2,})+$', w):
                domain = w
                break
        if domain:
            dork = f"site:{domain}"
        else:
            dork = f"site:{body.prompt.strip()}"
    return GenerateDorkResponse(dork=dork)


@router.get("/queries", response_model=List[AIQueryResponse])
async def list_ai_queries(
    scan_id: Optional[str] = None,
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """Return AIQuery history, optionally scoped to a scan."""
    stmt = select(AIQuery).order_by(AIQuery.created_at.desc()).limit(limit)
    if scan_id:
        stmt = (
            select(AIQuery)
            .where(AIQuery.scan_id == scan_id)
            .order_by(AIQuery.created_at.desc())
            .limit(limit)
        )
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/queries/{query_id}", response_model=AIQueryResponse)
async def get_ai_query(query_id: str, db: AsyncSession = Depends(get_db)):
    record = await db.get(AIQuery, query_id)
    if not record:
        raise HTTPException(status_code=404, detail="AI query not found")
    return record
