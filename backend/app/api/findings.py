from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api._filters import build_findings_query
from app.core.auth import get_authenticated_user, check_scan_access
from app.database import get_db
from app.models.finding import Finding
from app.models.user import User
from app.schemas.base import FindingResponse, PaginatedFindingsResponse

router = APIRouter(dependencies=[Depends(get_authenticated_user)])


@router.get("/", response_model=PaginatedFindingsResponse)
async def get_findings(
    scan_id: Optional[str] = None,
    vector_type: Optional[str] = None,
    entity_type: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    # Permission check: if a scan_id is specified, verify user has access
    if scan_id:
        try:
            await check_scan_access(db, scan_id, current_user, require_modify=False)
        except HTTPException:
            # If the user can't access the scan, return empty results
            return PaginatedFindingsResponse(items=[], total=0, skip=skip, limit=limit)
    # Get total count matching filters
    count_stmt = select(func.count(Finding.id))
    if scan_id:
        count_stmt = count_stmt.where(Finding.scan_id == scan_id)
    if vector_type:
        count_stmt = count_stmt.where(Finding.vector_type == vector_type)
    if entity_type:
        count_stmt = count_stmt.where(Finding.entity_type == entity_type)
    if severity:
        count_stmt = count_stmt.where(Finding.severity == severity)
    if q:
        count_stmt = count_stmt.where(
            Finding.search_vector.op("@@")(func.plainto_tsquery("english", q))
        )
    total = (await db.execute(count_stmt)).scalar_one()

    # Get paginated items
    stmt = await build_findings_query(
        db, scan_id=scan_id, vector_type=vector_type,
        entity_type=entity_type, severity=severity, q=q,
        skip=skip, limit=limit,
    )
    result = await db.execute(stmt)
    items = result.scalars().all()

    return PaginatedFindingsResponse(items=items, total=total, skip=skip, limit=limit)


@router.get("/export")
async def export_findings(
    format: str = Query("csv", pattern="^(csv|json|pdf)$"),
    scan_id: Optional[str] = None,
    vector_type: Optional[str] = None,
    entity_type: Optional[str] = None,
    severity: Optional[str] = None,
    q: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    """Download findings as CSV, JSON, or PDF. Same filters as `GET /findings/`."""
    # Permission check: if a scan_id is specified, verify user has access
    if scan_id:
        try:
            await check_scan_access(db, scan_id, current_user, require_modify=False)
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found",
            )
    # Import here to avoid circular import (export service imports models).
    from app.services.export_service import ExportService

    stmt = await build_findings_query(
        db,
        scan_id=scan_id,
        vector_type=vector_type,
        entity_type=entity_type,
        severity=severity,
        q=q,
    )
    result = await db.execute(stmt)
    findings: list[Finding] = list(result.scalars().all())

    if format == "csv":
        content = ExportService.export_findings_csv(findings)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=findings.csv"},
        )
    if format == "json":
        content = ExportService.export_findings_json(findings)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=findings.json"},
        )
    # format is guaranteed by the regex to be one of the three.
    content = ExportService.export_findings_pdf(findings)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=findings.pdf"},
    )
