from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import accessible_scan_ids_stmt, get_authenticated_user
from app.database import get_db
from app.models.entity_link import EntityLink
from app.models.user import User
from app.schemas.base import EntityLinkResponse

router = APIRouter(dependencies=[Depends(get_authenticated_user)])


@router.get("/", response_model=List[EntityLinkResponse])
async def get_entity_links(
    scan_id: Optional[str] = None,
    link_type: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_authenticated_user),
):
    stmt = select(EntityLink).where(
        EntityLink.scan_id.in_(accessible_scan_ids_stmt(current_user))
    )

    if scan_id:
        stmt = stmt.where(EntityLink.scan_id == scan_id)
    if link_type:
        stmt = stmt.where(EntityLink.link_type == link_type)

    stmt = stmt.offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()
