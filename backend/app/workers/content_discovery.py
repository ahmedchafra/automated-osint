"""Celery task for explicit, bounded content discovery."""
from __future__ import annotations

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.asset import Asset
from app.models.scan import Scan
from app.services.content_discovery import (
    MAX_DISCOVERY_ROOTS,
    ContentDiscoveryProfile,
    discover_content,
)
from app.services.progress import ScanProgressPublisher
from app.services.scope import ScopeEvaluator
from app.workers.celery_app import celery_app
from app.workers.task_utils import _run, persist_findings


async def _discover_scan_content(scan_id: str, profile: ContentDiscoveryProfile) -> dict:
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        if scan.scan_mode != "active":
            raise PermissionError("content discovery requires active mode")

        assets = (
            await session.execute(
                select(Asset).where(
                    Asset.scan_id == scan_id,
                    Asset.asset_type == "URL",
                    Asset.state == "LIVE",
                    Asset.in_scope.is_(True),
                    Asset.wildcard_suspected.is_(False),
                ).order_by(Asset.canonical_value.asc()).limit(MAX_DISCOVERY_ROOTS * 4)
            )
        ).scalars().all()
        urls = [asset.canonical_value for asset in assets]
        scope = ScopeEvaluator(
            scan.scope_manifest, target_type=scan.target_type, target=scan.target_domain,
        )
        publisher = ScanProgressPublisher()
        await publisher.publish(scan_id, "content_discovery_started", {
            "profile": profile, "eligible_urls": len(urls), "root_limit": MAX_DISCOVERY_ROOTS,
        })
        findings = await discover_content(urls, scope, profile)
        persisted = await persist_findings(session, scan_id, findings, default_vector="SERVICES")
        await session.commit()
        summary = {
            "scan_id": scan_id,
            "profile": profile,
            "eligible_urls": len(urls),
            "findings": len(findings),
            "persisted": persisted,
        }
        await publisher.publish(scan_id, "content_discovery_completed", summary)
        return summary


@celery_app.task(name="content_discovery", bind=True, max_retries=0)
def content_discovery_task(self, scan_id: str, profile: ContentDiscoveryProfile = "common"):
    return _run(_discover_scan_content(scan_id, profile))
