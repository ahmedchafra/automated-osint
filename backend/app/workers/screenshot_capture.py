"""Manual screenshot evidence capture for verified, in-scope live URLs."""
from __future__ import annotations

import asyncio
from pathlib import Path
import uuid

from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.screenshot import ScreenshotEvidence
from app.services.progress import ScanProgressPublisher
from app.services.scope import ScopeEvaluator
from app.services.screenshot_capture import capture_url, resolve_public_ips, storage_path
from app.workers.celery_app import celery_app
from app.workers.task_utils import _run


MAX_SCREENSHOTS_PER_RUN = 25
SCREENSHOT_CONCURRENCY = 2


async def _capture_screenshots(scan_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        if scan.scan_mode == "passive":
            raise PermissionError("screenshots require validated or active mode")

        evaluator = ScopeEvaluator(
            scan.scope_manifest, target_type=scan.target_type, target=scan.target_domain
        )
        assets = (
            await session.execute(
                select(Asset).where(
                    Asset.scan_id == scan_id,
                    Asset.asset_type == "URL",
                    Asset.state == "LIVE",
                    Asset.in_scope.is_(True),
                    Asset.wildcard_suspected.is_(False),
                ).order_by(Asset.canonical_value.asc()).limit(MAX_SCREENSHOTS_PER_RUN)
            )
        ).scalars().all()
        publisher = ScanProgressPublisher()
        await publisher.publish(scan_id, "screenshot_capture_started", {
            "targets": len(assets), "limit": MAX_SCREENSHOTS_PER_RUN,
        })

        semaphore = asyncio.Semaphore(SCREENSHOT_CONCURRENCY)
        exclusions = list((scan.scope_manifest or {}).get("excluded_url_paths") or [])

        async def capture_one(asset: Asset):
            async with semaphore:
                decision = evaluator.evaluate_asset("URL", asset.canonical_value)
                if not decision.allowed:
                    return None, f"scope blocked: {decision.reason}"
                from urllib.parse import urlparse
                hostname = urlparse(asset.canonical_value).hostname
                if not hostname:
                    return None, "URL has no hostname"
                addresses = await resolve_public_ips(hostname)
                if not addresses:
                    return None, "hostname did not resolve exclusively to public IPs"

                evidence_id = str(uuid.uuid4())
                key = f"{scan_id}/{evidence_id}.png"
                path = storage_path(settings.SCREENSHOT_STORAGE_PATH, key)
                try:
                    result = await capture_url(
                        asset.canonical_value,
                        path,
                        pinned_ip=addresses[0],
                        excluded_paths=exclusions,
                    )
                except Exception as exc:
                    return None, str(exc)[:500]
                evidence = ScreenshotEvidence(
                    id=evidence_id,
                    scan_id=scan_id,
                    asset_id=asset.id,
                    url=asset.canonical_value,
                    storage_key=key,
                    sha256=result.sha256,
                    width=result.width,
                    height=result.height,
                    page_title=result.page_title,
                    status_code=result.status_code,
                    capture_metadata={
                        "pinned_ip": addresses[0],
                        "resolved_ips": addresses,
                        "blocked_requests": result.blocked_requests,
                        "redirects_followed": False,
                        "cross_origin_requests_allowed": False,
                    },
                )
                return evidence, None

        results = await asyncio.gather(*(capture_one(asset) for asset in assets))
        captured = 0
        errors: list[dict[str, str]] = []
        for asset, (evidence, error) in zip(assets, results):
            if evidence:
                session.add(evidence)
                captured += 1
            elif error:
                errors.append({"url": asset.canonical_value, "error": error})
        try:
            await session.commit()
        except Exception:
            for evidence, _ in results:
                if evidence:
                    storage_path(settings.SCREENSHOT_STORAGE_PATH, evidence.storage_key).unlink(missing_ok=True)
            raise

        summary = {
            "scan_id": scan_id,
            "targets": len(assets),
            "captured": captured,
            "failed": len(errors),
            "errors": errors[:10],
        }
        await publisher.publish(scan_id, "screenshot_capture_completed", summary)
        return summary


@celery_app.task(name="screenshot_capture", bind=True, max_retries=0)
def screenshot_capture_task(self, scan_id: str):
    return _run(_capture_screenshots(scan_id))
