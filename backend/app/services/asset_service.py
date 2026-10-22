from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

import tldextract
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset


_extract = tldextract.TLDExtract(suffix_list_urls=())
_STATE_RANK = {"CANDIDATE": 0, "RESOLVED": 1, "LIVE": 2}


def canonical_hostname(value: str) -> str:
    """Return a stable lowercase ASCII hostname without a trailing dot."""
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    return candidate.encode("idna").decode("ascii")


def registrable_domain(value: str) -> str | None:
    """Return the public-suffix-aware registrable domain using the bundled PSL."""
    hostname = canonical_hostname(value)
    result = _extract(hostname)
    return result.top_domain_under_public_suffix or None


def canonical_asset_value(asset_type: str, value: str) -> str:
    if asset_type in {"DOMAIN", "SUBDOMAIN"}:
        return canonical_hostname(value)
    if asset_type == "IP_ADDRESS":
        return str(ipaddress.ip_address(value.strip()))
    return value.strip()


async def upsert_asset(
    session: AsyncSession,
    *,
    scan_id: str,
    asset_type: str,
    value: str,
    state: str = "CANDIDATE",
    source_module: str | None = None,
    in_scope: bool = True,
    wildcard_suspected: bool = False,
    dns_records: dict[str, Any] | None = None,
    resolved_ips: list[str] | None = None,
    http_metadata: dict[str, Any] | None = None,
) -> Asset:
    """Create or monotonically advance a canonical asset record."""
    canonical_value = canonical_asset_value(asset_type, value)
    result = await session.execute(
        select(Asset).where(
            Asset.scan_id == scan_id,
            Asset.asset_type == asset_type,
            Asset.canonical_value == canonical_value,
        )
    )
    asset = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if asset is None:
        sources = [source_module] if source_module else []
        domain = (
            registrable_domain(canonical_value)
            if asset_type in {"DOMAIN", "SUBDOMAIN"}
            else None
        )
        asset = Asset(
            scan_id=scan_id,
            asset_type=asset_type,
            value=value,
            canonical_value=canonical_value,
            registrable_domain=domain,
            state=state,
            in_scope=in_scope,
            wildcard_suspected=wildcard_suspected,
            source_modules=sources,
            evidence_count=1,
            dns_records=dns_records or {},
            resolved_ips=sorted(set(resolved_ips or [])),
            http_metadata=http_metadata or {},
            last_observed_at=now,
        )
        session.add(asset)
        return asset

    if _STATE_RANK.get(state, 0) > _STATE_RANK.get(asset.state, 0):
        asset.state = state
    sources = set(asset.source_modules or [])
    if source_module:
        sources.add(source_module)
    asset.source_modules = sorted(sources)
    asset.evidence_count = (asset.evidence_count or 0) + 1
    asset.in_scope = asset.in_scope and in_scope
    asset.wildcard_suspected = asset.wildcard_suspected or wildcard_suspected
    if dns_records:
        asset.dns_records = dns_records
    if resolved_ips:
        asset.resolved_ips = sorted(set(asset.resolved_ips or []) | set(resolved_ips))
    if http_metadata:
        asset.http_metadata = http_metadata
    asset.last_observed_at = now
    return asset
