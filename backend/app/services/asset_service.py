from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

import tldextract
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.models.asset_observation import AssetObservation
from app.models.base import generate_uuid


_extract = tldextract.TLDExtract(suffix_list_urls=())
_STATE_RANK = {"CANDIDATE": 0, "RESOLVED": 1, "LIVE": 2}


def _observation_evidence(
    *,
    previous_state: str | None,
    reported_state: str,
    scope_reason: str,
    dns_records: dict[str, Any] | None,
    resolved_ips: list[str] | None,
    http_metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "previous_state": previous_state,
        "reported_state": reported_state,
        "scope_reason": scope_reason,
    }
    if dns_records:
        evidence["dns_records"] = dns_records
    if resolved_ips:
        evidence["resolved_ips"] = sorted(set(resolved_ips))
    if http_metadata:
        evidence["http_metadata"] = http_metadata
    return evidence


def append_asset_observation(
    session: AsyncSession,
    *,
    asset: Asset,
    source_module: str | None,
    event_type: str,
    observed_at: datetime | None = None,
    evidence: dict[str, Any] | None = None,
) -> AssetObservation:
    """Append one immutable lifecycle event for an already identified asset."""
    observation = AssetObservation(
        scan_id=asset.scan_id,
        asset_id=asset.id,
        asset_type=asset.asset_type,
        canonical_value=asset.canonical_value,
        state=asset.state,
        source_module=source_module,
        event_type=event_type,
        in_scope=asset.in_scope,
        wildcard_suspected=asset.wildcard_suspected,
        evidence=evidence or {},
        observed_at=observed_at or datetime.now(timezone.utc),
    )
    session.add(observation)
    return observation


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
    scope_reason: str = "allowed",
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
            id=generate_uuid(),
            scan_id=scan_id,
            asset_type=asset_type,
            value=value,
            canonical_value=canonical_value,
            registrable_domain=domain,
            state=state,
            in_scope=in_scope,
            scope_reason=scope_reason,
            wildcard_suspected=wildcard_suspected,
            source_modules=sources,
            evidence_count=1,
            dns_records=dns_records or {},
            resolved_ips=sorted(set(resolved_ips or [])),
            http_metadata=http_metadata or {},
            created_at=now,
            last_observed_at=now,
            updated_at=now,
        )
        session.add(asset)
        append_asset_observation(
            session,
            asset=asset,
            source_module=source_module,
            event_type="DISCOVERED",
            observed_at=now,
            evidence=_observation_evidence(
                previous_state=None,
                reported_state=state,
                scope_reason=scope_reason,
                dns_records=dns_records,
                resolved_ips=resolved_ips,
                http_metadata=http_metadata,
            ),
        )
        return asset

    previous_state = asset.state
    previous_in_scope = asset.in_scope
    previous_wildcard = asset.wildcard_suspected
    if _STATE_RANK.get(state, 0) > _STATE_RANK.get(asset.state, 0):
        asset.state = state
    sources = set(asset.source_modules or [])
    source_added = bool(source_module and source_module not in sources)
    if source_module:
        sources.add(source_module)
    asset.source_modules = sorted(sources)
    if source_added:
        asset.evidence_count = (asset.evidence_count or 0) + 1
    asset.in_scope = asset.in_scope and in_scope
    if not in_scope or asset.scope_reason == "allowed":
        asset.scope_reason = scope_reason
    asset.wildcard_suspected = asset.wildcard_suspected or wildcard_suspected
    if dns_records:
        asset.dns_records = dns_records
    if resolved_ips:
        asset.resolved_ips = sorted(set(asset.resolved_ips or []) | set(resolved_ips))
    if http_metadata:
        asset.http_metadata = http_metadata
    asset.last_observed_at = now
    if asset.state != previous_state:
        event_type = "STATE_CHANGED"
    elif asset.wildcard_suspected and not previous_wildcard:
        event_type = "WILDCARD_CLASSIFIED"
    elif asset.in_scope != previous_in_scope:
        event_type = "SCOPE_CHANGED"
    elif source_added:
        event_type = "SOURCE_ADDED"
    else:
        event_type = "REOBSERVED"
    append_asset_observation(
        session,
        asset=asset,
        source_module=source_module,
        event_type=event_type,
        observed_at=now,
        evidence=_observation_evidence(
            previous_state=previous_state,
            reported_state=state,
            scope_reason=scope_reason,
            dns_records=dns_records,
            resolved_ips=resolved_ips,
            http_metadata=http_metadata,
        ),
    )
    return asset
