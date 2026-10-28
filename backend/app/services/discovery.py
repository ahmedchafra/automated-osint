"""Canonical, source-aware processing for discovery collector results."""
from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable

from app.services.asset_service import canonical_hostname, registrable_domain


MAX_DUPLICATE_EVIDENCE = 20
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


@dataclass(frozen=True)
class DiscoveryBatch:
    findings: list[dict[str, Any]]
    duplicates_merged: int = 0
    invalid_dropped: int = 0
    canonicalized: int = 0


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def scoped_hostname(value: str, root_domain: str | None = None) -> str | None:
    """Return a canonical hostname when syntax and optional scope are valid."""
    raw = value.strip()
    if raw.startswith("*."):
        return None
    try:
        hostname = canonical_hostname(raw)
        root = canonical_hostname(root_domain) if root_domain else None
    except (UnicodeError, ValueError):
        return None
    if not hostname or "." not in hostname or len(hostname) > 253:
        return None
    if root and hostname != root and not hostname.endswith(f".{root}"):
        return None
    if any(_HOST_LABEL.fullmatch(label) is None for label in hostname.split(".")):
        return None
    return hostname


def _provider_sources(finding: dict[str, Any]) -> set[str]:
    normalized = finding.get("normalized_data")
    if not isinstance(normalized, dict):
        return set()
    values: set[str] = set()
    for key in ("discovery_source", "source_section"):
        value = normalized.get(key)
        if isinstance(value, str) and value:
            values.add(value)
    existing = normalized.get("provider_sources")
    if isinstance(existing, list):
        values.update(str(value) for value in existing if value)
    return values


def _duplicate_snapshot(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "entity_value": str(finding.get("entity_value", "")),
        "raw_data": copy.deepcopy(finding.get("raw_data", {})),
        "provider_sources": sorted(_provider_sources(finding)),
    }


def process_discovery_findings(
    findings: Iterable[dict[str, Any]],
    *,
    root_domain: str | None = None,
    hostname_entity_types: frozenset[str] = frozenset({"SUBDOMAIN"}),
    max_findings: int = 1000,
) -> DiscoveryBatch:
    """Validate, canonicalize, and deduplicate a collector result batch.

    The dedup key intentionally includes ``source_module``. The same asset
    discovered by crt.sh and Subfinder remains two independent Finding rows,
    while repeated variants from one source become one canonical row with a
    bounded evidence trail.
    """
    selected: dict[tuple[str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str]] = []
    duplicates_merged = 0
    invalid_dropped = 0
    canonicalized = 0

    for original in findings:
        finding = copy.deepcopy(original)
        entity_type = str(finding.get("entity_type", ""))
        original_value = str(finding.get("entity_value", "")).strip()
        source_module = str(finding.get("source_module", ""))
        if not entity_type or not original_value:
            invalid_dropped += 1
            continue

        canonical_value = original_value
        if entity_type in hostname_entity_types:
            valid_hostname = scoped_hostname(original_value, root_domain)
            if valid_hostname is None:
                invalid_dropped += 1
                continue
            canonical_value = valid_hostname
        elif entity_type == "IP_ADDRESS":
            if not is_public_ip(original_value):
                invalid_dropped += 1
                continue
            canonical_value = str(ipaddress.ip_address(original_value))

        if canonical_value != original_value:
            canonicalized += 1
        finding["entity_value"] = canonical_value
        normalized = finding.get("normalized_data")
        if not isinstance(normalized, dict):
            normalized = {}
            finding["normalized_data"] = normalized
        if entity_type in hostname_entity_types:
            normalized["canonical_value"] = canonical_value
            normalized["registrable_domain"] = registrable_domain(canonical_value)
        if canonical_value != original_value:
            normalized.setdefault("original_value", original_value)
        normalized["discovery_source_modules"] = [source_module] if source_module else []
        normalized["discovery_evidence_count"] = 1
        providers = _provider_sources(finding)
        if providers:
            normalized["provider_sources"] = sorted(providers)

        key = (entity_type, canonical_value, source_module)
        existing = selected.get(key)
        if existing is None:
            selected[key] = finding
            order.append(key)
            continue

        duplicates_merged += 1
        existing_normalized = existing.setdefault("normalized_data", {})
        existing_normalized["discovery_evidence_count"] = (
            int(existing_normalized.get("discovery_evidence_count", 1)) + 1
        )
        merged_providers = _provider_sources(existing) | providers
        if merged_providers:
            existing_normalized["provider_sources"] = sorted(merged_providers)
        evidence = existing_normalized.setdefault("duplicate_evidence", [])
        snapshot = _duplicate_snapshot(finding)
        if snapshot not in evidence and len(evidence) < MAX_DUPLICATE_EVIDENCE:
            evidence.append(snapshot)
        existing["confidence"] = max(
            float(existing.get("confidence", 0.0)),
            float(finding.get("confidence", 0.0)),
        )

    return DiscoveryBatch(
        findings=[selected[key] for key in order[:max_findings]],
        duplicates_merged=duplicates_merged,
        invalid_dropped=invalid_dropped,
        canonicalized=canonicalized,
    )
