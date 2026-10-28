"""Shared state passed to every vector strategy.

The orchestrator constructs one `VectorContext` per scan; each vector
strategy reads from it, calls the shared helpers (`persist_findings`,
`publish`, `commit`), and may write back derived state (e.g. resolved
IPs collected by the infrastructure vector for the services vector to
reuse).

Keeping the surface small makes strategies easy to test in isolation.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.services.finding_contract import prepare_finding
from app.services.finding_service import refresh_finding
from app.services.progress import ScanProgressPublisher


@dataclass
class VectorContext:
    db: AsyncSession
    scan_id: str
    target_domain: str
    target_usernames: list[str]
    publisher: ScanProgressPublisher
    target_type: str = "domain"
    scan_mode: str = "validated"
    scope_manifest: dict[str, Any] = field(default_factory=dict)

    # Mutable running state — strategies append / replace as they work.
    findings_created: int = 0
    # Mirrors uq_finding_scan_entity_source on the findings table. Vector is
    # deliberately absent: the same evidence cannot be inserted twice merely
    # because two orchestration phases classified it differently.
    seen: set[tuple[str, str, str]] = field(default_factory=set)
    existing_findings: dict[tuple[str, str, str], Finding] = field(default_factory=dict)

    # Cross-vector scratch space. The infrastructure vector writes
    # resolved IPs here; services reads them so we don't re-run DNS.
    resolved_ips: set[str] = field(default_factory=set)

    async def load_seen_findings(self) -> None:
        """Populate `self.seen` with everything persisted so far."""
        result = await self.db.execute(
            select(Finding).where(Finding.scan_id == self.scan_id)
        )
        self.seen = set()
        self.existing_findings = {}
        for finding in result.scalars().all():
            key = (
                str(finding.entity_type or ""),
                str(finding.entity_value or ""),
                str(finding.source_module or ""),
            )
            self.seen.add(key)
            self.existing_findings[key] = finding

    async def persist(self, findings: Iterable[dict[str, Any]]) -> int:
        """Persist a batch of finding dicts, skipping duplicates.

        Returns the number of new rows inserted.
        """
        pending: list[Finding] = []
        new_keys: list[tuple[str, str, str]] = []
        processed_keys: set[tuple[str, str, str]] = set()
        for finding in findings:
            safe = prepare_finding(finding)
            key = (
                safe["entity_type"], safe["entity_value"], safe["source_module"],
            )
            if key in processed_keys:
                continue
            processed_keys.add(key)
            existing = self.existing_findings.get(key)
            if existing is not None:
                refresh_finding(existing, safe, observed_for=self.target_domain)
                continue
            pending.append(
                Finding(
                    scan_id=self.scan_id,
                    **safe,
                    last_observed_for=self.target_domain,
                )
            )
            new_keys.append(key)

        if not pending:
            self.seen.update(processed_keys)
            return 0

        self.db.add_all(pending)
        await self.db.flush()
        for finding, key in zip(pending, new_keys):
            self.existing_findings[key] = finding
        self.seen.update(processed_keys)
        self.findings_created += len(pending)
        return len(pending)

    async def persist_ip(self, ip: str) -> bool:
        """Helper for the common case of recording a discovered IP."""
        key = ("IP_ADDRESS", ip, "dns_resolver")
        existing = self.existing_findings.get(key)
        if existing is not None:
            refresh_finding(
                existing,
                {
                    "vector_type": "INFRASTRUCTURE",
                    "entity_type": "IP_ADDRESS",
                    "entity_value": ip,
                    "severity": "INFO",
                    "confidence": 1.0,
                    "source_module": "dns_resolver",
                    "raw_data": {"ip": ip},
                    "normalized_data": {"ip": ip},
                    "tags": ["resolved-ip"],
                },
                observed_for=self.target_domain,
            )
            return False
        self.seen.add(key)
        finding = Finding(
            scan_id=self.scan_id,
            vector_type="INFRASTRUCTURE",
            entity_type="IP_ADDRESS",
            entity_value=ip,
            severity="INFO",
            confidence=1.0,
            source_module="dns_resolver",
            raw_data={"ip": ip},
            normalized_data={"ip": ip},
            tags=["resolved-ip"],
            last_observed_for=self.target_domain,
        )
        self.db.add(finding)
        self.existing_findings[key] = finding
        self.findings_created += 1
        self.resolved_ips.add(ip)
        return True

    async def commit(self) -> None:
        """Flush a vector checkpoint without closing its orchestrator savepoint."""
        await self.db.flush()

    async def publish(self, event: str, **payload: Any) -> None:
        message = {
            "event": event,
            "scan_id": self.scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        await self.publisher.publish(self.scan_id, event, message)

    # Convenience accessors used by services-vector after infrastructure.
    async def findings_of(self, entity_type: str) -> list[Finding]:
        result = await self.db.execute(
            select(Finding).where(
                Finding.scan_id == self.scan_id,
                Finding.entity_type == entity_type,
            )
        )
        return list(result.scalars().all())
