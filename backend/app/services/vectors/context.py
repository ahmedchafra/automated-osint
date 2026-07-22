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
from app.services.progress import ScanProgressPublisher


@dataclass
class VectorContext:
    db: AsyncSession
    scan_id: str
    target_domain: str
    target_usernames: list[str]
    publisher: ScanProgressPublisher

    # Mutable running state — strategies append / replace as they work.
    findings_created: int = 0
    seen: set[tuple[str, str, str, str]] = field(default_factory=set)

    # Cross-vector scratch space. The infrastructure vector writes
    # resolved IPs here; services reads them so we don't re-run DNS.
    resolved_ips: set[str] = field(default_factory=set)

    async def load_seen_findings(self) -> None:
        """Populate `self.seen` with everything persisted so far."""
        result = await self.db.execute(
            select(Finding).where(Finding.scan_id == self.scan_id)
        )
        self.seen = set()
        for finding in result.scalars().all():
            key = (
                str(finding.vector_type or ""),
                str(finding.entity_type or ""),
                str(finding.entity_value or ""),
                str(finding.source_module or ""),
            )
            self.seen.add(key)

    async def persist(self, findings: Iterable[dict[str, Any]]) -> int:
        """Persist a batch of finding dicts, skipping duplicates.

        Returns the number of new rows inserted.
        """
        new = 0
        for finding in findings:
            try:
                # Build dedup key with defensive string coercion
                vt = str(finding.get("vector_type", ""))
                et = str(finding.get("entity_type", ""))
                ev = str(finding.get("entity_value", ""))
                sm = str(finding.get("source_module", ""))
                key = (vt, et, ev, sm)
                if key in self.seen:
                    continue
                self.seen.add(key)

                # Build a safe copy with only the columns the Finding model expects
                # This prevents unexpected keys from causing issues
                safe = {
                    "vector_type": vt,
                    "entity_type": et,
                    "entity_value": ev,
                    "severity": str(finding.get("severity", "INFO")),
                    "confidence": float(finding.get("confidence", 0.5)),
                    "source_module": sm,
                    "raw_data": finding.get("raw_data", {}),
                    "normalized_data": finding.get("normalized_data", {}),
                    "tags": finding.get("tags", []) or [],
                }
                # Ensure JSON fields are dicts/lists, not strings
                if isinstance(safe["raw_data"], str):
                    safe["raw_data"] = {"raw": safe["raw_data"]}
                if isinstance(safe["normalized_data"], str):
                    safe["normalized_data"] = {"data": safe["normalized_data"]}
                if isinstance(safe["tags"], str):
                    safe["tags"] = [safe["tags"]]

                self.db.add(Finding(scan_id=self.scan_id, **safe))
                self.findings_created += 1
                new += 1
            except Exception as e:
                print(f"[persist] ERROR skipping finding: {e} | finding={finding!r}")
                continue
        if new:
            try:
                # Use savepoint so a flush failure only rolls back this batch
                # rather than wiping all uncommitted changes in the session.
                async with self.db.begin_nested():
                    await self.db.flush()
            except Exception as e:
                print(f"[persist] FLUSH ERROR: {e}")
                # Savepoint was rolled back; outer transaction is still usable.
                # Revert counters and reload seen from DB for consistency.
                self.findings_created -= new
                await self.load_seen_findings()
                return 0
        return new

    async def persist_ip(self, ip: str) -> bool:
        """Helper for the common case of recording a discovered IP."""
        key = ("INFRASTRUCTURE", "IP_ADDRESS", ip, "dns_resolver")
        if key in self.seen:
            return False
        self.seen.add(key)
        self.db.add(
            Finding(
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
            )
        )
        self.findings_created += 1
        self.resolved_ips.add(ip)
        return True

    async def commit(self) -> None:
        await self.db.commit()

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
