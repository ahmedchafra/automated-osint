from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.entity_link import EntityLink
from app.models.finding import Finding


class CorrelationEngine:
    def __init__(self, db: AsyncSession, scan_id: str):
        self.db = db
        self.scan_id = scan_id
        self.links_created = 0
        self._existing: set[tuple[str, str, str]] = set()

    async def run(self) -> int:
        await self._load_existing_links()

        result = await self.db.execute(select(Finding).where(Finding.scan_id == self.scan_id))
        findings = result.scalars().all()

        ip_findings = {
            finding.entity_value: finding
            for finding in findings
            if finding.entity_type == "IP_ADDRESS"
        }

        email_findings = {
            finding.entity_value: finding
            for finding in findings
            if finding.entity_type == "EMAIL"
        }

        for finding in findings:
            if finding.entity_type == "SUBDOMAIN":
                for ip in finding.normalized_data.get("resolved_ips", []):
                    ip_finding = ip_findings.get(ip)
                    if ip_finding:
                        self._add_link(finding, ip_finding, "RESOLVES_TO", 1.0)

            if finding.entity_type == "PORT_SERVICE":
                ip = finding.normalized_data.get("ip")
                ip_finding = ip_findings.get(ip)
                if ip_finding:
                    self._add_link(ip_finding, finding, "HAS_PORT", finding.confidence)

            if finding.entity_type == "CVE":
                ip = finding.normalized_data.get("ip")
                ip_finding = ip_findings.get(ip)
                if ip_finding:
                    self._add_link(ip_finding, finding, "HAS_VULNERABILITY", finding.confidence)

            if finding.entity_type == "BREACH":
                breach_email = finding.normalized_data.get("email")
                email_finding = email_findings.get(breach_email) if breach_email else None
                if email_finding:
                    self._add_link(email_finding, finding, "BREACHED_IN", finding.confidence)

        await self.db.flush()
        return self.links_created

    async def _load_existing_links(self) -> None:
        result = await self.db.execute(select(EntityLink).where(EntityLink.scan_id == self.scan_id))
        self._existing = {
            (link.source_finding_id, link.target_finding_id, link.link_type)
            for link in result.scalars().all()
        }

    def _add_link(self, source: Finding, target: Finding, link_type: str, confidence: float) -> None:
        if not source.id or not target.id or source.id == target.id:
            return

        key = (source.id, target.id, link_type)
        if key in self._existing:
            return

        self.db.add(
            EntityLink(
                scan_id=self.scan_id,
                source_finding_id=source.id,
                target_finding_id=target.id,
                link_type=link_type,
                confidence=confidence,
            )
        )
        self._existing.add(key)
        self.links_created += 1

