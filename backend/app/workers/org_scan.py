"""Organization name reconnaissance pipeline.

Takes a company/organization name, discovers associated domains via
search engines and reverse whois, then stops — the user selects a domain
and triggers infrastructure discovery on-demand.

Pipeline order (automated):
  Phase 1: Org domain discovery (Serper + Whoxy) → find domains → score → stop

On-demand (user triggers from workspace):
  Phase 2+: For the selected domain → run standard infrastructure scan
            (crt.sh → subfinder → theHarvester → DNS → Shodan InternetDB)
            Services → WhoIS/ASN → NVD CVE → CISA KEV
"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.workers.task_utils import _run, persist_findings
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher

TOOL_WATCHDOG_SECONDS = 300
ISOLATED_TOOLS = {"subfinder", "crtsh", "dns_resolver"}
logger = logging.getLogger("osint.org_scan")


def _run_tool_sync(collector_name: str, target: str) -> list[dict]:
    """Run a collector in an isolated thread+loop, return normalized findings."""
    from collectors.registry import registry
    cls = registry.get_collector(collector_name)
    collector = cls()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            asyncio.wait_for(
                collector.execute(target),
                timeout=TOOL_WATCHDOG_SECONDS,
            )
        )
    except asyncio.TimeoutError:
        logger.warning("Tool %s timed out after %ds on %s", collector_name, TOOL_WATCHDOG_SECONDS, target)
        return []
    except Exception as e:
        logger.exception("Tool %s failed on %s: %s", collector_name, target, e)
        return []
    finally:
        loop.close()


async def _run_tool(collector_name: str, target: str, scan_id: str,
                    session, publisher, thread_pool=None) -> list[dict]:
    """Run a single collector and return normalized findings."""
    start = asyncio.get_event_loop().time()
    await publisher.publish(scan_id, "tool_started", {
        "tool": collector_name, "target": target,
    })
    try:
        if collector_name in ISOLATED_TOOLS and thread_pool:
            loop = asyncio.get_running_loop()
            findings = await loop.run_in_executor(
                thread_pool, _run_tool_sync, collector_name, target,
            )
        else:
            from collectors.registry import registry
            cls = registry.get_collector(collector_name)
            collector = cls()
            findings = await asyncio.wait_for(
                collector.execute(target),
                timeout=TOOL_WATCHDOG_SECONDS,
            )
        elapsed = asyncio.get_event_loop().time() - start
        await publisher.publish(scan_id, "tool_completed", {
            "tool": collector_name, "target": target,
            "collected": len(findings), "elapsed_seconds": round(elapsed, 1),
        })
        return findings
    except asyncio.TimeoutError:
        await publisher.publish(scan_id, "tool_timeout", {
            "tool": collector_name, "target": target,
            "watchdog_seconds": TOOL_WATCHDOG_SECONDS,
        })
        return []
    except Exception as e:
        await publisher.publish(scan_id, "tool_error", {
            "tool": collector_name, "target": target, "error": str(e),
        })
        return []


async def _run_org_domain_phase(scan_id: str, session, publisher, thread_pool) -> tuple[str | None, list[dict], int]:
    """Discover domains for the organization, return the primary domain and raw findings."""
    from app.models.finding import Finding

    scan = await session.get(Scan, scan_id)
    if not scan:
        return None, [], 0

    total = 0
    org_name = scan.target_domain  # holds the org name
    from app.services.asset_service import registrable_domain, upsert_asset

    await upsert_asset(
        session,
        scan_id=scan_id,
        asset_type="ORGANIZATION",
        value=org_name,
        state="CANDIDATE",
        source_module="scan_target",
    )

    await publisher.publish(scan_id, "phase_started", {
        "phase": "DISCOVERY", "phase_index": 1,
        "tools": ["org_domain_discovery", "reverse_whois_whoxy"],
    })

    # Serper-based domain discovery
    findings = await _run_tool("org_domain_discovery", org_name, scan_id, session, publisher, thread_pool)

    # Whoxy reverse-whois discovery
    whoxy_findings = await _run_tool("reverse_whois_whoxy", org_name, scan_id, session, publisher, thread_pool)
    findings.extend(whoxy_findings)

    for finding in findings:
        value = str(finding.get("entity_value", ""))
        if not value:
            continue
        normalized = finding.setdefault("normalized_data", {})
        normalized["asset_state"] = "CANDIDATE"
        normalized["registrable_domain"] = registrable_domain(value)
        await upsert_asset(
            session,
            scan_id=scan_id,
            asset_type="DOMAIN",
            value=value,
            state="CANDIDATE",
            source_module=finding.get("source_module"),
        )

    total += await persist_findings(session, scan_id, findings)

    await session.commit()

    discovered_domains = set()
    for f in findings:
        ev = f.get("entity_value", "")
        if ev:
            discovered_domains.add(ev)

    primary_domain = None
    if discovered_domains:
        # Pick the first discovered domain (most relevant from search)
        primary_domain = sorted(discovered_domains)[0]

    await publisher.publish(scan_id, "phase_completed", {
        "phase": "DISCOVERY", "phase_index": 1,
        "result": {
            "organization": org_name,
            "domains_discovered": len(discovered_domains),
            "primary_domain": primary_domain,
            "findings": total,
        },
    })

    return primary_domain, findings, total


async def _run_infra_phase(
    scan_id: str, domain: str, session, publisher, scan_mode: str = "validated"
) -> tuple[set, set, int]:
    """Run infrastructure discovery on a domain using the shared 6-tool pipeline."""
    from app.workers.initial_scan import run_domain_scan

    all_subdomains, resolved_ips, total = await run_domain_scan(
        domain, scan_id, session, publisher, free_only=True,
        scan_mode=scan_mode,
    )
    return all_subdomains, resolved_ips, total


async def _run_org_pipeline(scan_id: str) -> dict:
    """Execute the full organization reconnaissance pipeline."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return {"scan_id": scan_id, "status": "missing"}

        publisher = ScanProgressPublisher()
        org_name = scan.target_domain
        scan.status = "RUNNING"
        await session.commit()

        await publisher.publish(scan_id, "scan_started", {
            "target_org": org_name,
            "phases": ["DISCOVERY", "INFRASTRUCTURE", "SERVICES", "IDENTITY", "SEARCH"],
        })

        total_findings = 0
        thread_pool = ThreadPoolExecutor(max_workers=4)

        try:
            # ─── PHASE 1: ORG DOMAIN DISCOVERY ─────────────────────────────
            primary_domain, domain_findings, discovery_count = await _run_org_domain_phase(
                scan_id, session, publisher, thread_pool
            )
            total_findings += discovery_count

            # ─── STOP AFTER PHASE 1 ─────────────────────────────────────────
            # The user selects a domain and triggers infra on-demand via the
            # workspace UI.  We store discovered domains in scan metadata.
            discovered_domain_list = sorted(
                {f.get("entity_value", "") for f in domain_findings if f.get("entity_value", "")}
            )

            scan.status = "COMPLETED"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
            await session.commit()

            await publisher.publish(scan_id, "scan_completed", {
                "status": "COMPLETED",
                "total_findings": total_findings,
                "links_created": 0,
                "phases": {"DISCOVERY": {"domains": len(discovered_domain_list)}},
            })

            return {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "total_findings": total_findings,
                "links_created": 0,
            }

        except Exception:
            scan.status = "FAILED"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
            await session.commit()
            await publisher.publish(scan_id, "scan_failed", {"status": "FAILED"})
            raise
        finally:
            thread_pool.shutdown(wait=False)


@celery_app.task(name="execute_org_scan", bind=True, max_retries=1, default_retry_delay=10)
def execute_org_scan_task(self, scan_id: str):
    """Celery entry point for the organization reconnaissance pipeline.

    Runs Phase 1 (domain discovery) and stops — the user selects a
    domain and triggers infrastructure on-demand.
    """
    try:
        return _run(_run_org_pipeline(scan_id))
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise


async def _run_org_infra(scan_id: str, domain: str) -> dict:
    """Run the full infrastructure pipeline on a single domain.

    This is called on-demand after the user selects a domain discovered
    during the org scan's Phase 1.
    """
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return {"scan_id": scan_id, "domain": domain, "status": "missing"}

        publisher = ScanProgressPublisher()
        scan.status = "RUNNING"
        scan.target_domain = domain  # update to the selected domain
        await session.commit()

        await publisher.publish(scan_id, "scan_started", {
            "target_domain": domain,
            "phases": ["INFRASTRUCTURE", "SERVICES", "IDENTITY", "SEARCH"],
        })

        total_findings = 0
        thread_pool = ThreadPoolExecutor(max_workers=4)

        try:
            # ─── INFRASTRUCTURE ─────────────────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "INFRASTRUCTURE", "phase_index": 1,
                "tools": ["crtsh", "subfinder", "theharvester", "dns_resolver", "shodan_internetdb", "whois_lookup"],
            })

            all_subdomains, resolved_ips, infra_findings = await _run_infra_phase(
                scan_id, domain, session, publisher, scan.scan_mode
            )
            total_findings += infra_findings
            await session.commit()

            await publisher.publish(scan_id, "phase_completed", {
                "phase": "INFRASTRUCTURE", "phase_index": 1,
                "result": {"subdomains": len(all_subdomains), "ips": len(resolved_ips), "findings": total_findings},
            })

            # ─── SERVICES ───────────────────────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "SERVICES", "phase_index": 2,
                "tools": ["shodan_host", "censys_host", "nvd_cve", "cisa_kev"],
            })

            for ip in sorted(resolved_ips):
                for tool in ("shodan_host", "censys_host"):
                    tf = await _run_tool(tool, ip, scan_id, session, publisher, thread_pool)
                    total_findings += await persist_findings(session, scan_id, tf)

            # NVD CVE from discovered CPEs
            from app.models.finding import Finding
            from sqlalchemy import select
            cpe_values = set()
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id, Finding.entity_type == "PORT_SERVICE")
            )
            for finding in result.scalars().all():
                nd = finding.normalized_data or {}
                for key in ("cpes", "cpe23", "cpe"):
                    cpes = nd.get(key, [])
                    if isinstance(cpes, list):
                        for cpe in cpes:
                            if isinstance(cpe, str) and cpe.strip():
                                cpe_values.add(cpe.strip())

            for cpe in sorted(cpe_values):
                nvd_f = await _run_tool("nvd_cve", cpe, scan_id, session, publisher, thread_pool)
                total_findings += await persist_findings(session, scan_id, nvd_f)

            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id, Finding.entity_type == "CVE")
            )
            for finding in result.scalars().all():
                if finding.entity_value:
                    kev_f = await _run_tool("cisa_kev", finding.entity_value, scan_id, session, publisher, thread_pool)
                    total_findings += await persist_findings(session, scan_id, kev_f)

            await session.commit()
            await publisher.publish(scan_id, "phase_completed", {
                "phase": "SERVICES", "phase_index": 2,
                "result": {"findings": total_findings},
            })

            # ─── IDENTITY ───────────────────────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "IDENTITY", "phase_index": 3,
                "tools": ["hunter_domain", "xposedornot_breach", "h8mail"],
            })

            hunter_f = await _run_tool("hunter_domain", domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, hunter_f)

            # Collect emails
            emails = set()
            for f in hunter_f:
                ev = f.get("entity_value", "")
                if "@" in ev:
                    emails.add(ev)

            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id, Finding.entity_type == "EMAIL")
            )
            for finding in result.scalars().all():
                if "@" in (finding.entity_value or ""):
                    emails.add(finding.entity_value)

            for email in sorted(emails):
                bf = await _run_tool("xposedornot_breach", email, scan_id, session, publisher, thread_pool)
                total_findings += await persist_findings(session, scan_id, bf)
                await asyncio.sleep(0.6)

            for email in sorted(emails):
                hf = await _run_tool("h8mail", email, scan_id, session, publisher, thread_pool)
                total_findings += await persist_findings(session, scan_id, hf)

            await session.commit()
            await publisher.publish(scan_id, "phase_completed", {
                "phase": "IDENTITY", "phase_index": 3,
                "result": {"emails": len(emails), "findings": total_findings},
            })

            # ─── SEARCH ─────────────────────────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "SEARCH", "phase_index": 4,
                "tools": ["dnstwist", "github_secrets", "serper_search"],
            })

            dnstwist_f = await _run_tool("dnstwist", domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, dnstwist_f)

            gh_f = await _run_tool("github_secrets", domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, gh_f)

            serper_f = await _run_tool("serper_search", domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, serper_f)

            await session.commit()
            await publisher.publish(scan_id, "phase_completed", {
                "phase": "SEARCH", "phase_index": 4,
                "result": {"findings": total_findings},
            })

            # ─── CORRELATION ───────────────────────────────────────────────
            from app.services.correlation import CorrelationEngine
            links_created = await CorrelationEngine(session, scan_id).run()
            await session.commit()

            # ─── COMPLETE ──────────────────────────────────────────────────
            scan.status = "COMPLETED"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
            await session.commit()

            await publisher.publish(scan_id, "scan_completed", {
                "status": "COMPLETED",
                "total_findings": total_findings,
                "links_created": links_created,
            })

            return {
                "scan_id": scan_id,
                "domain": domain,
                "status": "COMPLETED",
                "total_findings": total_findings,
                "links_created": links_created,
            }

        except Exception:
            scan.status = "FAILED"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
            await session.commit()
            await publisher.publish(scan_id, "scan_failed", {"status": "FAILED"})
            raise
        finally:
            thread_pool.shutdown(wait=False)


@celery_app.task(name="execute_org_infra", bind=True, max_retries=1, default_retry_delay=10)
def execute_org_infra_task(self, scan_id: str, domain: str):
    """Celery entry point: run full infrastructure on a user-selected domain."""
    try:
        return _run(_run_org_infra(scan_id, domain))
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
