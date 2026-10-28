"""IP address reconnaissance pipeline.

Runs IP-focused collectors (reverse DNS, Shodan, Censys, ASN lookup)
then optionally converges into the domain pipeline if reverse DNS
discovers a domain.

Pipeline order:
  Phase 1: Reverse DNS (PTR lookup) → discover domains
  Phase 1b: Shodan InternetDB (free) → open ports, services, CVEs
  Phase 2: RDAP + WhoIS / ASN Lookup
  Phase 3: Shodan Host + Censys Host → detailed port/service intel
  Phase 4: NVD CVE + CISA KEV (from discovered CPEs/CVEs)
  Phase 5: Serper search → dork results on IP
  Phase 6: If domain found → crt.sh + subfinder + theHarvester etc.

Each tool publishes progress events so the frontend shows live status.
"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.workers.task_utils import _run, persist_findings
from app.services.discovery import process_discovery_findings
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.services.scope import ScopeEvaluator

TOOL_WATCHDOG_SECONDS = 300
ISOLATED_TOOLS = {"subfinder", "crtsh", "dns_resolver"}
logger = logging.getLogger("osint.ip_scan")


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
        "tool": collector_name,
        "target": target,
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


async def _run_ip_pipeline(scan_id: str) -> dict:
    """Execute the full IP reconnaissance pipeline."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return {"scan_id": scan_id, "status": "missing"}

        publisher = ScanProgressPublisher()
        target_ip = scan.target_domain  # holds the IP address
        scope = ScopeEvaluator(scan.scope_manifest, target_type="ip", target=target_ip)
        scan.status = "RUNNING"
        await session.commit()

        await publisher.publish(scan_id, "scan_started", {
            "target_ip": target_ip,
            "phases": ["INFRASTRUCTURE", "SERVICES", "SEARCH"],
        })

        total_findings = 0
        discovered_domains: set[str] = set()
        resolved_ips: set[str] = {target_ip}
        thread_pool = ThreadPoolExecutor(max_workers=4)

        try:
            from app.services.asset_service import registrable_domain, upsert_asset

            await upsert_asset(
                session,
                scan_id=scan_id,
                asset_type="IP_ADDRESS",
                value=target_ip,
                state="RESOLVED",
                source_module="scan_target",
                in_scope=True,
                scope_reason="matches allowed CIDR",
            )

            # ─── PHASE 1: REVERSE DNS ──────────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "INFRASTRUCTURE",
                "phase_index": 1,
                "tools": ["reverse_dns", "shodan_internetdb", "whois_lookup", "rdap_lookup", "ripestat"],
            })

            # 1a. Reverse DNS — IP → domain names
            rdns_findings = process_discovery_findings(
                await _run_tool("reverse_dns", target_ip, scan_id, session, publisher, thread_pool),
                hostname_entity_types=frozenset({"DOMAIN_METADATA"}),
            ).findings
            for finding in rdns_findings:
                value = str(finding.get("entity_value", ""))
                if not value:
                    continue
                normalized = finding.setdefault("normalized_data", {})
                normalized["asset_state"] = "CANDIDATE"
                normalized["registrable_domain"] = registrable_domain(value)
                decision = scope.evaluate_hostname(value)
                normalized["in_scope"] = decision.allowed
                normalized["scope_reason"] = decision.reason
                await upsert_asset(
                    session,
                    scan_id=scan_id,
                    asset_type="DOMAIN",
                    value=value,
                    state="CANDIDATE",
                    source_module="reverse_dns",
                    in_scope=decision.allowed,
                    scope_reason=decision.reason,
                )
            total_findings += await persist_findings(session, scan_id, rdns_findings)
            for f in rdns_findings:
                ev = f.get("entity_value", "")
                if ev:
                    discovered_domains.add(ev)

            # 1b. Shodan InternetDB — free, no API key needed
            internetdb_findings = await _run_tool("shodan_internetdb", target_ip, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, internetdb_findings)
            for f in internetdb_findings:
                ev = f.get("entity_value", "")
                if ev and f.get("entity_type") == "IP_ADDRESS":
                    resolved_ips.add(ev)

            # 1c. Registration and routing enrichment on the IP.
            registration_results = await asyncio.gather(
                _run_tool("whois_lookup", target_ip, scan_id, session, publisher, thread_pool),
                _run_tool("rdap_lookup", target_ip, scan_id, session, publisher, thread_pool),
                _run_tool("ripestat", target_ip, scan_id, session, publisher, thread_pool),
            )
            for findings in registration_results:
                total_findings += await persist_findings(session, scan_id, findings)

            await session.commit()
            infra_results = {
                "domains_from_ptr": len(discovered_domains),
                "findings": total_findings,
            }
            await publisher.publish(scan_id, "phase_completed", {
                "phase": "INFRASTRUCTURE", "phase_index": 1,
                "result": infra_results,
            })

            # ─── PHASE 2: SERVICES (Shodan + Censys + NVD) ────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "SERVICES", "phase_index": 2,
                "tools": ["shodan_host", "censys_host", "nvd_cve", "cisa_kev"],
            })

            services_findings = 0
            for ip in sorted(resolved_ips):
                for tool in ("shodan_host", "censys_host"):
                    tool_findings = await _run_tool(tool, ip, scan_id, session, publisher, thread_pool)
                    services_findings += len(tool_findings)
                    total_findings += await persist_findings(session, scan_id, tool_findings)

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
                nvd_findings = await _run_tool("nvd_cve", cpe, scan_id, session, publisher, thread_pool)
                total_findings += await persist_findings(session, scan_id, nvd_findings)

            # CISA KEV
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id, Finding.entity_type == "CVE")
            )
            for finding in result.scalars().all():
                if finding.entity_value:
                    kev_findings = await _run_tool("cisa_kev", finding.entity_value, scan_id, session, publisher, thread_pool)
                    total_findings += await persist_findings(session, scan_id, kev_findings)

            await session.commit()
            await publisher.publish(scan_id, "phase_completed", {
                "phase": "SERVICES", "phase_index": 2,
                "result": {"findings": total_findings},
            })

            # ─── PHASE 3: SEARCH (Serper) ─────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "SEARCH", "phase_index": 3,
                "tools": ["serper_search"],
            })

            serper_findings = await _run_tool("serper_search", target_ip, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, serper_findings)
            await session.commit()

            await publisher.publish(scan_id, "phase_completed", {
                "phase": "SEARCH", "phase_index": 3,
                "result": {"findings": len(serper_findings)},
            })

            # ─── PHASE 4: DOMAIN CONVERGENCE ──────────────────────────────
            # If reverse DNS found domains, run the standard 6-tool domain
            # infrastructure scan on each discovered domain.
            approved_domains = {
                domain for domain in discovered_domains
                if scope.evaluate_hostname(domain).allowed
            }
            if approved_domains:
                await publisher.publish(scan_id, "phase_started", {
                    "phase": "IDENTITY", "phase_index": 4,
                    "tools": ["crtsh", "subfinder", "theharvester", "common_crawl", "dns_email_posture", "dns_resolver", "shodan_internetdb", "whois_lookup", "rdap_lookup", "ripestat"],
                })

                from app.workers.initial_scan import run_domain_scan

                for domain in sorted(approved_domains):
                    subs, ips, tool_findings = await run_domain_scan(
                        domain, scan_id, session, publisher, free_only=True,
                        scan_mode=scan.scan_mode,
                    )
                    total_findings += tool_findings

                await session.commit()
                await publisher.publish(scan_id, "phase_completed", {
                    "phase": "IDENTITY", "phase_index": 4,
                    "result": {"domains_from_ptr": len(approved_domains), "findings": total_findings},
                })
            elif discovered_domains:
                await publisher.publish(scan_id, "scope_blocked", {
                    "stage": "domain_convergence",
                    "assets": len(discovered_domains),
                    "reason": "PTR domains require manual scope inclusion",
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
                "phases": {
                    "INFRASTRUCTURE": infra_results,
                    "SERVICES": {"findings": total_findings},
                    "SEARCH": {"findings": len(serper_findings)},
                },
            })

            return {
                "scan_id": scan_id,
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


@celery_app.task(name="execute_ip_scan", bind=True, max_retries=1, default_retry_delay=10)
def execute_ip_scan_task(self, scan_id: str):
    """Celery entry point for the IP reconnaissance pipeline."""
    try:
        return _run(_run_ip_pipeline(scan_id))
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
