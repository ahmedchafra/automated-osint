"""Initial reconnaissance scan — Phase 1 only (free APIs).

Runs crt.sh -> subfinder -> theHarvester (free sources only) -> DNS
resolution -> Shodan InternetDB -> WhoIS/ASN, then marks the scan COMPLETED.
The analyst can then trigger additional enrichment on-demand (Shodan Host,
Hunter, XposedOrNot, theHarvester with all 55 sources, etc.) from the
workspace UI.

This task avoids the strict rate limits of paid APIs (Shodan Host,
XposedOrNot, Censys) by only using free endpoints. The theHarvester
runs in free-only mode (24 sources, no API keys) so it finishes in
~30 seconds instead of 5+ minutes with all 55 sources.
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.workers.task_utils import _run, persist_findings
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.config import settings

logger = logging.getLogger("osint.initial_scan")

TOOL_WATCHDOG_SECONDS = 300
ISOLATED_TOOLS = {"subfinder", "crtsh", "dns_resolver"}


def _run_coro_in_thread(coro_factory, *args):
    """Run a coroutine in a fresh event loop in a separate thread."""
    import threading
    result = {}
    def _worker():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result['value'] = loop.run_until_complete(coro_factory(*args))
        finally:
            loop.close()
    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    return result.get('value', [])


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
                    session, publisher,
                    theharvester_free_only: bool = True) -> list[dict]:
    """Run a single collector and return normalized findings.

    Args:
        theharvester_free_only: If True (default), theHarvester runs in free-only
                                 mode (24 sources, ~30s). Set False for all 55
                                 sources (requires API keys, ~900s).
    """
    start = time.monotonic()
    await publisher.publish(scan_id, "tool_started", {
        "tool": collector_name,
        "target": target,
    })

    try:
        if collector_name in ISOLATED_TOOLS:
            loop = asyncio.get_running_loop()
            findings = await loop.run_in_executor(
                None, _run_tool_sync, collector_name, target,
            )
        else:
            from collectors.registry import registry
            cls = registry.get_collector(collector_name)
            collector = cls()
            # theHarvester: use only free sources for Phase 1 speed
            if collector_name == "theharvester":
                collector.free_only = theharvester_free_only
            findings = await asyncio.wait_for(
                collector.execute(target),
                timeout=TOOL_WATCHDOG_SECONDS,
            )

        elapsed = time.monotonic() - start
        await publisher.publish(scan_id, "tool_completed", {
            "tool": collector_name,
            "target": target,
            "collected": len(findings),
            "elapsed_seconds": round(elapsed, 1),
        })
        return findings
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start
        await publisher.publish(scan_id, "tool_timeout", {
            "tool": collector_name,
            "target": target,
            "elapsed_seconds": round(elapsed, 1),
        })
        return []
    except Exception as e:
        elapsed = time.monotonic() - start
        await publisher.publish(scan_id, "tool_error", {
            "tool": collector_name,
            "target": target,
            "error": str(e),
            "elapsed_seconds": round(elapsed, 1),
        })
        return []


async def run_domain_scan(
    domain: str, scan_id: str, session, publisher,
    free_only: bool = True,
) -> tuple[set, set, int]:
    """Run the 6-tool domain infrastructure scan on a target domain.

    Can be called from any pipeline (initial, IP convergence, org infra)
    to avoid duplicating the tool chain.

    Tools: crtsh → subfinder → theHarvester → DNS → Shodan InternetDB → WhoIS

    Args:
        domain:     Target domain to scan.
        scan_id:    Scan UUID.
        session:    DB session.
        publisher:  Progress publisher.
        free_only:  If True (default), theHarvester runs in free-only mode (24 sources, ~30s).
                    Set False to run all 55 sources (needs API keys, ~900s).

    Returns:
        (all_subdomains, resolved_ips, total_findings)
    """
    total_findings = 0
    all_subdomains: set[str] = set()
    resolved_ips: set[str] = set()

    # 1a. crt.sh — SSL certificate transparency logs
    crtsh_findings = await _run_tool("crtsh", domain, scan_id, session, publisher)
    total_findings += await persist_findings(session, scan_id, crtsh_findings)
    for f in crtsh_findings:
        ev = f.get("entity_value", "")
        if ev:
            all_subdomains.add(ev)

    # 1b. subfinder — passive subdomain discovery
    subfinder_findings = await _run_tool("subfinder", domain, scan_id, session, publisher)
    total_findings += await persist_findings(session, scan_id, subfinder_findings)
    for f in subfinder_findings:
        ev = f.get("entity_value", "")
        if ev:
            all_subdomains.add(ev)

    # 1c. theHarvester — email/subdomain/IP from search engines
    theharvester_findings = await _run_tool(
        "theharvester", domain, scan_id, session, publisher,
        theharvester_free_only=free_only,
    )
    total_findings += await persist_findings(session, scan_id, theharvester_findings)
    for f in theharvester_findings:
        etype = f.get("entity_type", "")
        ev = f.get("entity_value", "")
        if etype == "SUBDOMAIN" and ev:
            all_subdomains.add(ev)
        elif etype == "IP_ADDRESS" and ev:
            resolved_ips.add(ev)

    # 1d. DNS resolution (bounded to 200 subdomains)
    from app.services.vectors.infrastructure import MAX_DNS_SUBDOMAINS, DNS_CONCURRENCY
    subdomains_to_resolve = {domain} | all_subdomains
    if len(subdomains_to_resolve) > MAX_DNS_SUBDOMAINS:
        subdomains_to_resolve = set(list(subdomains_to_resolve)[:MAX_DNS_SUBDOMAINS])

    dns_findings_all = []
    semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

    async def resolve_one(subdomain):
        async with semaphore:
            return await _run_tool("dns_resolver", subdomain, scan_id, session, publisher)

    dns_tasks = [asyncio.create_task(resolve_one(s)) for s in sorted(subdomains_to_resolve)]
    dns_results = await asyncio.gather(*dns_tasks, return_exceptions=True)
    for result in dns_results:
        if isinstance(result, list):
            dns_findings_all.extend(result)

    total_findings += await persist_findings(session, scan_id, dns_findings_all)
    for f in dns_findings_all:
        for ip in (f.get("normalized_data", {}) or {}).get("resolved_ips", []):
            resolved_ips.add(ip)

    # 1e. Shodan InternetDB — free port/service lookup per IP
    for ip in sorted(resolved_ips):
        shodan_findings = await _run_tool("shodan_internetdb", ip, scan_id, session, publisher)
        total_findings += await persist_findings(session, scan_id, shodan_findings)

    # 1f. WhoIS / ASN Lookup on domain and all resolved IPs
    whois_findings = await _run_tool("whois_lookup", domain, scan_id, session, publisher)
    total_findings += await persist_findings(session, scan_id, whois_findings)
    for ip in sorted(resolved_ips):
        asn_findings = await _run_tool("whois_lookup", ip, scan_id, session, publisher)
        total_findings += await persist_findings(session, scan_id, asn_findings)

    return all_subdomains, resolved_ips, total_findings


async def _run_pipeline(scan_id: str) -> dict:
    """Execute Phase 1: crt.sh -> subfinder -> DNS -> Shodan InternetDB."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return {"scan_id": scan_id, "status": "missing"}

        publisher = ScanProgressPublisher()
        scan.status = "RUNNING"
        await session.commit()

        await publisher.publish(scan_id, "scan_started", {
            "target_domain": scan.target_domain,
            "phases": ["INFRASTRUCTURE"],
        })

        total_findings = 0

        try:
            await publisher.publish(scan_id, "phase_started", {
                "phase": "INFRASTRUCTURE",
                "phase_index": 1,
                "tools": ["crtsh", "subfinder", "theharvester", "dns_resolver", "shodan_internetdb", "whois_lookup"],
            })

            all_subdomains, resolved_ips, tool_findings = await run_domain_scan(
                scan.target_domain, scan_id, session, publisher, free_only=True,
            )
            total_findings += tool_findings

            await session.commit()

            phase_results = {
                "subdomains": len(all_subdomains),
                "ips": len(resolved_ips),
                "findings": total_findings,
            }

            await publisher.publish(scan_id, "phase_completed", {
                "phase": "INFRASTRUCTURE",
                "phase_index": 1,
                "result": phase_results,
            })

            # Run correlation engine
            from app.services.correlation import CorrelationEngine
            links_created = await CorrelationEngine(session, scan_id).run()
            await session.commit()

            # Mark COMPLETED — user can still add more data via on-demand tasks
            scan.status = "COMPLETED"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
            await session.commit()

            await publisher.publish(scan_id, "scan_completed", {
                "status": "COMPLETED",
                "total_findings": total_findings,
                "links_created": links_created,
                "phases": {"INFRASTRUCTURE": phase_results},
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


@celery_app.task(name="execute_initial_scan", bind=True, max_retries=1, default_retry_delay=10)
def execute_initial_scan_task(self, scan_id: str):
    """Celery entry point for Phase 1 initial scan."""
    try:
        return _run(_run_pipeline(scan_id))
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
