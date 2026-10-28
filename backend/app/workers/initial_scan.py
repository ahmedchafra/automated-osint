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
from app.services.asset_service import registrable_domain, upsert_asset
from app.services.discovery import (
    is_public_ip,
    process_discovery_findings,
    scoped_hostname,
)
from app.services.dns_validation import detect_wildcard_dns, matches_wildcard
from app.services.http_validation import (
    HTTP_PROBE_CONCURRENCY,
    MAX_HTTP_PROBES,
    probe_http,
)
from app.services.scope import ScopeEvaluator
from app.config import settings

logger = logging.getLogger("osint.initial_scan")

TOOL_WATCHDOG_SECONDS = 300
ISOLATED_TOOLS = {"subfinder", "crtsh", "dns_resolver"}
MAX_DISCOVERY_FINDINGS_PER_SOURCE = 1000
MAX_WEB_SURFACE_TARGETS = 25
WEB_SURFACE_CONCURRENCY = 5
MAX_REGISTRY_IP_TARGETS = 25


def _bounded_dns_candidates(
    root_domain: str, discovered: set[str], limit: int
) -> list[str]:
    """Select deterministic DNS candidates while always retaining the apex."""
    ordered = sorted(
        (hostname for hostname in discovered if hostname != root_domain),
        key=lambda hostname: (hostname.count("."), len(hostname), hostname),
    )
    return [root_domain, *ordered[: max(0, limit - 1)]]


def _valid_subdomain(value: str, root_domain: str) -> bool:
    """Return whether a discovered name is a syntactically valid child."""
    return scoped_hostname(value, root_domain) is not None


def _public_ip(value: str) -> bool:
    return is_public_ip(value)


def _filter_discovery_findings(
    findings: list[dict], root_domain: str
) -> list[dict]:
    """Canonicalize, source-deduplicate, validate, and bound discovery."""
    return process_discovery_findings(
        findings,
        root_domain=root_domain,
        max_findings=MAX_DISCOVERY_FINDINGS_PER_SOURCE,
    ).findings


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


async def _run_registration_enrichment(
    domain: str,
    resolved_ips: set[str],
    scan_id: str,
    session,
    publisher,
) -> int:
    """Persist WHOIS, RDAP, and RIPEstat data with bounded IP fan-out."""
    created = 0
    domain_results = await asyncio.gather(
        _run_tool("whois_lookup", domain, scan_id, session, publisher),
        _run_tool("rdap_lookup", domain, scan_id, session, publisher),
    )
    for findings in domain_results:
        created += await persist_findings(session, scan_id, findings)

    for index, ip in enumerate(sorted(resolved_ips)):
        collectors = [
            _run_tool("whois_lookup", ip, scan_id, session, publisher)
        ]
        if index < MAX_REGISTRY_IP_TARGETS:
            collectors.append(
                _run_tool("rdap_lookup", ip, scan_id, session, publisher)
            )
            collectors.append(
                _run_tool("ripestat", ip, scan_id, session, publisher)
            )
        ip_results = await asyncio.gather(*collectors)
        for findings in ip_results:
            created += await persist_findings(session, scan_id, findings)
    return created


async def run_domain_scan(
    domain: str, scan_id: str, session, publisher,
    free_only: bool = True,
    scan_mode: str = "validated",
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
    resolved_hosts: dict[str, list[str]] = {}
    scan = await session.get(Scan, scan_id)
    evaluator = ScopeEvaluator(
        scan.scope_manifest if scan else None,
        target_type="domain",
        target=domain,
    )
    root_scope = evaluator.evaluate_hostname(domain)

    await upsert_asset(
        session,
        scan_id=scan_id,
        asset_type="DOMAIN",
        value=domain,
        state="CANDIDATE",
        source_module="scan_target",
        in_scope=root_scope.allowed,
        scope_reason=root_scope.reason,
    )

    async def record_candidates(findings: list[dict]) -> None:
        for finding in findings:
            if finding.get("entity_type") != "SUBDOMAIN":
                continue
            value = str(finding.get("entity_value", ""))
            if not value:
                continue
            normalized = finding.setdefault("normalized_data", {})
            normalized["asset_state"] = "CANDIDATE"
            normalized["registrable_domain"] = registrable_domain(value)
            decision = evaluator.evaluate_hostname(value)
            normalized["in_scope"] = decision.allowed
            normalized["scope_reason"] = decision.reason
            await upsert_asset(
                session,
                scan_id=scan_id,
                asset_type="DOMAIN" if value == domain else "SUBDOMAIN",
                value=value,
                state="CANDIDATE",
                source_module=finding.get("source_module"),
                in_scope=decision.allowed,
                scope_reason=decision.reason,
            )

    # 1a. crt.sh — SSL certificate transparency logs
    crtsh_findings = _filter_discovery_findings(
        await _run_tool("crtsh", domain, scan_id, session, publisher), domain
    )
    await record_candidates(crtsh_findings)
    total_findings += await persist_findings(session, scan_id, crtsh_findings)
    for f in crtsh_findings:
        ev = f.get("entity_value", "")
        if ev:
            all_subdomains.add(ev)

    # 1b. subfinder — passive subdomain discovery
    subfinder_findings = _filter_discovery_findings(
        await _run_tool("subfinder", domain, scan_id, session, publisher), domain
    )
    await record_candidates(subfinder_findings)
    total_findings += await persist_findings(session, scan_id, subfinder_findings)
    for f in subfinder_findings:
        ev = f.get("entity_value", "")
        if ev:
            all_subdomains.add(ev)

    # 1c. theHarvester — email/subdomain/IP from search engines
    theharvester_findings = _filter_discovery_findings(
        await _run_tool(
            "theharvester", domain, scan_id, session, publisher,
            theharvester_free_only=free_only,
        ),
        domain,
    )
    await record_candidates(theharvester_findings)
    total_findings += await persist_findings(session, scan_id, theharvester_findings)
    for f in theharvester_findings:
        etype = f.get("entity_type", "")
        ev = f.get("entity_value", "")
        if etype == "SUBDOMAIN" and ev:
            all_subdomains.add(ev)
        # theHarvester also returns unlinked IPs from search results. Persist
        # those as evidence, but do not fan out into network enrichment until
        # our own DNS resolver verifies an association with this target.

    # Common Crawl provides passive historical URLs and can reveal candidate
    # subdomains. It performs one bounded, rate-limited latest-index query.
    common_crawl_findings = _filter_discovery_findings(
        await _run_tool("common_crawl", domain, scan_id, session, publisher),
        domain,
    )
    await record_candidates(common_crawl_findings)
    total_findings += await persist_findings(
        session, scan_id, common_crawl_findings
    )
    for finding in common_crawl_findings:
        if finding.get("entity_type") == "SUBDOMAIN":
            value = str(finding.get("entity_value", ""))
            if value:
                all_subdomains.add(value)

    # Assess the root domain once. This is recursive-DNS-only and remains
    # available in passive mode; it does not connect to mail servers or fetch
    # the MTA-STS HTTPS policy body.
    posture_findings = await _run_tool(
        "dns_email_posture", domain, scan_id, session, publisher
    )
    total_findings += await persist_findings(
        session, scan_id, posture_findings
    )

    if scan_mode == "passive":
        await publisher.publish(scan_id, "validation_skipped", {
            "reason": "passive_mode",
            "candidates": len(all_subdomains) + 1,
        })
        total_findings += await _run_registration_enrichment(
            domain, resolved_ips, scan_id, session, publisher
        )
        wayback_findings = await _run_tool(
            "wayback_machine", domain, scan_id, session, publisher
        )
        total_findings += await persist_findings(
            session, scan_id, wayback_findings
        )
        return all_subdomains, resolved_ips, total_findings

    # 1d. Detect wildcard DNS before resolving the bounded candidate set.
    wildcard = await detect_wildcard_dns(domain)
    await publisher.publish(scan_id, "wildcard_dns_checked", {
        "domain": domain,
        "detected": wildcard.detected,
        "responsive_samples": wildcard.responsive_samples,
    })

    # Resolve candidates (bounded to 200 subdomains).
    from app.services.vectors.infrastructure import MAX_DNS_SUBDOMAINS, DNS_CONCURRENCY
    subdomains_to_resolve = [
        hostname for hostname in _bounded_dns_candidates(
            domain, all_subdomains, MAX_DNS_SUBDOMAINS
        ) if evaluator.evaluate_hostname(hostname).allowed
    ]

    dns_findings_all = []
    semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

    async def resolve_one(subdomain):
        async with semaphore:
            return await _run_tool("dns_resolver", subdomain, scan_id, session, publisher)

    dns_tasks = [asyncio.create_task(resolve_one(s)) for s in subdomains_to_resolve]
    dns_results = await asyncio.gather(*dns_tasks, return_exceptions=True)
    for result in dns_results:
        if isinstance(result, list):
            dns_findings_all.extend(result)

    for f in dns_findings_all:
        hostname = str(f.get("entity_value", ""))
        normalized = f.setdefault("normalized_data", {})
        wildcard_suspected = hostname != domain and matches_wildcard(f, wildcard)
        normalized["asset_state"] = "CANDIDATE" if wildcard_suspected else "RESOLVED"
        normalized["wildcard_suspected"] = wildcard_suspected
        if wildcard_suspected:
            from app.services.dns_validation import finding_dns_signature
            signature = finding_dns_signature(f)
            normalized["wildcard_evidence"] = {
                "responsive_samples": wildcard.responsive_samples,
                "matched_signatures": sorted(signature & wildcard.signatures),
            }
        normalized["registrable_domain"] = registrable_domain(hostname)
        host_scope = evaluator.evaluate_hostname(hostname)
        normalized["in_scope"] = host_scope.allowed
        normalized["scope_reason"] = host_scope.reason
        ips = normalized.get("resolved_ips", [])
        await upsert_asset(
            session,
            scan_id=scan_id,
            asset_type="DOMAIN" if hostname == domain else "SUBDOMAIN",
            value=hostname,
            state="CANDIDATE" if wildcard_suspected else "RESOLVED",
            source_module="dns_resolver",
            wildcard_suspected=wildcard_suspected,
            dns_records=normalized.get("dns_records", {}),
            resolved_ips=ips,
            in_scope=host_scope.allowed,
            scope_reason=host_scope.reason,
        )
        if wildcard_suspected:
            continue
        public_ips = [ip for ip in ips if _public_ip(ip)]
        if public_ips:
            resolved_hosts[hostname] = public_ips
        for ip in ips:
            if _public_ip(ip):
                resolved_ips.add(ip)
                await upsert_asset(
                    session,
                    scan_id=scan_id,
                    asset_type="IP_ADDRESS",
                    value=ip,
                    state="RESOLVED",
                    source_module="dns_resolver",
                    in_scope=host_scope.allowed,
                    scope_reason="resolved from allowed hostname" if host_scope.allowed else host_scope.reason,
                )

    total_findings += await persist_findings(session, scan_id, dns_findings_all)

    # Low-impact HTTP validation for clean, publicly resolved hosts.
    hosts_to_probe = sorted(resolved_hosts)[:MAX_HTTP_PROBES]
    probe_semaphore = asyncio.Semaphore(HTTP_PROBE_CONCURRENCY)
    await publisher.publish(scan_id, "http_validation_started", {
        "hosts": len(hosts_to_probe),
        "limit": MAX_HTTP_PROBES,
    })

    async def probe_one(hostname: str):
        async with probe_semaphore:
            return hostname, await probe_http(
                hostname, resolved_hosts[hostname]
            )

    probe_results = await asyncio.gather(
        *(probe_one(hostname) for hostname in hosts_to_probe),
        return_exceptions=True,
    )
    live_findings: list[dict] = []
    for result in probe_results:
        if isinstance(result, Exception):
            logger.debug("HTTP validation failed: %s", result)
            continue
        hostname, metadata = result
        if not metadata:
            continue
        await upsert_asset(
            session,
            scan_id=scan_id,
            asset_type="DOMAIN" if hostname == domain else "SUBDOMAIN",
            value=hostname,
            state="LIVE",
            source_module="http_probe",
            http_metadata=metadata,
            in_scope=True,
            scope_reason="matches allowed domain",
        )
        url_scope = evaluator.evaluate_url(metadata["url"])
        await upsert_asset(
            session,
            scan_id=scan_id,
            asset_type="URL",
            value=metadata["url"],
            state="LIVE",
            source_module="http_probe",
            http_metadata=metadata,
            in_scope=url_scope.allowed,
            scope_reason=url_scope.reason,
        )
        live_findings.append({
            "vector_type": "INFRASTRUCTURE",
            "entity_type": "URL",
            "entity_value": metadata["url"],
            "severity": "INFO",
            "confidence": 1.0,
            "source_module": "http_probe",
            "raw_data": metadata,
            "normalized_data": {
                **metadata,
                "hostname": hostname,
                "asset_state": "LIVE",
            },
            "tags": ["live", "http-validated"],
        })
    total_findings += await persist_findings(
        session, scan_id, live_findings
    )
    await publisher.publish(scan_id, "http_validation_completed", {
        "probed": len(hosts_to_probe),
        "live": len(live_findings),
    })

    # Enrich only URLs that passed DNS and HTTP validation. This keeps the
    # web-surface fan-out disconnected from unverified discovery candidates.
    live_urls = [
        finding["entity_value"]
        for finding in live_findings[:MAX_WEB_SURFACE_TARGETS]
    ]
    surface_semaphore = asyncio.Semaphore(WEB_SURFACE_CONCURRENCY)

    async def inspect_surface(url: str):
        async with surface_semaphore:
            return await _run_tool(
                "web_surface", url, scan_id, session, publisher
            )

    surface_results = await asyncio.gather(
        *(inspect_surface(url) for url in live_urls),
        return_exceptions=True,
    )
    surface_findings: list[dict] = []
    for result in surface_results:
        if isinstance(result, list):
            surface_findings.extend(result)
    total_findings += await persist_findings(
        session, scan_id, surface_findings
    )
    await publisher.publish(scan_id, "web_surface_completed", {
        "origins": len(live_urls),
        "findings": len(surface_findings),
    })

    # Wayback is third-party/passive and runs once for the root domain rather
    # than once per live subdomain.
    wayback_findings = await _run_tool(
        "wayback_machine", domain, scan_id, session, publisher
    )
    total_findings += await persist_findings(
        session, scan_id, wayback_findings
    )

    # 1e. Shodan InternetDB — free port/service lookup per IP
    for ip in sorted(resolved_ips):
        shodan_findings = await _run_tool("shodan_internetdb", ip, scan_id, session, publisher)
        total_findings += await persist_findings(session, scan_id, shodan_findings)

    # 1f. Registration and routing enrichment via WHOIS, RDAP, and RIPEstat.
    total_findings += await _run_registration_enrichment(
        domain, resolved_ips, scan_id, session, publisher
    )

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
            "scan_mode": scan.scan_mode,
            "phases": ["INFRASTRUCTURE"],
        })

        total_findings = 0

        try:
            phase_tools = ["crtsh", "subfinder", "theharvester", "common_crawl", "dns_email_posture"]
            if scan.scan_mode != "passive":
                phase_tools.extend([
                    "wildcard_dns", "dns_resolver", "http_probe",
                    "web_surface", "shodan_internetdb",
                ])
            phase_tools.extend(["wayback_machine", "whois_lookup", "rdap_lookup", "ripestat"])
            await publisher.publish(scan_id, "phase_started", {
                "phase": "INFRASTRUCTURE",
                "phase_index": 1,
                "tools": phase_tools,
            })

            all_subdomains, resolved_ips, tool_findings = await run_domain_scan(
                scan.target_domain, scan_id, session, publisher, free_only=True,
                scan_mode=scan.scan_mode,
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
