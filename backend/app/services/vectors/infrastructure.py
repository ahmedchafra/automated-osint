"""INFRASTRUCTURE vector strategy.

Pipeline: crt.sh → subfinder → DNS resolver → Shodan InternetDB.
The set of resolved IPs is captured in `ctx.resolved_ips` for the
SERVICES vector to consume without re-running DNS.

DNS resolution is bounded: max 200 subdomains, 10 concurrent DNS queries.
Large crt.sh responses (10k+ certs for domains like github.com) are truncated
to the first 200 to prevent the scan from hanging.
"""
from __future__ import annotations

import asyncio

from collectors.registry import registry

from app.services.asset_service import registrable_domain, upsert_asset
from app.services.discovery import is_public_ip
from app.services.dns_validation import (
    detect_wildcard_dns,
    finding_dns_signature,
    matches_wildcard,
)
from app.services.http_validation import (
    HTTP_PROBE_CONCURRENCY,
    MAX_HTTP_PROBES,
    probe_http,
)
from app.services.scope import ScopeEvaluator
from app.services.vectors.context import VectorContext
from app.services.discovery import process_discovery_findings

MAX_DNS_SUBDOMAINS = 200
DNS_CONCURRENCY = 10
MAX_REGISTRY_IP_TARGETS = 25
MAX_WEB_SURFACE_TARGETS = 25
WEB_SURFACE_CONCURRENCY = 5


async def _resolve_one(dns, subdomain: str, ctx: VectorContext) -> list[dict]:
    """Resolve a single subdomain and return findings (without persisting)."""
    dns_findings = await dns.execute(subdomain)
    if dns_findings:
        for finding in dns_findings:
            for ip in finding.get("normalized_data", {}).get("resolved_ips", []):
                if is_public_ip(str(ip)):
                    ctx.resolved_ips.add(str(ip))
    return dns_findings


async def run(ctx: VectorContext) -> None:
    target = ctx.target_domain
    evaluator = ScopeEvaluator(
        ctx.scope_manifest, target_type=ctx.target_type, target=target
    )
    target_scope = evaluator.evaluate_hostname(target)
    await upsert_asset(
        ctx.db,
        scan_id=ctx.scan_id,
        asset_type="DOMAIN",
        value=target,
        state="CANDIDATE",
        source_module="scan_target",
        in_scope=target_scope.allowed,
        scope_reason=target_scope.reason,
    )

    async def record_candidates(findings: list[dict]) -> None:
        for finding in findings:
            if finding.get("entity_type") != "SUBDOMAIN":
                continue
            value = str(finding.get("entity_value", "")).strip()
            if not value:
                continue
            decision = evaluator.evaluate_hostname(value)
            normalized = finding.setdefault("normalized_data", {})
            normalized.update({
                "asset_state": "CANDIDATE",
                "registrable_domain": registrable_domain(value),
                "in_scope": decision.allowed,
                "scope_reason": decision.reason,
            })
            await upsert_asset(
                ctx.db,
                scan_id=ctx.scan_id,
                asset_type="DOMAIN" if value == target else "SUBDOMAIN",
                value=value,
                state="CANDIDATE",
                source_module=finding.get("source_module"),
                in_scope=decision.allowed,
                scope_reason=decision.reason,
            )

    # 1. crt.sh subdomain enumeration
    crtsh = registry.get_collector("crtsh")()
    sub_findings = process_discovery_findings(
        await crtsh.execute(target), root_domain=target
    ).findings
    if sub_findings:
        await record_candidates(sub_findings)
        await ctx.persist(sub_findings)
        await ctx.publish(
            "vector_completed",
            vector_type="INFRASTRUCTURE",
            stage="crtsh",
            collected=len(sub_findings),
            findings_created=ctx.findings_created,
        )

    # 2. Subfinder (optional binary on PATH; returns [] when absent)
    subfinder = registry.get_collector("subfinder")()
    subfinder_findings = process_discovery_findings(
        await subfinder.execute(target), root_domain=target
    ).findings
    if subfinder_findings:
        await record_candidates(subfinder_findings)
        await ctx.persist(subfinder_findings)
        await ctx.publish(
            "vector_completed",
            vector_type="INFRASTRUCTURE",
            stage="subfinder",
            collected=len(subfinder_findings),
            findings_created=ctx.findings_created,
        )

    # 3. Common Crawl historical URLs and candidate subdomains.
    common_crawl = registry.get_collector("common_crawl")()
    common_crawl_findings = process_discovery_findings(
        await common_crawl.execute(target), root_domain=target
    ).findings
    if common_crawl_findings:
        await record_candidates(common_crawl_findings)
        await ctx.persist(common_crawl_findings)
        await ctx.publish(
            "vector_completed",
            vector_type="INFRASTRUCTURE",
            stage="common_crawl",
            collected=len(common_crawl_findings),
            findings_created=ctx.findings_created,
        )

    # Wayback is passive and runs once for the apex rather than once per
    # discovered host.
    wayback = registry.get_collector("wayback_machine")()
    wayback_findings = await wayback.execute(target)
    if wayback_findings:
        await ctx.persist(wayback_findings)

    subdomains = {target}
    for finding in (
        list(sub_findings) + list(subfinder_findings) + list(common_crawl_findings)
    ):
        if finding.get("entity_type") == "SUBDOMAIN":
            subdomains.add(finding["entity_value"])

    # Passive mode records third-party discovery evidence as candidates but
    # deliberately avoids direct DNS and HTTP interaction with the target.
    if ctx.scan_mode == "passive":
        rdap = registry.get_collector("rdap_lookup")()
        domain_findings = await rdap.execute(target)
        if domain_findings:
            await ctx.persist(domain_findings)
        await ctx.commit()
        await ctx.publish(
            "validation_skipped",
            vector_type="INFRASTRUCTURE",
            reason="passive_mode",
            candidates=len(subdomains),
            findings_created=ctx.findings_created,
        )
        return

    # 4. Root-domain DNS and email security posture. Recursive DNS only;
    # no SMTP connection or MTA-STS policy fetch is made here. It belongs to
    # validated/active profiles because even recursive DNS ultimately queries
    # the target's authoritative infrastructure.
    posture = registry.get_collector("dns_email_posture")()
    posture_findings = await posture.execute(target)
    if posture_findings:
        await ctx.persist(posture_findings)
        await ctx.publish(
            "vector_completed",
            vector_type="INFRASTRUCTURE",
            stage="dns_email_posture",
            collected=len(posture_findings),
            findings_created=ctx.findings_created,
        )

    # 5. DNS resolution for the union of base domain + discovered subdomains.
    #    Bounded to MAX_DNS_SUBDOMAINS with DNS_CONCURRENCY parallel workers.
    ordered_subdomains = [target, *sorted(
        (value for value in subdomains if value != target),
        key=lambda value: (value.count("."), len(value), value),
    )[: MAX_DNS_SUBDOMAINS - 1]]

    wildcard = await detect_wildcard_dns(target)
    await ctx.publish(
        "wildcard_dns_checked",
        domain=target,
        detected=wildcard.detected,
        responsive_samples=wildcard.responsive_samples,
    )

    dns = registry.get_collector("dns_resolver")()
    dns_count = 0
    semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

    async def _bounded_resolve(subdomain):
        async with semaphore:
            return subdomain, await _resolve_one(dns, subdomain, ctx)

    tasks = [asyncio.create_task(_bounded_resolve(s)) for s in ordered_subdomains]
    all_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Persist sequentially to avoid concurrent flush() on the same session
    dns_count = 0
    resolved_hosts: dict[str, list[str]] = {}
    for result in all_results:
        if isinstance(result, Exception):
            continue
        hostname, findings = result
        if not findings:
            continue
        for finding in findings:
            normalized = finding.setdefault("normalized_data", {})
            wildcard_suspected = hostname != target and matches_wildcard(
                finding, wildcard
            )
            state = "CANDIDATE" if wildcard_suspected else "RESOLVED"
            decision = evaluator.evaluate_hostname(hostname)
            normalized.update({
                "asset_state": state,
                "wildcard_suspected": wildcard_suspected,
                "registrable_domain": registrable_domain(hostname),
                "in_scope": decision.allowed,
                "scope_reason": decision.reason,
            })
            if wildcard_suspected:
                normalized["wildcard_evidence"] = {
                    "responsive_samples": wildcard.responsive_samples,
                    "matched_signatures": sorted(
                        finding_dns_signature(finding) & wildcard.signatures
                    ),
                }
            ips = [
                str(ip) for ip in normalized.get("resolved_ips", [])
                if is_public_ip(str(ip))
            ]
            await upsert_asset(
                ctx.db,
                scan_id=ctx.scan_id,
                asset_type="DOMAIN" if hostname == target else "SUBDOMAIN",
                value=hostname,
                state=state,
                source_module="dns_resolver",
                in_scope=decision.allowed,
                scope_reason=decision.reason,
                wildcard_suspected=wildcard_suspected,
                dns_records=normalized.get("dns_records", {}),
                resolved_ips=ips,
            )
            if not wildcard_suspected and ips:
                resolved_hosts[hostname] = ips
                for ip in ips:
                    ip_scope = evaluator.evaluate_ip(
                        ip, derived_from_allowed_host=decision.allowed
                    )
                    await upsert_asset(
                        ctx.db,
                        scan_id=ctx.scan_id,
                        asset_type="IP_ADDRESS",
                        value=ip,
                        state="RESOLVED",
                        source_module="dns_resolver",
                        in_scope=ip_scope.allowed,
                        scope_reason=ip_scope.reason,
                    )
        await ctx.persist(findings)
        dns_count += len(findings)

    if ctx.resolved_ips:
        for ip in sorted(ctx.resolved_ips):
            await ctx.persist_ip(ip)
    await ctx.commit()

    await ctx.publish(
        "vector_completed",
        vector_type="INFRASTRUCTURE",
        stage="dns",
        collected=dns_count,
        unique_ips=len(ctx.resolved_ips),
        findings_created=ctx.findings_created,
    )

    # Low-impact liveness validation: a single HEAD, no redirect following,
    # and only for hosts whose DNS answers were verified as public.
    probe_semaphore = asyncio.Semaphore(HTTP_PROBE_CONCURRENCY)

    async def _bounded_probe(hostname: str):
        async with probe_semaphore:
            return hostname, await probe_http(hostname, resolved_hosts[hostname])

    probe_results = await asyncio.gather(
        *(
            _bounded_probe(hostname)
            for hostname in sorted(resolved_hosts)[:MAX_HTTP_PROBES]
        ),
        return_exceptions=True,
    )
    live_urls: list[str] = []
    live_findings: list[dict] = []
    for result in probe_results:
        if isinstance(result, Exception):
            continue
        hostname, metadata = result
        if not metadata:
            continue
        decision = evaluator.evaluate_hostname(hostname)
        await upsert_asset(
            ctx.db,
            scan_id=ctx.scan_id,
            asset_type="DOMAIN" if hostname == target else "SUBDOMAIN",
            value=hostname,
            state="LIVE",
            source_module="http_probe",
            http_metadata=metadata,
            in_scope=decision.allowed,
            scope_reason=decision.reason,
        )
        url = str(metadata["url"])
        url_scope = evaluator.evaluate_url(url)
        await upsert_asset(
            ctx.db,
            scan_id=ctx.scan_id,
            asset_type="URL",
            value=url,
            state="LIVE",
            source_module="http_probe",
            http_metadata=metadata,
            in_scope=url_scope.allowed,
            scope_reason=url_scope.reason,
        )
        if url_scope.allowed:
            live_urls.append(url)
        live_findings.append({
            "vector_type": "INFRASTRUCTURE",
            "entity_type": "URL",
            "entity_value": url,
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
    if live_findings:
        await ctx.persist(live_findings)
    await ctx.commit()
    await ctx.publish(
        "http_validation_completed",
        probed=min(len(resolved_hosts), MAX_HTTP_PROBES),
        live=len(live_findings),
        findings_created=ctx.findings_created,
    )

    # Run the web-surface collector only on verified, in-scope live URLs.
    surface_semaphore = asyncio.Semaphore(WEB_SURFACE_CONCURRENCY)

    async def _surface(url: str) -> list[dict]:
        async with surface_semaphore:
            return await registry.get_collector("web_surface")().execute(url)

    surface_results = await asyncio.gather(
        *(_surface(url) for url in live_urls[:MAX_WEB_SURFACE_TARGETS]),
        return_exceptions=True,
    )
    surface_findings = [
        finding
        for result in surface_results
        if isinstance(result, list)
        for finding in result
    ]
    if surface_findings:
        await ctx.persist(surface_findings)
        await ctx.commit()
    await ctx.publish(
        "web_surface_completed",
        origins=min(len(live_urls), MAX_WEB_SURFACE_TARGETS),
        findings=len(surface_findings),
        findings_created=ctx.findings_created,
    )

    # 6. Shodan InternetDB (free) + Shodan Host (paid API) enrichment
    if ctx.resolved_ips:
        from app.config import settings
        shodan = registry.get_collector("shodan_internetdb")()
        shodan_host = registry.get_collector("shodan_host")()
        shodan_count = 0
        for ip in sorted(ctx.resolved_ips):
            ip_findings = await shodan.execute(ip)
            shodan_count += len(ip_findings)
            if ip_findings:
                await ctx.persist(ip_findings)
            if settings.SHODAN_API_KEY:
                host_findings = await shodan_host.execute(ip)
                shodan_count += len(host_findings)
                if host_findings:
                    await ctx.persist(host_findings)
        await ctx.commit()
        await ctx.publish(
            "vector_completed",
            vector_type="INFRASTRUCTURE",
            stage="shodan_enrichment",
            collected=shodan_count,
            findings_created=ctx.findings_created,
        )

    # 7. Standards-based registration data. RDAP is passive and free; keep
    # IP fan-out bounded to avoid excessive traffic to regional registries.
    rdap = registry.get_collector("rdap_lookup")()
    ripestat = registry.get_collector("ripestat")()
    rdap_count = 0
    domain_findings = await rdap.execute(target)
    if domain_findings:
        await ctx.persist(domain_findings)
        rdap_count += len(domain_findings)
    for ip in sorted(ctx.resolved_ips)[:MAX_REGISTRY_IP_TARGETS]:
        results = await asyncio.gather(rdap.execute(ip), ripestat.execute(ip))
        for ip_findings in results:
            if ip_findings:
                await ctx.persist(ip_findings)
                rdap_count += len(ip_findings)
    await ctx.commit()
    await ctx.publish(
        "vector_completed",
        vector_type="INFRASTRUCTURE",
        stage="registry_routing_enrichment",
        collected=rdap_count,
        findings_created=ctx.findings_created,
    )
