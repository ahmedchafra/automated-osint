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

from app.services.vectors.context import VectorContext

MAX_DNS_SUBDOMAINS = 200
DNS_CONCURRENCY = 10


async def _resolve_one(dns, subdomain: str, ctx: VectorContext) -> list[dict]:
    """Resolve a single subdomain and return findings (without persisting)."""
    dns_findings = await dns.execute(subdomain)
    if dns_findings:
        for finding in dns_findings:
            for ip in finding.get("normalized_data", {}).get("resolved_ips", []):
                ctx.resolved_ips.add(ip)
    return dns_findings


async def run(ctx: VectorContext) -> None:
    target = ctx.target_domain

    # 1. crt.sh subdomain enumeration
    crtsh = registry.get_collector("crtsh")()
    sub_findings = await crtsh.execute(target)
    if sub_findings:
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
    subfinder_findings = await subfinder.execute(target)
    if subfinder_findings:
        await ctx.persist(subfinder_findings)
        await ctx.publish(
            "vector_completed",
            vector_type="INFRASTRUCTURE",
            stage="subfinder",
            collected=len(subfinder_findings),
            findings_created=ctx.findings_created,
        )

    # 3. DNS resolution for the union of base domain + discovered subdomains.
    #    Bounded to MAX_DNS_SUBDOMAINS with DNS_CONCURRENCY parallel workers.
    subdomains = {target}
    for finding in list(sub_findings) + list(subfinder_findings):
        subdomains.add(finding["entity_value"])

    if len(subdomains) > MAX_DNS_SUBDOMAINS:
        subdomains = set(list(subdomains)[:MAX_DNS_SUBDOMAINS])

    dns = registry.get_collector("dns_resolver")()
    dns_count = 0
    semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

    async def _bounded_resolve(subdomain):
        async with semaphore:
            return await _resolve_one(dns, subdomain, ctx)

    tasks = [asyncio.create_task(_bounded_resolve(s)) for s in subdomains]
    all_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Persist sequentially to avoid concurrent flush() on the same session
    dns_count = 0
    for result in all_results:
        if isinstance(result, Exception):
            continue
        if result:
            await ctx.persist(result)
            dns_count += len(result)

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

    # 4. Shodan InternetDB (free) + Shodan Host (paid API) enrichment
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
