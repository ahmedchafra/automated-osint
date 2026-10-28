"""SERVICES vector strategy.

Pipeline: per-IP Shodan Host + Censys Host → extract CPEs → NVD CVE
match → CISA KEV lookup for each discovered CVE.

Reuses `ctx.resolved_ips` from the infrastructure vector when
available; falls back to running DNS for the apex domain when
INFRASTRUCTURE was not part of the requested vector set.
"""
from __future__ import annotations

from collectors.registry import registry

from app.services.vectors.context import VectorContext


async def _ensure_ips(ctx: VectorContext) -> set[str]:
    """Make sure `ctx.resolved_ips` is populated before services runs."""
    if ctx.resolved_ips:
        return ctx.resolved_ips

    # INFRASTRUCTURE vector was skipped — resolve the apex domain directly.
    dns = registry.get_collector("dns_resolver")()
    dns_findings = await dns.execute(ctx.target_domain)
    if dns_findings:
        await ctx.persist(dns_findings)
    for finding in dns_findings:
        for ip in finding.get("normalized_data", {}).get("resolved_ips", []):
            ctx.resolved_ips.add(ip)
    for ip in sorted(ctx.resolved_ips):
        await ctx.persist_ip(ip)
    await ctx.commit()
    return ctx.resolved_ips


async def run(ctx: VectorContext) -> None:
    if ctx.scan_mode == "passive":
        await ctx.publish(
            "validation_skipped",
            vector_type="SERVICES",
            reason="passive_mode",
            findings_created=ctx.findings_created,
        )
        return
    ips = await _ensure_ips(ctx)

    # 1. Service-level enumeration (Shodan Host, Censys Host).
    collected = 0
    for ip in ips:
        for name in ("shodan_host", "censys_host"):
            collector = registry.get_collector(name)()
            findings = await collector.execute(ip)
            collected += len(findings)
            if findings:
                await ctx.persist(findings)

    # 2. NVD CVE matching — extract CPE strings from PORT_SERVICE findings.
    cpe_values: set[str] = set()
    for finding in await ctx.findings_of("PORT_SERVICE"):
        nd = finding.normalized_data or {}
        # Check multiple CPE field names used by different collectors
        for key in ("cpes", "cpe23", "cpe"):
            cpes = nd.get(key, [])
            if isinstance(cpes, list):
                for cpe in cpes:
                    if isinstance(cpe, str) and cpe.strip():
                        cpe_values.add(cpe.strip())

    # Also check HOST_METADATA for CPEs (Censys stores them there)
    for finding in await ctx.findings_of("HOST_METADATA"):
        cpes = (finding.normalized_data or {}).get("cpes", [])
        if isinstance(cpes, list):
            for cpe in cpes:
                if isinstance(cpe, str) and cpe.strip():
                    cpe_values.add(cpe.strip())

    if cpe_values:
        nvd = registry.get_collector("nvd_cve")
        for cpe in cpe_values:
            for finding in await nvd().execute(cpe):
                await ctx.persist([finding])
    await ctx.commit()

    # 3. CISA KEV — which of our CVEs are known-exploited?
    kev_collector = registry.get_collector("cisa_kev")()
    kev_count = 0
    for finding in await ctx.findings_of("CVE"):
        if not finding.entity_value:
            continue
        kev_findings = await kev_collector.execute(finding.entity_value)
        kev_count += len(kev_findings)
        if kev_findings:
            await ctx.persist(kev_findings)
    await ctx.commit()

    await ctx.publish(
        "vector_completed",
        vector_type="SERVICES",
        stage="service_enrichment",
        ips=len(ips),
        collected=collected + kev_count,
        findings_created=ctx.findings_created,
    )
