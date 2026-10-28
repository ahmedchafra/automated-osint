"""IDENTITY vector strategy.

Pipeline:
  1. Hunter.io domain search → harvest corporate emails
  2. Subdomain email construction → build candidate emails from discovered
     subdomains (only for subdomains with MX records to avoid API waste)
  3. Per-email XposedOrNot breach lookup → checks breach & paste databases
  4. Per-email h8mail breach/reputation check → emailrep.io + scylla.sh
  5. Per-email Holehe → checks which platforms the email is registered on
  6. GitHub secrets scan → search public repos for leaked secrets (API keys, tokens)

XposedOrNot, h8mail, and Holehe are free, no API key required.
Hunter.io requires HUNTER_API_KEY (already configured).
GitHub secrets requires GITHUB_TOKEN (free, read-only).
"""
from __future__ import annotations

import asyncio
import dns.asyncresolver

from collectors.registry import registry

from app.services.vectors.context import VectorContext

EMAIL_PREFIXES = ["info", "admin", "contact", "webmaster", "support", "office", "help", "hr", "it", "web"]


async def _construct_subdomain_emails(ctx: VectorContext) -> set[str]:
    """Build candidate emails from discovered subdomains.

    To avoid draining free APIs, only construct emails for subdomains
    that have MX records (meaning they actually accept email).
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.timeout = 2.0
    resolver.lifetime = 3.0

    subdomains = set()
    for finding in await ctx.findings_of("SUBDOMAIN"):
        subdomains.add(finding.entity_value)

    candidates: set[str] = set()
    semaphore = asyncio.Semaphore(5)

    async def _check_mx(subdomain):
        async with semaphore:
            try:
                await resolver.resolve(subdomain, "MX")
                return True
            except Exception:
                return False

    mx_results = await asyncio.gather(*[_check_mx(s) for s in subdomains])
    mx_subdomains = {s for s, has_mx in zip(subdomains, mx_results) if has_mx}

    for subdomain in mx_subdomains:
        for prefix in EMAIL_PREFIXES:
            candidates.add(f"{prefix}@{subdomain}")

    return candidates


async def run(ctx: VectorContext) -> None:
    # ── Stage 1: Hunter.io domain email discovery ────────────────────────
    hunter = registry.get_collector("hunter_domain")()
    email_findings = await hunter.execute(ctx.target_domain)
    if email_findings:
        await ctx.persist(email_findings)
        await ctx.commit()

    emails = {
        finding["entity_value"]
        for finding in email_findings
        if finding.get("entity_value")
    }

    # MX resolution interacts with target-controlled DNS, so passive scans use
    # only addresses returned by third-party sources such as Hunter.
    constructed = (
        await _construct_subdomain_emails(ctx)
        if ctx.scan_mode != "passive"
        else set()
    )
    emails.update(constructed)

    # ── Stage 2: XposedOrNot breach lookup per email ─────────────────────
    # XposedOrNot shares a per-IP rate limit across all requests in a
    # time window. Once we hit it, consecutive requests are 429'd until
    # enough requests "fall off" the window. Subspaceconsecutive empty
    # → sleep 10 minutes to let the window drain before continuing.
    xposed = registry.get_collector("xposedornot_breach")()
    breach_count = 0
    for email in sorted(emails):
        breach_findings = await xposed.execute(email)
        if breach_findings:
            breach_count += len(breach_findings)
            await ctx.persist(breach_findings)
    await ctx.commit()

    # ── Stage 2b: h8mail breach/reputation check per email ────────────────
    # h8mail uses emailrep.io + scylla.sh — different sources than
    # XposedOrNot, so running both gives better coverage. No API key needed.
    h8mail_collector = registry.get_collector("h8mail")()
    h8mail_count = 0
    for email in sorted(emails):
        h8mail_findings = await h8mail_collector.execute(email)
        h8mail_count += len(h8mail_findings)
        if h8mail_findings:
            await ctx.persist(h8mail_findings)
    await ctx.commit()

    # ── Stage 3: Holehe platform registration check per email ─────────────
    platform_count = 0
    if ctx.scan_mode != "passive":
        holehe = registry.get_collector("holehe")()
        for email in sorted(emails):
            platform_findings = await holehe.execute(email)
            platform_count += len(platform_findings)
            if platform_findings:
                await ctx.persist(platform_findings)
    await ctx.commit()

    # ── Stage 4: GitHub leaked secrets scan ───────────────────────────────
    github = registry.get_collector("github_secrets")()
    gh_findings = await github.execute(ctx.target_domain)
    gh_count = len(gh_findings)
    if gh_findings:
        await ctx.persist(gh_findings)
    await ctx.commit()

    await ctx.publish(
        "vector_completed",
        vector_type="IDENTITY",
        stage="identity_enrichment",
        emails=len(emails),
        breaches=breach_count,
        h8mail_findings=h8mail_count,
        platforms=platform_count,
        github_secrets=gh_count,
        findings_created=ctx.findings_created,
    )
