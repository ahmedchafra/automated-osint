"""SEARCH vector strategy.

Pipeline:
  Stage 1: Serper.dev Google dorking across the open web
  Stage 2: Telegram channel/group mention monitoring (Telethon)
"""
from __future__ import annotations

from collectors.registry import registry

from app.services.vectors.context import VectorContext


async def run(ctx: VectorContext) -> None:
    # ── Stage 1: Serper web search ─────────────────────────────────────
    serper = registry.get_collector("serper_search")()
    serper_findings = await serper.execute(ctx.target_domain)
    serper_count = len(serper_findings)
    if serper_findings:
        await ctx.persist(serper_findings)
    await ctx.commit()

    # ── Stage 2: dnstwist lookalike domain detection ───────────────────
    dnstwist_findings = []
    if ctx.scan_mode != "passive":
        dnstwist_collector = registry.get_collector("dnstwist")()
        dnstwist_findings = await dnstwist_collector.execute(ctx.target_domain)
    dnstwist_count = len(dnstwist_findings)
    if dnstwist_findings:
        await ctx.persist(dnstwist_findings)
    await ctx.commit()

    # ── Stage 3: Telegram monitoring ───────────────────────────────────
    telegram = registry.get_collector("telegram_monitor")()
    tg_findings = await telegram.execute(ctx.target_domain)
    tg_count = len(tg_findings)
    if tg_findings:
        await ctx.persist(tg_findings)
    await ctx.commit()

    await ctx.publish(
        "vector_completed",
        vector_type="SEARCH",
        stage="serper+dnstwist+telegram",
        collected=serper_count + dnstwist_count + tg_count,
        findings_created=ctx.findings_created,
    )
