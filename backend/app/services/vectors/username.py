"""USERNAME vector strategy.

Pipeline per requested handle:
  1. Maigret → deep search across 3,000+ sites for username profiles
  2. SimpleProfiler → lightweight check of major platforms (fallback)

Maigret requires the `maigret` binary (pip install maigret).
SimpleProfiler is a built-in fallback that needs no external deps.
"""
from __future__ import annotations

from collectors.registry import registry

from app.services.vectors.context import VectorContext


async def run(ctx: VectorContext) -> None:
    usernames = ctx.target_usernames
    if not usernames:
        await ctx.publish(
            "vector_completed",
            vector_type="USERNAME",
            stage="maigret+simple_profiler",
            usernames=0,
            collected=0,
            findings_created=ctx.findings_created,
        )
        return

    maigret = registry.get_collector("maigret")()
    simple = registry.get_collector("simple_username_profiler")()
    collected = 0

    for username in usernames:
        # Primary: Maigret deep search
        findings = await maigret.execute(username)
        collected += len(findings)
        if findings:
            await ctx.persist(findings)

        # Fallback: lightweight check for platforms Maigret might miss
        fallback = await simple.execute(username)
        # Only add fallback results for platforms not already found by Maigret
        maigret_platforms = {f["normalized_data"]["platform"] for f in findings if f.get("normalized_data")}
        for fb in fallback:
            platform = fb.get("normalized_data", {}).get("platform") or fb.get("platform")
            if platform not in maigret_platforms and platform:
                collected += 1
                await ctx.persist([fb])

    await ctx.commit()

    await ctx.publish(
        "vector_completed",
        vector_type="USERNAME",
        stage="maigret+simple_profiler",
        usernames=len(usernames),
        collected=collected,
        findings_created=ctx.findings_created,
    )
