"""Check what lookalike findings exist in the DB."""
from app.database import AsyncSessionLocal
from app.models.finding import Finding
from sqlalchemy import select
import asyncio


async def c():
    async with AsyncSessionLocal() as s:
        r = await s.execute(
            select(Finding).where(
                Finding.scan_id == "dc04fead-5841-4057-a088-59fc34221441",
                Finding.entity_type == "LOOKALIKE_DOMAIN",
            ).order_by(Finding.entity_value)
        )
        all_f = r.scalars().all()
        print(f"Total lookalikes: {len(all_f)}")
        for f in all_f:
            nd = f.normalized_data or {}
            ips = nd.get("resolved_ips", [])
            og = nd.get("original_domain", "?")
            print(f"  {f.entity_value:25s} original_domain={og:20s} ips={len(ips)}")


asyncio.run(c())
