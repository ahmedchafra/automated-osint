"""BuiltWith Free API — web technology profiler.

Fetches the technology stack behind a domain (CMS, CDN, analytics, frameworks,
server software, etc.) via the BuiltWith free-tier API.

Rate limit: 1 request/second (free tier). We enforce this via a module-level
last-request clock so concurrent instances also pace themselves.
"""
import os
import time
import httpx
from typing import List, Dict, Any

from collectors.base import BaseCollector, CollectorMetadata


# Module-level rate limiter — shared across all instances of this collector
_last_request: float = 0.0


def _rate_limit():
    """Ensure at least 1.0 s between consecutive BuiltWith API calls."""
    global _last_request
    now = time.monotonic()
    elapsed = now - _last_request
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)
    _last_request = time.monotonic()


class BuiltWithCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="builtwith",
        vector="SERVICES",
        description="Web technology stack profiling via BuiltWith Free API",
        passive=True,
        requires_api_key=True,
        api_key_env="BUILTWITH_API_KEY",
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_key = os.getenv("BUILTWITH_API_KEY", "")

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not self.api_key:
            print("[builtwith] No BUILTWITH_API_KEY set, skipping")
            return []

        # Strip protocol and path
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

        # Rate limit before firing the request
        _rate_limit()

        url = "https://api.builtwith.com/free1/api.json"
        params = {"KEY": self.api_key, "LOOKUP": target}

        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()

        results: list[dict] = []

        # BuiltWith free API returns:
        # { "domain": str, "first": timestamp, "last": timestamp,
        #   "groups": [ { "name": str, "live": int, "dead": int,
        #       "categories": [ { "name": str, "live": int, "dead": int,
        #         "latest": timestamp, "oldest": timestamp } ] } ] }
        domain = data.get("domain", target)
        for group in data.get("groups", []):
            group_name = group.get("name", "Uncategorized")
            for cat in group.get("categories", []):
                cat_name = cat.get("name", "Unknown")
                results.append({
                    "type": "TECHNOLOGY",
                    "value": f"{cat_name} @ {domain}",
                    "technology": {
                        "domain": domain,
                        "category": cat_name,
                        "group": group_name,
                        "live": cat.get("live", 0),
                        "dead": cat.get("dead", 0),
                        "latest": cat.get("latest", 0),
                        "oldest": cat.get("oldest", 0),
                    },
                })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        tech = raw.get("technology", {})
        return {
            "entity_type": "TECHNOLOGY",
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.8,
            "normalized_data": {
                "domain": tech.get("domain", ""),
                "category": tech.get("category", ""),
                "group": tech.get("group", ""),
                "live": tech.get("live", 0),
                "dead": tech.get("dead", 0),
                "latest_indexed": tech.get("latest", 0),
                "oldest_indexed": tech.get("oldest", 0),
            },
        }
