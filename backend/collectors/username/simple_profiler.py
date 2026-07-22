from typing import Any, Dict, List

import httpx

from collectors.base import BaseCollector, CollectorMetadata


class SimpleUsernameProfilerCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="simple_username_profiler",
        vector="USERNAME",
        description="Lightweight username profile existence checks",
        passive=False,
        requires_api_key=False,
    )

    SITES = {
        "github": "https://github.com/{username}",
        "gitlab": "https://gitlab.com/{username}",
        "reddit": "https://www.reddit.com/user/{username}",
        "x": "https://x.com/{username}",
    }

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        username = target.strip().lstrip("@")
        if not username:
            return []

        headers = {"User-Agent": self.get_random_user_agent()}
        results = []
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            for platform, template in self.SITES.items():
                url = template.format(username=username)
                try:
                    response = await client.get(url, headers=headers)
                except httpx.HTTPError as exc:
                    results.append({"username": username, "platform": platform, "url": url, "found": False, "error": str(exc)})
                    continue

                if response.status_code == 200:
                    results.append({"username": username, "platform": platform, "url": url, "found": True})

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "PROFILE",
            "entity_value": raw["url"],
            "severity": "INFO",
            "confidence": 0.7,
            "normalized_data": {
                "username": raw["username"],
                "platform": raw["platform"],
                "url": raw["url"],
                "found": raw["found"],
            },
        }
