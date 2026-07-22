import httpx
from typing import Any, Dict, List

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class SerperDorkSearchCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="serper_dork_search",
        vector="SEARCH",
        description="Serper.dev Google search for arbitrary dork queries",
        passive=True,
        requires_api_key=True,
        api_key_env="SERPER_API_KEY",
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        Execute a Google search via Serper.dev using the provided query string.
        The 'target' parameter should be the complete dork query.
        """
        if not settings.SERPER_API_KEY:
            return []

        headers = {
            "X-API-KEY": settings.SERPER_API_KEY,
            "Content-Type": "application/json",
        }
        payload = {"q": target}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    "https://google.serper.dev/search",
                    headers=headers,
                    json=payload,
                )
                if response.status_code == 429:
                    # Rate limited
                    return []
                response.raise_for_status()
                data = response.json()

            results = []
            for item in data.get("organic", []):
                link = item.get("link")
                if not link:
                    continue
                results.append({
                    "query": target,
                    **item,  # Include title, link, snippet, position, etc.
                })
            return results

        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.RequestError) as e:
            # Treat transient errors as empty results so the task doesn't fail
            name = getattr(self.metadata, "name", self.__class__.__name__)
            print(f"[{name}] upstream error: {e}")
            return []
        except Exception as e:
            name = getattr(self.metadata, "name", self.__class__.__name__)
            print(f"[{name}] unexpected error: {e}")
            return []

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        link = raw.get("link")
        return {
            "entity_type": "DORK_RESULT",
            "entity_value": link,
            "severity": "MEDIUM",
            "confidence": 0.7,
            "normalized_data": {
                "title": raw.get("title"),
                "url": link,
                "snippet": raw.get("snippet"),
                "query": raw.get("query"),
                "position": raw.get("position"),
            },
        }