"""Ahmia .onion search collector.

Uses Ahmia.fi's public search API to find .onion sites mentioning a
target domain or keyword. Ahmia indexes Tor hidden services and exposes
a JSON API that does NOT require Tor to be running on our side — it
returns metadata about indexed .onion URLs.

Optional deep-scraping: if a .onion URL is in the results and Tor is
running locally, we can fetch the page via SOCKS5. Most "did this brand
show up on a leak forum?" questions are answered by the index alone,
so deep scraping is opt-in via the AHMIA_DEEP_SCRAPE env flag.

API: https://ahmia.fi/api/v1/search/?q=<query>&format=json
Docs: https://ahmia.fi/api/v1/docs
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import httpx

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class AhmiaCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="ahmia",
        vector="SEARCH",
        description="Ahmia.fi .onion search (dark web index)",
        passive=True,
        requires_api_key=False,
    )

    BASE_URL = "https://ahmia.fi/api/v1/search"

    # Ahmia rate-limits anonymous requests. Be polite.
    TIMEOUT = 30
    PAGE_SIZE = 50  # Ahmia caps at 100 per page
    MAX_PAGES = 3   # Collect up to 150 results across 3 pages

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Query Ahmia.fi for .onion sites mentioning the target.

        Paginates through MAX_PAGES of results to collect more than the
        default first page. ``target`` may be a domain (e.g. "example.com")
        or a brand keyword (e.g. "acmecorp"). Ahmia does full-text search
        on indexed pages, so a brand keyword will surface forum posts and
        paste mentions even when no .onion literally contains the domain string.
        """
        if not target:
            return []

        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
        }

        results: List[Dict[str, Any]] = []
        seen_onions = set()

        async with httpx.AsyncClient(timeout=self.TIMEOUT, headers=headers) as client:
            for page in range(self.MAX_PAGES):
                params = {
                    "q": target,
                    "format": "json",
                    "page": page,
                }
                try:
                    resp = await client.get(self.BASE_URL, params=params)
                    if resp.status_code != 200:
                        print(f"[ahmia] HTTP {resp.status_code} for {target} (page {page})")
                        break
                    data = resp.json() or {}
                except httpx.HTTPError as e:
                    print(f"[ahmia] upstream error (page {page}): {e}")
                    break
                except Exception as e:
                    print(f"[ahmia] unexpected error (page {page}): {e}")
                    break

                # The result schema (per Ahmia API v1):
                #   [
                #     {
                #       "title": "...",
                #       "id": "<onion url>",
                #       "date": "...",
                #       "description": "...",
                #       "keywords": [...],
                #       "tor": "true"
                #     },
                #     ...
                #   ]
                items = data if isinstance(data, list) else data.get("results", [])
                if not items:
                    break  # No more results

                for item in items:
                    onion_url = item.get("id") or item.get("url")
                    if not onion_url:
                        continue
                    # Defensive: only keep .onion URLs
                    if ".onion" not in onion_url.lower():
                        continue
                    if onion_url in seen_onions:
                        continue
                    seen_onions.add(onion_url)
                    results.append({
                        "kind": "onion_site",
                        "onion_url": onion_url,
                        "title": item.get("title", ""),
                        "description": item.get("description", ""),
                        "date": item.get("date"),
                        "keywords": item.get("keywords", []),
                        "query": target,
                    })

        # Optionally deep-scrape a few .onion pages via Tor SOCKS5
        if settings.AHMIA_DEEP_SCRAPE and results:
            results = await self._deep_scrape(results[:5])

        return results

    async def _deep_scrape(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optionally fetch a few .onion pages via Tor SOCKS5 for richer text.

        Requires:
          - Tor daemon running on 127.0.0.1:9050 (entrypoint.sh starts it)
          - PySocks installed (in requirements.txt)
          - AHMIA_DEEP_SCRAPE=true in the env
        """
        socks_host = "127.0.0.1"
        socks_port = 9050
        try:
            import socket
            # Quick check: is Tor actually listening?
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                if s.connect_ex((socks_host, socks_port)) != 0:
                    print("[ahmia] Tor not reachable on 127.0.0.1:9050, skipping deep scrape")
                    return candidates
        except OSError:
            return candidates

        # SOCKS5 proxy URL for httpx via urllib3's socks support
        proxies = f"socks5h://{socks_host}:{socks_port}"
        try:
            async with httpx.AsyncClient(
                proxy=proxies, timeout=20.0, follow_redirects=True
            ) as client:
                for entry in candidates:
                    url = entry.get("onion_url")
                    if not url:
                        continue
                    try:
                        r = await client.get(url)
                        if r.status_code == 200:
                            # Naively extract visible text length and title —
                            # the analyst can open the URL manually for the rest.
                            text = r.text or ""
                            entry["page_title"] = self._extract_title(text)
                            entry["page_size_bytes"] = len(text)
                    except Exception as e:
                        # One bad onion shouldn't fail the whole batch
                        print(f"[ahmia] deep scrape failed for {url}: {e}")
                        continue
        except Exception as e:
            print(f"[ahmia] could not initialize Tor client: {e}")

        return candidates

    def _extract_title(self, html: str) -> str:
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else ""

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Map Ahmia results to ONION_SITE / DARKWEB_MENTION findings.

        An entry is ONION_SITE if Ahmia returned a valid .onion URL.
        DARKWEB_MENTION is reserved for future use when we have paste
        or forum-post text from a deep scrape.
        """
        onion_url = raw.get("onion_url", "")

        # Use the URL as the entity_value so dedup works on URL string
        return {
            "entity_type": "ONION_SITE",
            "entity_value": onion_url,
            "severity": "MEDIUM",
            "confidence": 0.7,
            "normalized_data": {
                "onion_url": onion_url,
                "title": raw.get("title", ""),
                "description": raw.get("description", ""),
                "date": raw.get("date"),
                "keywords": raw.get("keywords", []),
                "query": raw.get("query", ""),
                "source": "ahmia",
                "deep_scraped": "page_title" in raw,
            },
        }
