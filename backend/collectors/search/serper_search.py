"""Serper.dev Google SERP collector with expanded dork templates.

During a unified scan this collector runs a battery of dork queries
against the target domain to find exposed sensitive files, config leaks,
admin panels, and other interesting resources via Serper.dev.

Free-tier limit: 2500 queries/month. Each domain triggers up to 5 queries.
"""
from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse
from typing import Any, Dict, List

import httpx

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata

logger = logging.getLogger("osint.serper_search")


class SerperSearchCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="serper_search",
        vector="SEARCH",
        description="Serper.dev Google SERP search for exposed sensitive files",
        passive=True,
        requires_api_key=True,
        api_key_env="SERPER_API_KEY",
    )

    # ── Dork templates ──────────────────────────────────────────────────
    # Each template is a Python format string where {target} is replaced
    # with the domain being scanned. Add new patterns here to auto-expand
    # the search battery.
    DORKS: list[str] = [
        # Sensitive file types
        "site:{target} (filetype:env OR filetype:sql OR filetype:bak OR filetype:log)",
        "site:{target} (filetype:conf OR filetype:yml OR filetype:yaml OR filetype:xml OR filetype:json)",
        "site:{target} (filetype:pdf OR filetype:doc OR filetype:docx OR filetype:xls OR filetype:xlsx) confidential",
        # Admin / login panels
        "site:{target} inurl:admin OR inurl:login OR inurl:dashboard",
        # Version-control / config exposure
        "site:{target} inurl:.git OR inurl:.svn OR inurl:wp-config OR inurl:config.php",
    ]

    _EXPOSED_EXTENSIONS: set[str] = {
        ".env", ".sql", ".bak", ".log", ".conf", ".yml", ".yaml",
        ".xml", ".json", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".csv", ".dump", ".rdp", ".pem", ".key", ".cert", ".pfx",
        ".htpasswd", ".htaccess", ".gitignore", ".terraform",
    }

    TIMEOUT = 60

    @staticmethod
    def _classify_result(link: str) -> str:
        """Return 'EXPOSED_FILE' if the URL ends with a sensitive extension, else 'DORK_RESULT'."""
        try:
            path = urlparse(link).path.lower()
            for ext in SerperSearchCollector._EXPOSED_EXTENSIONS:
                if path.endswith(ext):
                    return "EXPOSED_FILE"
        except Exception:
            pass
        return "DORK_RESULT"

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not settings.SERPER_API_KEY:
            return []

        headers = {"X-API-KEY": settings.SERPER_API_KEY, "Content-Type": "application/json"}
        results: list[dict] = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            for dork_template in self.DORKS:
                query = dork_template.format(target=target)
                try:
                    response = await client.post(
                        "https://google.serper.dev/search",
                        headers=headers,
                        json={"q": query},
                    )
                    if response.status_code == 429:
                        logger.warning("Serper.dev rate limited (429) on query %r — stopping dork battery", query[:60])
                        break
                    response.raise_for_status()
                    data = response.json()
                    for item in data.get("organic", []):
                        link = item.get("link")
                        if not link:
                            continue
                        result_type = self._classify_result(link)
                        results.append({
                            "type": result_type,
                            "query": query,
                            **item,
                        })
                    # Small delay between dorks to be gentle
                    await asyncio.sleep(0.3)
                except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.RequestError) as e:
                    logger.warning("Serper.dev upstream error for query %r: %s", query[:60], e)
                    continue

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        link = raw.get("link")
        raw_type = raw.get("type", "DORK_RESULT")

        if raw_type == "EXPOSED_FILE":
            from urllib.parse import urlparse
            ext = ""
            try:
                ext = urlparse(link).path.split(".")[-1].lower() if link else ""
            except Exception:
                pass
            return {
                "entity_type": "EXPOSED_FILE",
                "entity_value": link,
                "severity": "HIGH",
                "confidence": 0.7,
                "normalized_data": {
                    "title": raw.get("title"),
                    "url": link,
                    "file_type": f".{ext}" if ext else "",
                    "snippet": raw.get("snippet"),
                    "query": raw.get("query"),
                },
            }

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
