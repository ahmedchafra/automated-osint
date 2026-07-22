"""Organization domain discovery collector.

Takes a company/organization name and discovers associated domain names
via search engines and public data sources.

Strategy:
  1. Serper (Google SERP) — search for the company name, extract domains
     from the top organic results.
  2. Whoxy Reverse Whois — registered domains mentioning the org name
     (in a separate collector; merged at the scan level).

Entity types produced:
  - DOMAIN_METADATA: discovered domain associated with the organization

Scoring (stored in details.score, higher = more relevant):
  - +30  domain contains the org name (e.g., tesla.com for "Tesla")
  - +20  from Knowledge Graph (Google's official site hint)
  - -10  generic platforms (youtube, instagram, x, wikipedia, etc.)
  Base score is 50 for any discovered domain.

Requires SERPER_API_KEY for Serper searches (optional — returns empty
results without it, which is consistent with other serper collectors).
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse
from typing import Any, Dict, List

import httpx

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata

logger = logging.getLogger("osint.org_domain_discovery")

# Regex to extract domain from a URL — captures www.example.com, sub.example.co.uk
_DOMAIN_IN_URL_RE = re.compile(r"://([^/]+)")

# Domains that are clearly generic platforms, not the org's own site.
_GENERIC_PLATFORMS: set[str] = {
    "youtube.com", "instagram.com", "x.com",
    "en.wikipedia.org", "facebook.com", "twitter.com",
    "linkedin.com", "reddit.com",
}


class OrgDomainDiscoveryCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="org_domain_discovery",
        vector="INFRASTRUCTURE",
        description="Discover domains associated with an organization name via search engines",
        passive=True,
        requires_api_key=True,
        api_key_env="SERPER_API_KEY",
    )

    TIMEOUT = 30

    # Search queries to discover domains for a company.
    # {target} is replaced with the company name.
    QUERIES: list[str] = [
        "{target} official website",
        "{target} .com",
        '"{target}" company site',
    ]

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Search for domains associated with an organization name.

        Parameters
        ----------
        target : str
            Organization name (e.g. "Acme Corp", "University of Tunis").

        Returns
        -------
        List[Dict[str, Any]]
            Deduplicated list of discovered domains with metadata and scores.
        """
        if not settings.SERPER_API_KEY:
            logger.info("org_domain_discovery: SERPER_API_KEY not set, skipping")
            return []

        headers = {
            "X-API-KEY": settings.SERPER_API_KEY,
            "Content-Type": "application/json",
        }
        discovered: dict[str, dict[str, Any]] = {}

        async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
            for query_template in self.QUERIES:
                query = query_template.format(target=target)
                try:
                    resp = await client.post(
                        "https://google.serper.dev/search",
                        headers=headers,
                        json={"q": query, "num": 10},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                except httpx.HTTPStatusError as exc:
                    logger.warning(
                        "org_domain_discovery: Serper HTTP %s for query '%s'",
                        exc.response.status_code,
                        query,
                    )
                    continue
                except httpx.TimeoutException:
                    logger.debug("org_domain_discovery: Serper timeout for query '%s'", query)
                    continue
                except Exception as exc:
                    logger.warning(
                        "org_domain_discovery: Serper error for query '%s': %s",
                        query,
                        exc,
                    )
                    continue

                # Extract domains from organic results
                organic = data.get("organic", [])
                for item in organic:
                    link = item.get("link", "")
                    domain = self._extract_domain(link)
                    if domain and domain not in discovered:
                        discovered[domain] = {
                            "type": "DOMAIN_METADATA",
                            "value": domain,
                            "details": {
                                "domain": domain,
                                "source": "org_domain_discovery",
                                "discovery_query": query,
                                "title": item.get("title", ""),
                                "snippet": item.get("snippet", ""),
                                "url": link,
                                "organization": target,
                                "from_knowledge_graph": False,
                            },
                        }

                # Also check the knowledgeGraph if present (often has the official site)
                kg = data.get("knowledgeGraph", {})
                kg_url = kg.get("websiteUrl", "") or kg.get("url", "")
                kg_domain = self._extract_domain(kg_url)
                if kg_domain and kg_domain not in discovered:
                    discovered[kg_domain] = {
                        "type": "DOMAIN_METADATA",
                        "value": kg_domain,
                        "details": {
                            "domain": kg_domain,
                            "source": "org_domain_discovery",
                            "discovery_query": query,
                            "title": kg.get("title", ""),
                            "url": kg_url,
                            "organization": target,
                            "from_knowledge_graph": True,
                        },
                    }

        # Score each discovered domain
        for domain, entry in discovered.items():
            score = self._score_domain(domain, target, entry["details"].get("from_knowledge_graph", False))
            entry["details"]["score"] = score

        if not discovered:
            logger.info(
                "org_domain_discovery: no domains found for '%s' (try a more specific name)",
                target,
            )

        return list(discovered.values())

    @staticmethod
    def _score_domain(domain: str, org_name: str, from_kg: bool) -> int:
        """Score a domain by how relevant it is to the organization.

        Higher scores mean the domain is more likely the org's official site.
        """
        score = 50  # base

        # +30 if domain contains the org name (simplified: check if org name
        # words appear in the domain)
        org_slug = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())
        domain_slug = domain.replace("www.", "").replace(".com", "").replace(".org", "")
        if org_slug and org_slug in domain_slug:
            score += 30

        # +20 for Knowledge Graph hits (Google's strong signal)
        if from_kg:
            score += 20

        # -10 for known generic platforms
        if domain in _GENERIC_PLATFORMS:
            score -= 10

        return max(0, score)

    @staticmethod
    def _extract_domain(url: str) -> str | None:
        """Extract the domain from a URL, lowercased, without 'www.' prefix."""
        if not url:
            return None
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                # Try raw extraction for non-URL strings
                match = _DOMAIN_IN_URL_RE.search(url)
                if match:
                    host = match.group(1)
            if host:
                host = host.lower()
                # Strip www. prefix for cleaner results
                if host.startswith("www."):
                    host = host[4:]
                return host
        except Exception:
            pass
        return None

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        details = raw.get("details", {})

        return {
            "entity_type": "DOMAIN_METADATA",
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.7,
            "normalized_data": details,
        }
