"""Whoxy Reverse Whois collector.

Queries the Whoxy API for domains registered to or mentioning a given
company/organisation name.  This complements the Serper-based domain
discovery (org_domain_discovery.py) by surfacing domains that may not
appear in organic search results — parked domains, privacy-shielded
registrations, subsidiaries, etc.

API endpoint
------------
    GET https://api.whoxy.com/?key={key}&reverse=whois&company={company}

Response shape (JSON):
    {
      "status": 1,
      "success": true,
      "total_results": 50,
      "search_type": "reverse_whois",
      "search_term": "instagram",
      "domains_count": 50,
      "domains": ["instagram.com", "instagram-engineering.com", ...]
    }

Entity types produced:
  - DOMAIN_METADATA: discovered domain tied to the organisation

Scoring (stored in details.score, higher = more relevant):
  - +30  domain contains the org name
  - -10  generic platforms (youtube, instagram, x, wikipedia, etc.)
  Base score is 40 for Whoxy results (slightly lower confidence than
  Serper results since Whoxy includes privacy-shielded registrations).

Requires WHOXY_API_KEY (optional — returns empty results without it).
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

import httpx

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata

logger = logging.getLogger("osint.reverse_whois_whoxy")

WHoxy_API_BASE = "https://api.whoxy.com"

# Domains that are clearly generic platforms, not the org's own site.
_GENERIC_PLATFORMS: set[str] = {
    "youtube.com", "instagram.com", "x.com",
    "en.wikipedia.org", "facebook.com", "twitter.com",
    "linkedin.com", "reddit.com",
}


class ReverseWhoisWhoxyCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="reverse_whois_whoxy",
        vector="INFRASTRUCTURE",
        description="Discover domains registered to an organisation via Whoxy reverse whois",
        passive=True,
        requires_api_key=True,
        api_key_env="WHOXY_API_KEY",
    )

    TIMEOUT = 30

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Query Whoxy reverse whois for domains mentioning the organisation.

        Parameters
        ----------
        target : str
            Organisation name (e.g. "Tesla", "Acme Corp").

        Returns
        -------
        List[Dict[str, Any]]
            Deduplicated list of discovered domains with metadata and scores.
        """
        if not settings.WHOXY_API_KEY:
            logger.info("reverse_whois_whoxy: WHOXY_API_KEY not set, skipping")
            return []

        params = {
            "key": settings.WHOXY_API_KEY,
            "reverse": "whois",
            "company": target,
        }

        discovered: dict[str, dict[str, Any]] = {}

        async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
            try:
                resp = await client.get(WHoxy_API_BASE, params=params)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as exc:
                logger.warning(
                    "reverse_whois_whoxy: HTTP %s for '%s'",
                    exc.response.status_code,
                    target,
                )
                return []
            except httpx.TimeoutException:
                logger.debug("reverse_whois_whoxy: timeout for '%s'", target)
                return []
            except Exception as exc:
                logger.warning(
                    "reverse_whois_whoxy: error for '%s': %s",
                    target,
                    exc,
                )
                return []

        # Validate API response
        if not data.get("success"):
            logger.warning(
                "reverse_whois_whoxy: API returned success=false for '%s': %s",
                target,
                data.get("error", "unknown error"),
            )
            return []

        domains = data.get("domains", [])
        total_results = data.get("total_results", 0)
        domains_count = data.get("domains_count", 0)

        logger.info(
            "reverse_whois_whoxy: found %s domains for '%s' (total_results=%s)",
            domains_count,
            target,
            total_results,
        )

        for domain in domains:
            domain_lower = domain.lower().strip()
            if domain_lower and domain_lower not in discovered:
                score = self._score_domain(domain_lower, target)
                discovered[domain_lower] = {
                    "type": "DOMAIN_METADATA",
                    "value": domain_lower,
                    "details": {
                        "domain": domain_lower,
                        "source": "reverse_whois_whoxy",
                        "organization": target,
                        "total_results": total_results,
                        "score": score,
                    },
                }

        if not discovered:
            logger.info(
                "reverse_whois_whoxy: no domains found for '%s'",
                target,
            )

        return list(discovered.values())

    @staticmethod
    def _score_domain(domain: str, org_name: str) -> int:
        """Score a domain by how relevant it is to the organization.

        Whoxy results start at base 40 (lower than Serper's 50 since
        registrant data can be stale or broadly scoped).
        """
        score = 40  # base

        # +30 if domain contains the org name
        org_slug = re.sub(r"[^a-zA-Z0-9]", "", org_name.lower())
        domain_slug = domain.replace("www.", "").replace(".com", "").replace(".org", "")
        if org_slug and org_slug in domain_slug:
            score += 30

        # -10 for known generic platforms
        if domain in _GENERIC_PLATFORMS:
            score -= 10

        return max(0, score)

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        details = raw.get("details", {})

        return {
            "entity_type": "DOMAIN_METADATA",
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.6,
            "normalized_data": details,
        }
