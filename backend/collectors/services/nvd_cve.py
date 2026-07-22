import asyncio
import httpx
from typing import List, Dict, Any, Optional

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class NvdCveCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="nvd_cve",
        vector="SERVICES",
        description="NVD CVE matching for CPE strings from service banners",
        passive=True,
        requires_api_key=False,  # NVD API v2 is free without key (rate-limited)
        api_key_env="NVD_API_KEY",  # Optional key increases rate limit
    )

    # NVD API v2 endpoint (free, no key required for basic usage)
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        The 'target' passed to this collector is expected to be a CPE string
        (e.g., cpe:2.3:a:microsoft:internet_explorer:11.0.9600.18097:*:*:*:*:*:*:*:*).
        The calling code (scan_service.py) should extract CPE strings from
        Shodan/Censys banners and call this collector for each one.
        """
        cpe = target.strip()
        if not cpe.startswith("cpe:"):
            # Not a valid CPE; return empty so we don't spam the API
            return []

        # Prepare parameters
        params = {
            "cpeName": cpe,
            "resultsPerPage": 1000,  # Max allowed
            # No API key by default; if NVD_API_KEY is set, we'll add it via headers
        }

        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.BASE_URL, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()

                vulnerabilities = data.get("vulnerabilities", [])
                results: List[Dict[str, Any]] = []

                for vuln in vulnerabilities:  # Return all CVEs from the API (capped at 1000 by resultsPerPage)
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue

                    # Extract description (prefer English)
                    descriptions = cve.get("descriptions", [])
                    description = ""
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    if not description and descriptions:
                        description = descriptions[0].get("value", "")

                    # Extract CVSS v3.1 score if available
                    metrics = cve.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [])
                    base_score = None
                    severity = None
                    if cvss_v31:
                        first = cvss_v31[0]
                        base_score = first.get("cvssData", {}).get("baseScore")
                        severity = first.get("cvssData", {}).get("baseSeverity")

                    results.append({
                        "cve_id": cve_id,
                        "description": description,
                        "base_score": base_score,
                        "severity": severity,
                        "cpe": cpe,
                    })

                return results

        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.RequestError) as e:
            # For NVD, we treat transient errors as empty results so the scan continues
            name = getattr(self.metadata, "name", self.__class__.__name__)
            print(f"[{name}] upstream error: {e}")
            return []
        except Exception as e:
            name = getattr(self.metadata, "name", self.__class__.__name__)
            print(f"[{name}] unexpected error: {e}")
            return []

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Turn the raw NVD result into a Finding.
        """
        cve_id = raw.get("cve_id", "UNKNOWN")
        description = raw.get("description", "")
        base_score = raw.get("base_score")
        severity_raw = raw.get("severity", "UNKNOWN")
        cpe = raw.get("cpe", "")

        # Map NVD severity to our scale
        severity_map = {
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        severity = severity_map.get(severity_raw, "INFO")

        # Confidence: NVD is authoritative, so high confidence
        confidence = 0.95

        # Entity value is the CVE ID
        entity_value = cve_id

        # Build a summary for normalized_data
        summary_parts = []
        if description:
            summary_parts.append(description[:200])
        if base_score is not None:
            summary_parts.append(f"CVSS v3.1: {base_score}")
        if cpe:
            summary_parts.append(f"Matched CPE: {cpe}")

        normalized_data = {
            "cve_id": cve_id,
            "description": description,
            "base_score": base_score,
            "severity": severity_raw,
            "cpe": cpe,
            "summary": " - ".join(summary_parts),
        }

        return {
            "entity_type": "CVE",
            "entity_value": entity_value,
            "severity": severity,
            "confidence": confidence,
            "normalized_data": normalized_data,
        }