"""Technology-to-CVE cross-reference collector.

Takes a technology/product name (e.g. "Nginx", "WordPress", "jQuery") and
queries the NVD API v2 keyword search to find related CVEs.

When an explicit *version* is provided (from the version_detector step), the
collector post-filters NVD results using CPE match criteria version ranges so
only CVEs that actually affect the detected version are returned.

Free NVD API (no key required), rate limited to ~5 req/s without key.
"""
from __future__ import annotations

import httpx
import re
from packaging.version import Version, InvalidVersion
from typing import List, Dict, Any

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


# Generic/abstract technology categories that are too broad for CVE matching
_GENERIC_KEYWORDS = {
    "hosting", "services", "management", "platform", "network", "analytics",
    "tracking", "marketing", "advertising", "cdn", "provider", "solution",
    "framework", "library", "api", "sdk", "tool", "monitoring", "security",
    "performance", "delivery", "optimization", "engagement", "retargeting",
    "attribution", "measurement", "automation", "integration", "infrastructure",
    "compliance", "governance", "business", "enterprise", "ecommerce",
    "social", "content", "customer", "data", "digital", "experience",
    "support", "service", "application", "bot", "bot detection",
    "a/b testing", "ai", "ux", "seo", "crm", "erp", "captcha",
    "verification", "authentication", "identity", "compatibility",
    "responsive", "accessibility", "localization", "personalization",
    "recommendation", "search", "chat", "payment", "billing",
    "subscription", "newsletter", "feedback", "survey", "forms",
}


def _is_product_like(name: str) -> bool:
    """Heuristic: return True if *name* looks like a specific product rather
    than a generic category, so it's worth querying NVD for CVEs."""
    name_lower = name.lower().strip()

    # Too short to be meaningful
    if len(name_lower) < 3:
        return False

    # Skip pure numbers
    if re.match(r'^\d+[\d\s]*$', name_lower):
        return False

    # Check against generic keywords
    words = set(re.split(r'[\s/&,-]+', name_lower))
    if words & _GENERIC_KEYWORDS:
        return False

    # Names with 4+ words are probably descriptive phrases, not products
    if len(name_lower.split()) >= 4:
        return False

    return True


# ── CPE matching helpers ──────────────────────────────────────────────


def _cpe_matches_technology(criteria: str, tech_name: str) -> bool:
    """Check whether a CPE 2.3 criteria string matches our technology name.

    Handles fuzzy matching — e.g. "Apache HTTP Server" matches
    ``cpe:2.3:a:apache:http_server`` and "Nginx" matches
    ``cpe:2.3:a:nginx:nginx``.
    """
    # Format: cpe:2.3:part:vendor:product:version:update:...
    parts = criteria.split(":")
    if len(parts) < 5:
        return False
    _scheme, _version, _part, vendor, product = parts[:5]

    # Only match application parts
    if _part != "a":
        return False

    name = tech_name.lower().strip()

    # Normalise CPE parts: underscores → spaces
    vendor_norm = vendor.replace("_", " ")
    product_norm = product.replace("_", " ")

    # Direct match
    if name == product_norm or name == vendor_norm:
        return True

    # Substring match (Apache HTTP Server → apache)
    if name in product_norm or product_norm in name:
        return True
    if name in vendor_norm or vendor_norm in name:
        return True

    return False


def _is_version_affected(version_str: str, cpe_matches: List[Dict]) -> bool:
    """Return True if *version_str* falls within any CPE version range.

    Examines ``versionStartIncluding``, ``versionEndExcluding``,
    ``versionStartExcluding``, and ``versionEndIncluding`` in each match
    entry.  When no version bounds exist, the CVE is assumed to affect
    all versions.
    """
    try:
        target = Version(version_str)
    except InvalidVersion:
        return True  # can't parse → include for safety

    for match in cpe_matches:
        if not match.get("vulnerable", True):
            continue

        vsi = match.get("versionStartIncluding")
        vee = match.get("versionEndExcluding")
        vse = match.get("versionStartExcluding")
        vei = match.get("versionEndIncluding")

        # No version bounds → all versions affected
        if not (vsi or vee or vse or vei):
            return True

        try:
            if vsi and target < Version(vsi):
                continue
            if vse and target <= Version(vse):
                continue
            if vee and target >= Version(vee):
                continue
            if vei and target > Version(vei):
                continue
            return True
        except InvalidVersion:
            continue

    return False


def _filter_cves_by_version(
    vulnerabilities: List[Dict], tech_name: str, version: str,
) -> List[Dict]:
    """Post-filter NVD results: keep only CVEs whose CPE ranges include *version*.

    Returns (cves_that_match, filtered_count).
    """
    matched: List[Dict] = []
    for vuln in vulnerabilities:
        cve = vuln.get("cve", {})
        configs = cve.get("configurations", [])
        if not configs:
            matched.append(vuln)
            continue

        affected = False
        for config in configs:
            if affected:
                break
            for node in config.get("nodes", []):
                if affected:
                    break
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if not _cpe_matches_technology(criteria, tech_name):
                        continue
                    if _is_version_affected(version, [cpe_match]):
                        affected = True
                        break

        if affected:
            matched.append(vuln)

    return matched


# ── Collector ─────────────────────────────────────────────────────────


class TechnologyCveCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="technology_cve",
        vector="SERVICES",
        description="Cross-reference technology names against NVD for CVEs",
        passive=True,
        requires_api_key=False,
    )

    def __init__(self, domain: str = "", version: str | None = None):
        """Create technology_cve collector.

        Args:
            domain:  The parent domain being scanned. Stored in normalized_data
                     so the frontend can scope CVE findings to the correct domain.
            version: Optional detected version string (e.g. "1.25.3"). When set,
                     results are post-filtered via CPE version ranges.
        """
        self.domain = domain
        self.version = version

    # NVD API v2 keyword search
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Target is a technology/product name (e.g. 'Nginx', 'WordPress')."""
        tech_name = target.strip()

        if not _is_product_like(tech_name):
            return []

        params: Dict[str, Any] = {
            "keywordSearch": tech_name,
            "resultsPerPage": 50,
        }

        headers: Dict[str, str] = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.BASE_URL, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return []

            # ── Version-aware post-filter ──────────────────────────────
            if self.version:
                total_before = len(vulnerabilities)
                vulnerabilities = _filter_cves_by_version(
                    vulnerabilities, tech_name, self.version,
                )
                filtered = total_before - len(vulnerabilities)
                if filtered:
                    print(
                        f"[technology_cve] {tech_name} v{self.version}: "
                        f"filtered {filtered}/{total_before} CVEs (version mismatch)"
                    )

            results: List[Dict[str, Any]] = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                # Extract English description
                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break
                if not description and descriptions:
                    description = descriptions[0].get("value", "")

                # Extract CVSS v3.1 score
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
                    "technology": tech_name,
                    "detected_version": self.version,
                })

            return results

        except (httpx.HTTPStatusError, httpx.TimeoutException, httpx.RequestError) as e:
            print(f"[technology_cve] NVD API error for '{tech_name}': {e}")
            return []
        except Exception as e:
            print(f"[technology_cve] unexpected error for '{tech_name}': {e}")
            return []

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = raw.get("cve_id", "UNKNOWN")
        description = raw.get("description", "")
        base_score = raw.get("base_score")
        severity_raw = raw.get("severity", "UNKNOWN")
        tech_name = raw.get("technology", "")
        detected_version = raw.get("detected_version")

        severity_map = {
            "LOW": "LOW",
            "MEDIUM": "MEDIUM",
            "HIGH": "HIGH",
            "CRITICAL": "CRITICAL",
        }
        severity = severity_map.get(severity_raw, "INFO")

        summary_parts = []
        if description:
            summary_parts.append(description[:200])
        if base_score is not None:
            summary_parts.append(f"CVSS v3.1: {base_score}")
        summary_parts.append(f"(from {tech_name} technology scan)")
        if detected_version:
            summary_parts.insert(0, f"v{detected_version}")

        version_info = {"detected_version": detected_version} if detected_version else {}

        return {
            "entity_type": "CVE",
            "entity_value": cve_id,
            "severity": severity,
            "confidence": 0.85 if detected_version else 0.5,
            "normalized_data": {
                "cve_id": cve_id,
                "description": description,
                "base_score": base_score,
                "severity": severity_raw,
                "technology": tech_name,
                "domain": self.domain if self.domain else None,
                "summary": " - ".join(summary_parts),
                **version_info,
            },
        }
