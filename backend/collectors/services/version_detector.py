"""Technology version detector — probes a domain for software versions.

Runs after BuiltWith has identified which technologies are present. Probes
the domain via HTTP to extract version numbers from:

  - Response headers (Server, X-Powered-By, X-Generator, etc.)
  - HTML meta tags (<meta name="generator">)
  - Known version-revealing URLs (/readme.html, /feed/, /CHANGELOG.txt)
  - HTML comments and JS bundle patterns

Stored as TECHNOLOGY_VERSION findings so the CVE cross-referencer can do
version-accurate lookups against NVD.
"""
from __future__ import annotations

import httpx
import re
from typing import List, Dict, Any

from collectors.base import BaseCollector, CollectorMetadata


class VersionDetectorCollector(BaseCollector):
    """Probe a domain for technology version information."""

    metadata = CollectorMetadata(
        name="version_detector",
        vector="SERVICES",
        description="Detect technology versions via HTTP header & page probing",
        passive=True,
        requires_api_key=False,
    )

    # ── Header → version extractors ────────────────────────────────────
    # Each entry: header_name -> [(compiled_regex, canonical_tech_name)]
    HEADER_PATTERNS: Dict[str, List[tuple]] = {
        "Server": [
            (r"(?i)nginx/([\d.]+)", "Nginx"),
            (r"(?i)apache/([\d.]+)", "Apache HTTP Server"),
            (r"(?i)Microsoft-IIS/([\d.]+)", "IIS"),
            (r"(?i)openresty/([\d.]+)", "OpenResty"),
            (r"(?i)Caddy/([\d.]+)", "Caddy"),
            (r"(?i)LiteSpeed", "LiteSpeed"),
            (r"(?i)cloudflare", "Cloudflare"),
            (r"(?i)AmazonS3", "Amazon S3"),
            (r"(?i)Google\s*Frontend", "Google Frontend"),
        ],
        "X-Powered-By": [
            (r"(?i)PHP/?([\d.]+)", "PHP"),
            (r"(?i)ASP\.NET", "ASP.NET"),
            (r"(?i)Express", "Express"),
            (r"(?i)Node\.?[Jj]s", "Node.js"),
            (r"(?i)Python/([\d.]+)", "Python"),
            (r"(?i)Ruby/([\d.]+)", "Ruby on Rails"),
        ],
        "X-Generator": [
            (r"(?i)WordPress\s*([\d.]+)", "WordPress"),
            (r"(?i)Drupal\s*([\d.]+)", "Drupal"),
            (r"(?i)Joomla!?\s*([\d.]+)", "Joomla"),
            (r"(?i)Wix\.com", "Wix"),
            (r"(?i)Shopify", "Shopify"),
            (r"(?i)Squarespace", "Squarespace"),
        ],
        "X-AspNet-Version": [
            (r"([\d.]+)", "ASP.NET"),
        ],
        "X-Runtime": [
            (r"(?i)ruby", "Ruby on Rails"),
        ],
    }

    # ── Known sub-paths that expose version info ───────────────────────
    VERSION_URLS: Dict[str, List[tuple]] = {
        "/readme.html": [
            (r"(?i)WordPress\s*([\d.]+)", "WordPress"),
        ],
        "/feed/": [
            (r"<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>", "WordPress"),
        ],
        "/wp-json/": [
            (r'"version":"([\d.]+)"', "WordPress"),
        ],
        "/CHANGELOG.txt": [
            (r"Drupal\s*([\d.]+)", "Drupal"),
        ],
        "/version.txt": [],
    }

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Probe *target* (a domain) and return version findings."""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        results: List[Dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()  # (tech_name, version) dedup

        async with httpx.AsyncClient(
            timeout=15.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        ) as client:

            # ── Main page fetch ─────────────────────────────────────────
            try:
                resp = await client.get(f"https://{domain}")

                # Headers
                for hdr, patterns in self.HEADER_PATTERNS.items():
                    value = resp.headers.get(hdr, "")
                    if not value:
                        continue
                    for pat, tech_name in patterns:
                        m = re.search(pat, value)
                        if m:
                            version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                            key = (tech_name, version)
                            if key not in seen:
                                seen.add(key)
                                results.append({
                                    "technology": tech_name,
                                    "version": version,
                                    "source": f"header:{hdr}",
                                })
                            break

                # HTML meta / comments
                ct = resp.headers.get("content-type", "")
                if "text/html" in ct:
                    html = resp.text
                    # <meta name="generator" content="WordPress 6.4">
                    gen_m = re.search(
                        r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
                        html, re.IGNORECASE,
                    )
                    if gen_m:
                        gen_val = gen_m.group(1)
                        for tn in ("WordPress", "Drupal", "Joomla", "Wix", "Shopify", "Squarespace"):
                            if tn.lower() in gen_val.lower():
                                ver_m = re.search(r"([\d.]+)", gen_val)
                                ver = ver_m.group(1) if ver_m else ""
                                key = (tn, ver)
                                if key not in seen:
                                    seen.add(key)
                                    results.append({
                                        "technology": tn,
                                        "version": ver,
                                        "source": "meta:generator",
                                    })
                                break
                    # HTML comments (WooCommerce etc.)
                    wc_m = re.search(
                        r'<!--\s*Built\s+with\s+WooCommerce\s+([\d.]+)',
                        html, re.IGNORECASE,
                    )
                    if wc_m:
                        key = ("WooCommerce", wc_m.group(1))
                        if key not in seen:
                            seen.add(key)
                            results.append({
                                "technology": "WooCommerce",
                                "version": wc_m.group(1),
                                "source": "html:comment",
                            })

            except Exception as exc:
                print(f"[version_detector] main page error: {exc}")

            # ── Known version URL probes ────────────────────────────────
            for url_path, patterns in self.VERSION_URLS.items():
                if not patterns:
                    continue
                try:
                    sub_resp = await client.get(f"https://{domain}{url_path}")
                    if sub_resp.status_code != 200:
                        continue
                    for pat, tn in patterns:
                        m = re.search(pat, sub_resp.text)
                        if m:
                            ver = m.group(1)
                            key = (tn, ver)
                            if key not in seen:
                                seen.add(key)
                                results.append({
                                    "technology": tn,
                                    "version": ver,
                                    "source": f"url:{url_path}",
                                })
                            break
                except Exception:
                    pass

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "TECHNOLOGY_VERSION",
            "entity_value": raw.get("technology", ""),
            "severity": "INFO",
            "confidence": 0.7,
            "normalized_data": {
                "technology": raw.get("technology", ""),
                "version": raw.get("version", ""),
                "source": raw.get("source", ""),
            },
        }
