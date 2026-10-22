"""Wayback Machine (archive.org) — historical URL discovery.

Uses the CDX API to enumerate all URLs that archive.org has ever captured
for a given domain. Each result represents a historical snapshot URL with
its timestamp, HTTP status, and content type.

API endpoint: http://web.archive.org/cdx/search/cdx
Free, no API key required. Rate limit is generous but we pace at 1 req/s.
"""
import time
import urllib.parse
from typing import List, Dict, Any

import httpx

from collectors.base import BaseCollector, CollectorMetadata


# Module-level rate limiter
_last_request: float = 0.0


def _rate_limit():
    global _last_request
    now = time.monotonic()
    elapsed = now - _last_request
    if elapsed < 1.0:
        time.sleep(1.0 - elapsed)
    _last_request = time.monotonic()


class WaybackMachineCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="wayback_machine",
        vector="SEARCH",
        description="Archive.org Wayback Machine historical URL discovery",
        passive=True,
        requires_api_key=False,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        # Strip protocol and path
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

        results: list[dict] = []

        # ── CDX API for historical URLs ──────────────────────────────
        _rate_limit()
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        cdx_params = {
            "url": f"*.{target}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype,digest,length",
            "limit": "500",
            "collapse": "digest",
            "filter": "statuscode:200",
        }

        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.get(cdx_url, params=cdx_params, headers=headers)
                response.raise_for_status()
                data = response.json()

            # First row is the header ["original", "timestamp", ...]
            if not data or len(data) < 2:
                return []

            for row in data[1:]:
                if len(row) < 6:
                    continue
                original_url = row[0]
                timestamp = row[1]
                status_code = row[2]
                mime_type = row[3]
                digest = row[4]
                length_str = row[5]

                # Build the archive.org playback URL
                wayback_url = f"https://web.archive.org/web/{timestamp}/{original_url}"

                results.append({
                    "type": "HISTORICAL_URL",
                    "value": original_url,
                    "wayback": {
                        "original_url": original_url,
                        "wayback_url": wayback_url,
                        "timestamp": timestamp,
                        "status_code": status_code,
                        "mime_type": mime_type,
                        "digest": digest,
                        "length": int(length_str) if length_str.isdigit() else 0,
                    },
                })
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            print(f"[wayback_machine] CDX API error for {target}: {e}")
        except httpx.HTTPStatusError as e:
            print(f"[wayback_machine] CDX API HTTP {e.response.status_code} for {target}")

        # ── Also fetch latest snapshot metadata for the root domain ──
        _rate_limit()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Single-page availability check
                avail_url = f"https://archive.org/wayback/available"
                avail_params = {"url": f"https://{target}"}
                resp = await client.get(avail_url, params=avail_params, headers=headers)
                resp.raise_for_status()
                avail_data = resp.json()

            snapshots = avail_data.get("archived_snapshots", {})
            closest = snapshots.get("closest", {})
            if closest and closest.get("url"):
                results.append({
                    "type": "WAYBACK_SNAPSHOT",
                    "value": f"{target} (latest snapshot)",
                    "wayback": {
                        "original_url": f"https://{target}",
                        "wayback_url": closest.get("url", ""),
                        "timestamp": closest.get("timestamp", ""),
                        "status_code": closest.get("status", ""),
                        "available": closest.get("available", False),
                    },
                })
        except Exception as e:
            print(f"[wayback_machine] availability check error for {target}: {e}")

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        wb = raw.get("wayback", {})
        raw_type = raw.get("type", "HISTORICAL_URL")

        if raw_type == "WAYBACK_SNAPSHOT":
            return {
                "entity_type": "WAYBACK_SNAPSHOT",
                "entity_value": raw.get("value", ""),
                "severity": "INFO",
                "confidence": 0.9,
                "normalized_data": {
                    "original_url": wb.get("original_url", ""),
                    "wayback_url": wb.get("wayback_url", ""),
                    "timestamp": wb.get("timestamp", ""),
                    "status_code": wb.get("status_code", ""),
                    "available": wb.get("available", False),
                },
            }

        # Default: HISTORICAL_URL
        return {
            "entity_type": "HISTORICAL_URL",
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.9,
            "normalized_data": {
                "original_url": wb.get("original_url", ""),
                "wayback_url": wb.get("wayback_url", ""),
                "timestamp": wb.get("timestamp", ""),
                "status_code": wb.get("status_code", ""),
                "mime_type": wb.get("mime_type", ""),
                "content_length": wb.get("length", 0),
            },
        }
