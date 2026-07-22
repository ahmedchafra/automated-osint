"""HTTP Response Headers collector.

Performs a simple HTTP GET to both https:// and http:// variants of a
domain and captures the response status, headers, redirect chain, and
a hash of the response body.

No API key required — purely passive HTTP fingerprinting.
"""
import hashlib
from typing import List, Dict, Any

import httpx

from collectors.base import BaseCollector, CollectorMetadata


class HttpHeadersCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="http_headers",
        vector="SERVICES",
        description="HTTP response headers and redirect chain capture",
        passive=True,
        requires_api_key=False,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        # Strip protocol and path
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

        results: list[dict] = []

        # Try both HTTPS and HTTP variants
        for scheme in ("https", "http"):
            url = f"{scheme}://{target}"
            try:
                async with httpx.AsyncClient(
                    timeout=15.0,
                    follow_redirects=True,
                    max_redirects=10,
                    verify=False,  # tolerate self-signed certs
                ) as client:
                    response = await client.get(
                        url,
                        headers={
                            "User-Agent": self.get_random_user_agent(),
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        },
                    )

                    # Collect the redirect chain
                    redirect_chain = []
                    if response.history:
                        for r in response.history:
                            redirect_chain.append({
                                "url": str(r.url),
                                "status": r.status_code,
                                "location": r.headers.get("location", ""),
                            })

                    # Select interesting headers
                    interesting_keys = [
                        "server", "x-powered-by", "x-frame-options",
                        "content-security-policy", "strict-transport-security",
                        "x-content-type-options", "set-cookie",
                        "www-authenticate", "x-aspnet-version",
                        "x-ratelimit-limit", "x-ratelimit-remaining",
                        "via", "x-cache", "x-served-by",
                        "cf-ray", "x-amz-cf-pop", "x-amz-cf-id",
                        "x-robots-tag", "access-control-allow-origin",
                        "x-forwarded-for", "x-real-ip",
                    ]
                    captured = {}
                    for key in interesting_keys:
                        val = response.headers.get(key)
                        if val:
                            captured[key] = val[:500]  # truncate long values

                    # Also capture all response headers as a JSON blob
                    all_headers = dict(response.headers)

                    # Body hash (first 100KB only for speed)
                    body_hash = hashlib.sha256(response.content[:102400]).hexdigest()[:16]

                    results.append({
                        "type": "HTTP_HEADER",
                        "value": f"{scheme}://{target}",
                        "http_info": {
                            "scheme": scheme,
                            "url": str(response.url),
                            "status": response.status_code,
                            "redirect_chain": redirect_chain,
                            "interesting_headers": captured,
                            "all_headers": all_headers,
                            "body_hash": body_hash,
                            "content_length": len(response.content),
                            "content_type": response.headers.get("content-type", ""),
                        },
                    })
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                results.append({
                    "type": "HTTP_HEADER",
                    "value": f"{scheme}://{target}",
                    "http_info": {
                        "scheme": scheme,
                        "url": f"{scheme}://{target}",
                        "status": 0,
                        "error": str(e.__class__.__name__),
                        "redirect_chain": [],
                        "interesting_headers": {},
                        "all_headers": {},
                        "body_hash": "",
                        "content_length": 0,
                        "content_type": "",
                    },
                })
            except httpx.HTTPStatusError as e:
                results.append({
                    "type": "HTTP_HEADER",
                    "value": f"{scheme}://{target}",
                    "http_info": {
                        "scheme": scheme,
                        "url": f"{scheme}://{target}",
                        "status": e.response.status_code,
                        "error": f"HTTP {e.response.status_code}",
                        "redirect_chain": [],
                        "interesting_headers": dict(e.response.headers),
                        "all_headers": dict(e.response.headers),
                        "body_hash": "",
                        "content_length": 0,
                        "content_type": e.response.headers.get("content-type", ""),
                    },
                })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        info = raw.get("http_info", {})
        severity = "INFO"
        # Flag non-standard or interesting headers
        interesting = info.get("interesting_headers", {})
        if "www-authenticate" in interesting:
            severity = "MEDIUM"
        if info.get("status", 0) == 401 or info.get("status", 0) == 403:
            severity = "MEDIUM"

        return {
            "entity_type": "HTTP_HEADER",
            "entity_value": raw.get("value", ""),
            "severity": severity,
            "confidence": 1.0,
            "normalized_data": {
                "scheme": info.get("scheme", "https"),
                "url": info.get("url", ""),
                "status": info.get("status", 0),
                "error": info.get("error", ""),
                "redirect_chain": info.get("redirect_chain", []),
                "headers": info.get("interesting_headers", {}),
                "body_hash": info.get("body_hash", ""),
                "content_length": info.get("content_length", 0),
                "content_type": info.get("content_type", ""),
            },
        }
