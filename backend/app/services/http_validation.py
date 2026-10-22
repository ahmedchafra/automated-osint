from __future__ import annotations

import ipaddress
import time
from typing import Any

import httpx


MAX_HTTP_PROBES = 100
HTTP_PROBE_CONCURRENCY = 15
_SAFE_RESPONSE_HEADERS = (
    "server",
    "content-type",
    "content-length",
    "location",
    "x-powered-by",
)


def public_ip_set(values: list[str]) -> bool:
    """Require at least one address and reject any private/special address."""
    if not values:
        return False
    try:
        return all(ipaddress.ip_address(value).is_global for value in values)
    except ValueError:
        return False


async def probe_http(hostname: str, expected_ips: list[str]) -> dict[str, Any] | None:
    """Perform a low-impact HEAD probe against a validated public hostname.

    Redirects are recorded but never followed. HTTPS is preferred; HTTP is
    attempted only when the TLS endpoint cannot be reached.
    """
    if not public_ip_set(expected_ips):
        return None

    timeout = httpx.Timeout(7.0, connect=5.0)
    headers = {
        "User-Agent": "OSINT-Asset-Validator/1.0",
        "Accept": "*/*",
    }
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=False,
        headers=headers,
    ) as client:
        for scheme in ("https", "http"):
            url = f"{scheme}://{hostname}/"
            started = time.monotonic()
            try:
                response = await client.head(url)
            except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError):
                continue
            return {
                "url": str(response.url),
                "scheme": scheme,
                "status_code": response.status_code,
                "headers": {
                    name: response.headers[name]
                    for name in _SAFE_RESPONSE_HEADERS
                    if name in response.headers
                },
                "redirect_location": response.headers.get("location"),
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
    return None
