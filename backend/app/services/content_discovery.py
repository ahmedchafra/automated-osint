"""Bounded, manual-only content discovery for verified live web assets.

This module intentionally does not brute-force arbitrary wordlists.  It probes
two small, reviewed path profiles with GET requests, does not follow redirects,
does not retain response bodies, and compares every result with a randomized
missing-path baseline to suppress custom-404 false positives.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import re
import secrets
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from app.services.scope import ScopeEvaluator
from app.services.scoped_crawler import (
    PinnedResolver,
    canonicalize_url,
    parse_html_surface,
    resolve_public_addresses,
)


ContentDiscoveryProfile = Literal["common", "exposure"]

MAX_DISCOVERY_ROOTS = 5
DISCOVERY_CONCURRENCY = 4
MAX_RESPONSE_BYTES = 128 * 1024
DISCOVERY_TIMEOUT_SECONDS = 10

PROFILE_PATHS: dict[ContentDiscoveryProfile, tuple[str, ...]] = {
    "common": (
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/humans.txt", "/admin/", "/login", "/dashboard", "/api/",
        "/api/docs", "/docs", "/swagger/", "/swagger-ui/",
        "/openapi.json", "/graphql", "/health", "/status",
    ),
    "exposure": (
        "/.git/HEAD", "/.env", "/.env.local", "/config.json",
        "/backup.zip", "/database.sql", "/debug", "/actuator",
        "/actuator/health", "/server-status", "/phpinfo.php", "/.DS_Store",
    ),
}

_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("git_head_reference", re.compile(r"ref:\s*refs/heads/", re.IGNORECASE)),
    ("environment_assignment", re.compile(
        r"(?m)^(?:APP_KEY|DATABASE_URL|DB_PASSWORD|AWS_ACCESS_KEY_ID|SECRET_KEY)\s*=",
        re.IGNORECASE,
    )),
    ("phpinfo_page", re.compile(r"phpinfo\(\)|PHP Version", re.IGNORECASE)),
    ("openapi_document", re.compile(r'"(?:openapi|swagger)"\s*:', re.IGNORECASE)),
    ("directory_listing", re.compile(r"<title>\s*Index of /", re.IGNORECASE)),
    ("spring_actuator", re.compile(r'"(?:status|_links)"\s*:', re.IGNORECASE)),
)


@dataclass(frozen=True)
class ProbeResponse:
    url: str
    status: int
    content_type: str
    content_length: int
    body_sha256: str
    body_text: str
    bytes_read: int
    truncated: bool
    redirect_location: str | None
    connect_ip: str


def _origin(value: str) -> str | None:
    normalized = canonicalize_url(value, keep_query=False)
    if not normalized:
        return None
    parsed = urlsplit(normalized)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _marker_id(body: str) -> str | None:
    for marker_id, pattern in _MARKERS:
        if pattern.search(body):
            return marker_id
    return None


def _looks_like_baseline(response: ProbeResponse, baseline: ProbeResponse | None) -> bool:
    if baseline is None or response.status != baseline.status:
        return False
    if response.body_sha256 == baseline.body_sha256:
        return True
    size_delta = abs(response.content_length - baseline.content_length)
    tolerance = max(32, int(max(response.content_length, baseline.content_length) * 0.03))
    return response.content_type == baseline.content_type and size_delta <= tolerance


async def _fetch_probe(url: str, scope: ScopeEvaluator) -> ProbeResponse | None:
    """Fetch one URL after scope and fresh public-DNS checks."""
    if not scope.evaluate_url(url).allowed:
        return None
    parsed = urlsplit(url)
    if parsed.query or not parsed.hostname:
        return None
    addresses = await resolve_public_addresses(parsed.hostname)
    if not addresses:
        return None
    resolver = PinnedResolver(parsed.hostname, addresses)
    connector = aiohttp.TCPConnector(
        resolver=resolver, use_dns_cache=False, force_close=True, limit=1, ssl=False,
    )
    timeout = aiohttp.ClientTimeout(
        total=DISCOVERY_TIMEOUT_SECONDS, connect=4, sock_connect=4, sock_read=6,
    )
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": "OWL-OSINT-Content-Discovery/1.0",
                "Accept": "text/html,application/json,text/plain,application/xml;q=0.8,*/*;q=0.1",
            },
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
        ) as session:
            async with session.get(url, allow_redirects=False) as response:
                payload = bytearray()
                truncated = False
                async for chunk in response.content.iter_chunked(16 * 1024):
                    remaining = MAX_RESPONSE_BYTES - len(payload)
                    if remaining <= 0:
                        truncated = True
                        break
                    payload.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                raw = bytes(payload)
                charset = response.charset or "utf-8"
                try:
                    text = raw.decode(charset, errors="replace")
                except (LookupError, UnicodeError):
                    text = raw.decode("utf-8", errors="replace")
                connection = response.connection
                transport = connection.transport if connection is not None else None
                peer = transport.get_extra_info("peername") if transport is not None else None
                connect_ip = str(peer[0]) if isinstance(peer, tuple) and peer else addresses[0]
                return ProbeResponse(
                    url=url,
                    status=response.status,
                    content_type=response.headers.get("content-type", "").split(";", 1)[0].lower(),
                    content_length=len(raw),
                    body_sha256=hashlib.sha256(raw).hexdigest(),
                    body_text=text,
                    bytes_read=len(raw),
                    truncated=truncated,
                    redirect_location=response.headers.get("location"),
                    connect_ip=connect_ip,
                )
    except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError):
        return None


def _finding(
    response: ProbeResponse,
    *,
    profile: ContentDiscoveryProfile,
    path: str,
    baseline: ProbeResponse | None,
) -> dict[str, Any] | None:
    marker = _marker_id(response.body_text)
    custom_404 = _looks_like_baseline(response, baseline)
    interesting_status = 200 <= response.status < 400
    if custom_404 or not interesting_status:
        return None

    parsed = parse_html_surface(response.body_text) if response.content_type in {
        "text/html", "application/xhtml+xml",
    } else None
    severity = "INFO"
    confidence = 0.75
    if profile == "exposure":
        severity = "HIGH" if marker else "MEDIUM"
        confidence = 0.95 if marker else 0.7
    elif path in {"/admin/", "/dashboard", "/graphql", "/swagger/", "/swagger-ui/"}:
        severity = "LOW"

    return {
        "vector_type": "SERVICES",
        "entity_type": "CONTENT_DISCOVERY",
        "entity_value": response.url,
        "severity": severity,
        "confidence": confidence,
        "source_module": "content_discovery",
        "raw_data": {},
        "normalized_data": {
            "url": response.url,
            "path": path,
            "profile": profile,
            "status_code": response.status,
            "content_type": response.content_type,
            "content_length": response.content_length,
            "content_sha256": response.body_sha256,
            "title": parsed.title if parsed else None,
            "marker_id": marker,
            "confidence_reason": (
                f"matched {marker}" if marker else "distinct successful response from missing-path baseline"
            ),
            "baseline_status": baseline.status if baseline else None,
            "baseline_compared": baseline is not None,
            "custom_404_match": False,
            "connect_ip": response.connect_ip,
            "redirect_location": response.redirect_location,
            "bytes_read": response.bytes_read,
            "truncated": response.truncated,
            "response_body_stored": False,
            "redirects_followed": False,
            "request_method": "GET",
        },
        "tags": ["active", "manual", "content-discovery", profile] + ([marker] if marker else []),
    }


async def discover_content(
    urls: list[str],
    scope: ScopeEvaluator,
    profile: ContentDiscoveryProfile,
) -> list[dict[str, Any]]:
    """Probe a reviewed path set on up to five distinct, verified origins."""
    paths = PROFILE_PATHS[profile]
    roots: list[str] = []
    for value in urls:
        origin = _origin(value)
        if origin and scope.evaluate_url(origin).allowed and origin not in roots:
            roots.append(origin)
        if len(roots) >= MAX_DISCOVERY_ROOTS:
            break

    semaphore = asyncio.Semaphore(DISCOVERY_CONCURRENCY)

    async def limited_fetch(url: str) -> ProbeResponse | None:
        async with semaphore:
            return await _fetch_probe(url, scope)

    findings: list[dict[str, Any]] = []
    for root in roots:
        baseline_path = f"/.__owl_missing_{secrets.token_hex(12)}"
        baseline = await limited_fetch(root.rstrip("/") + baseline_path)
        responses = await asyncio.gather(*(
            limited_fetch(root.rstrip("/") + path) for path in paths
        ))
        for path, response in zip(paths, responses):
            if response is None:
                continue
            finding = _finding(response, profile=profile, path=path, baseline=baseline)
            if finding:
                findings.append(finding)
    return findings
