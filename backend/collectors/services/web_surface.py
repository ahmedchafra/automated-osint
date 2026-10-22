"""Verified web-surface collector for live public HTTP origins.

The collector performs one bounded landing-page request, checks a small set of
standard discovery files, fingerprints common technologies, hashes the favicon,
and captures the peer TLS certificate. Redirects are recorded but never followed.
Every hostname is re-resolved and rejected if any address is private or special.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import ssl
from html.parser import HTMLParser
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from collectors.base import BaseCollector, CollectorMetadata


MAX_PAGE_BYTES = 262_144
MAX_DISCOVERY_FILE_BYTES = 65_536
MAX_FAVICON_BYTES = 1_048_576
DISCOVERY_PATHS = (
    ("robots", "/robots.txt"),
    ("security", "/.well-known/security.txt"),
    ("security", "/security.txt"),
    ("sitemap", "/sitemap.xml"),
)


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts: list[str] = []
        self.generator = ""
        self.favicon_href = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self.in_title = True
        elif tag.lower() == "meta" and values.get("name", "").lower() == "generator":
            self.generator = values.get("content", "")[:300]
        elif tag.lower() == "link" and "icon" in values.get("rel", "").lower():
            self.favicon_href = values.get("href", "")[:1000]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title and len("".join(self.title_parts)) < 500:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())[:500]


async def _read_limited(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        remaining = limit - size
        if remaining <= 0:
            break
        chunks.append(chunk[:remaining])
        size += min(len(chunk), remaining)
        if size >= limit:
            break
    return b"".join(chunks)


async def _public_addresses(hostname: str) -> list[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    addresses: set[str] = set()
    for record_type in ("A", "AAAA"):
        try:
            answers = await resolver.resolve(hostname, record_type)
            addresses.update(str(answer) for answer in answers)
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
    if not addresses:
        return []
    try:
        if not all(ipaddress.ip_address(value).is_global for value in addresses):
            return []
    except ValueError:
        return []
    return sorted(addresses)


def _technology_names(headers: httpx.Headers, html: str, generator: str) -> set[str]:
    technologies: set[str] = set()
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server:
        technologies.add(server.split()[0][:100])
    if powered_by:
        technologies.add(powered_by[:100])
    if headers.get("cf-ray") or "cloudflare" in server.lower():
        technologies.add("Cloudflare")
    if generator:
        technologies.add(generator)
    patterns = {
        "WordPress": r"(?i)(wp-content|wp-includes|wordpress)",
        "Drupal": r"(?i)(drupalSettings|sites/default/files)",
        "Joomla": r"(?i)(/media/system/js/|joomla!)",
        "Next.js": r"(?i)(__NEXT_DATA__|/_next/static/)",
        "React": r"(?i)(data-reactroot|react-dom)",
        "Vue.js": r"(?i)(data-v-[0-9a-f]{6,}|vue\.js)",
        "Angular": r"(?i)(ng-version|angular\.min\.js)",
    }
    for name, pattern in patterns.items():
        if re.search(pattern, html):
            technologies.add(name)
    canonical_names = {
        "cloudflare": "Cloudflare",
        "express": "Express",
        "next.js": "Next.js",
        "react": "React",
        "vue.js": "Vue.js",
        "angular": "Angular",
        "wordpress": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
    }
    deduplicated: dict[str, str] = {}
    for name in technologies:
        cleaned = name.strip()
        if not cleaned:
            continue
        key = cleaned.lower()
        deduplicated[key] = canonical_names.get(key, cleaned)
    return set(deduplicated.values())


async def _tls_finding(hostname: str) -> dict[str, Any] | None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                hostname, 443, ssl=context, server_hostname=hostname
            ),
            timeout=7.0,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if not der:
            return None
        certificate = x509.load_der_x509_certificate(der)
        try:
            sans = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        return {
            "entity_type": "TLS_CERT",
            "entity_value": f"tls://{hostname}:443",
            "severity": "INFO",
            "confidence": 1.0,
            "normalized_data": {
                "hostname": hostname,
                "port": 443,
                "subject": certificate.subject.rfc4514_string(),
                "issuer": certificate.issuer.rfc4514_string(),
                "serial_number": str(certificate.serial_number),
                "not_before": certificate.not_valid_before_utc.isoformat(),
                "not_after": certificate.not_valid_after_utc.isoformat(),
                "san": sans[:500],
                "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            },
        }
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return None
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class WebSurfaceCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="web_surface",
        vector="SERVICES",
        description="Verified HTTP metadata, standard files, favicon, TLS, and technology discovery",
        passive=False,
        requires_api_key=False,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return []
        hostname = parsed.hostname.lower().rstrip(".")
        addresses = await _public_addresses(hostname)
        if not addresses:
            return []
        origin = f"{parsed.scheme}://{parsed.netloc}"
        landing_url = f"{origin}{parsed.path or '/'}"
        results: list[dict[str, Any]] = []
        timeout = httpx.Timeout(10.0, connect=5.0)
        headers = {
            "User-Agent": "OSINT-Web-Surface/1.0",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        }

        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, verify=False, headers=headers
        ) as client:
            page_body = b""
            page_headers = httpx.Headers()
            page_status = 0
            try:
                async with client.stream("GET", landing_url) as response:
                    page_status = response.status_code
                    page_headers = response.headers
                    page_body = await _read_limited(response, MAX_PAGE_BYTES)
            except httpx.HTTPError:
                return []

            content_type = page_headers.get("content-type", "")
            html = page_body.decode("utf-8", errors="replace") if "html" in content_type else ""
            parser = _PageParser()
            if html:
                parser.feed(html)

            results.append({
                "entity_type": "HTTP_HEADER",
                "entity_value": landing_url,
                "severity": "MEDIUM" if page_status in {401, 403} else "INFO",
                "confidence": 1.0,
                "normalized_data": {
                    "url": landing_url,
                    "status": page_status,
                    "headers": {
                        key: value[:1000]
                        for key, value in page_headers.items()
                        if key.lower() in {
                            "server", "x-powered-by", "content-type", "location",
                            "content-security-policy", "strict-transport-security",
                            "x-frame-options", "x-content-type-options", "set-cookie",
                            "www-authenticate", "cf-ray", "via", "x-cache",
                        }
                    },
                    "body_sha256": hashlib.sha256(page_body).hexdigest(),
                    "body_bytes_sampled": len(page_body),
                    "redirect_location": page_headers.get("location"),
                },
            })
            results.append({
                "entity_type": "HOST_METADATA",
                "entity_value": f"web:{landing_url}",
                "severity": "INFO",
                "confidence": 1.0,
                "normalized_data": {
                    "hostname": hostname,
                    "url": landing_url,
                    "title": parser.title,
                    "generator": parser.generator,
                    "content_type": content_type,
                    "resolved_ips": addresses,
                },
            })

            for technology in sorted(
                _technology_names(page_headers, html, parser.generator)
            ):
                results.append({
                    "entity_type": "TECHNOLOGY",
                    "entity_value": f"{technology} @ {hostname}",
                    "severity": "INFO",
                    "confidence": 0.75,
                    "normalized_data": {
                        "domain": hostname,
                        "category": technology,
                        "source": "verified_web_surface",
                    },
                })

            seen_discovery_urls: set[str] = set()
            for kind, path in DISCOVERY_PATHS:
                discovery_url = f"{origin}{path}"
                if discovery_url in seen_discovery_urls:
                    continue
                seen_discovery_urls.add(discovery_url)
                try:
                    async with client.stream("GET", discovery_url) as response:
                        if response.status_code != 200:
                            continue
                        body = await _read_limited(response, MAX_DISCOVERY_FILE_BYTES)
                        if not body:
                            continue
                        preview = body.decode("utf-8", errors="replace")[:4000]
                        results.append({
                            "entity_type": "URL",
                            "entity_value": discovery_url,
                            "severity": "INFO",
                            "confidence": 1.0,
                            "normalized_data": {
                                "url": discovery_url,
                                "kind": kind,
                                "status": response.status_code,
                                "content_type": response.headers.get("content-type", ""),
                                "content_sha256": hashlib.sha256(body).hexdigest(),
                                "content_preview": preview,
                                "truncated": len(body) >= MAX_DISCOVERY_FILE_BYTES,
                            },
                            "tags": ["web-surface", kind],
                        })
                except httpx.HTTPError:
                    continue

            favicon_url = urljoin(landing_url, parser.favicon_href or "/favicon.ico")
            favicon_parsed = urlparse(favicon_url)
            if favicon_parsed.hostname == hostname:
                try:
                    async with client.stream("GET", favicon_url) as response:
                        if response.status_code == 200:
                            body = await _read_limited(response, MAX_FAVICON_BYTES)
                            if body:
                                results.append({
                                    "entity_type": "HOST_METADATA",
                                    "entity_value": f"favicon:{favicon_url}",
                                    "severity": "INFO",
                                    "confidence": 1.0,
                                    "normalized_data": {
                                        "hostname": hostname,
                                        "favicon_url": favicon_url,
                                        "content_type": response.headers.get("content-type", ""),
                                        "size": len(body),
                                        "md5": hashlib.md5(body, usedforsecurity=False).hexdigest(),
                                        "sha256": hashlib.sha256(body).hexdigest(),
                                    },
                                })
                except httpx.HTTPError:
                    pass

        if parsed.scheme == "https":
            tls = await _tls_finding(hostname)
            if tls:
                results.append(tls)
        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": raw.get("entity_type", "HOST_METADATA"),
            "entity_value": raw.get("entity_value", ""),
            "severity": raw.get("severity", "INFO"),
            "confidence": raw.get("confidence", 0.8),
            "normalized_data": raw.get("normalized_data", {}),
            "tags": raw.get("tags", ["web-surface"]),
        }
