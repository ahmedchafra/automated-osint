"""Low-impact, scope-enforced crawling for verified live web assets.

The crawler performs GET requests only. It never submits forms, follows a
redirect automatically, persists response bodies, or fetches query-bearing and
action-like URLs discovered in pages. Every outbound request is scope checked,
freshly resolved, restricted to public addresses, and connected through a
pinned resolver to reduce DNS-rebinding/SSRF risk.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
from html.parser import HTMLParser
import ipaddress
import re
import socket
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import aiohttp

from app.services.http_validation import public_ip_set
from app.services.scope import ScopeEvaluator


MAX_CRAWL_SEEDS = 10
MAX_CRAWL_PAGES = 50
MAX_CRAWL_DEPTH = 2
CRAWL_CONCURRENCY = 4
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_DISCOVERED_PER_PAGE = 200
MAX_CRAWL_FINDINGS = 5000
MAX_URL_LENGTH = 2048
CRAWL_TIMEOUT_SECONDS = 12

_SAFE_RESPONSE_HEADERS = (
    "content-type", "content-length", "server", "x-powered-by",
)
_NON_PAGE_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".csv", ".doc", ".docx", ".eot",
    ".gif", ".gz", ".ico", ".jpeg", ".jpg", ".json", ".map", ".mp3",
    ".mp4", ".mpeg", ".mov", ".pdf", ".png", ".ppt", ".pptx", ".rar",
    ".rss", ".svg", ".tar", ".tgz", ".tif", ".tiff", ".ttf", ".txt",
    ".wav", ".webm", ".webp", ".woff", ".woff2", ".xls", ".xlsx",
    ".xml", ".zip",
}
_ACTION_SEGMENT = re.compile(
    r"^(?:log[-_]?out|log[-_]?off|sign[-_]?out|delete|destroy|remove|"
    r"unsubscribe|purchase|checkout|confirm[-_]?order)(?:[-_].*)?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ParsedForm:
    action: str
    method: str
    fields: tuple[dict[str, str], ...]


@dataclass(frozen=True)
class ParsedPage:
    title: str | None
    base_href: str | None
    links: tuple[str, ...]
    scripts: tuple[str, ...]
    forms: tuple[ParsedForm, ...]


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    content_type: str
    headers: dict[str, str]
    body: str
    bytes_read: int
    truncated: bool
    redirect_location: str | None
    connect_ip: str


class _SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[ParsedForm] = []
        self.base_href: str | None = None
        self._title_parts: list[str] = []
        self._in_title = False
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "base" and not self.base_href and values.get("href"):
            self.base_href = values["href"]
        elif tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"])
        elif tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": values.get("method", "GET").upper(),
                "fields": [],
            }
        elif self._form is not None and tag in {"input", "select", "textarea", "button"}:
            name = values.get("name", "").strip()[:100]
            if name:
                self._form["fields"].append({
                    "name": name,
                    "type": values.get("type", tag).lower()[:50],
                })

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._form is not None:
            self.forms.append(ParsedForm(
                action=self._form["action"],
                method=self._form["method"],
                fields=tuple(self._form["fields"][:100]),
            ))
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    def result(self) -> ParsedPage:
        title = " ".join(" ".join(self._title_parts).split())[:500] or None
        return ParsedPage(
            title=title,
            base_href=self.base_href,
            links=tuple(self.links[:MAX_DISCOVERED_PER_PAGE]),
            scripts=tuple(self.scripts[:MAX_DISCOVERED_PER_PAGE]),
            forms=tuple(self.forms[:50]),
        )


def parse_html_surface(html: str) -> ParsedPage:
    parser = _SurfaceParser()
    try:
        parser.feed(html)
        parser.close()
    except (UnicodeError, ValueError):
        pass
    return parser.result()


def canonicalize_url(value: str, *, keep_query: bool = True) -> str | None:
    """Normalize an HTTP(S) URL while dropping fragments and credentials."""
    if not value or len(value) > MAX_URL_LENGTH:
        return None
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        hostname = parsed.hostname.lower().rstrip(".").encode("idna").decode("ascii")
        port = parsed.port
    except (UnicodeError, ValueError):
        return None
    scheme = parsed.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    host_display = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host_display if port in {None, default_port} else f"{host_display}:{port}"
    path = parsed.path or "/"
    query = parsed.query if keep_query else ""
    normalized = urlunsplit((scheme, netloc, path, query, ""))
    return normalized if len(normalized) <= MAX_URL_LENGTH else None


def endpoint_template(url: str) -> str:
    """Represent a parameterized endpoint without persisting query values."""
    parsed = urlsplit(url)
    names = sorted({name[:100] for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name})
    base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return f"{base}?{'&'.join(names)}" if names else base


def parameter_names(url: str) -> list[str]:
    return sorted({name[:100] for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if name})


def automatic_fetch_decision(url: str, scope: ScopeEvaluator) -> tuple[bool, str]:
    decision = scope.evaluate_url(url)
    if not decision.allowed:
        return False, decision.reason
    parsed = urlsplit(url)
    if parsed.query:
        return False, "query-bearing URL is evidence-only"
    segments = [segment for segment in parsed.path.split("/") if segment]
    if any(_ACTION_SEGMENT.match(segment) for segment in segments):
        return False, "state-changing path is evidence-only"
    path_lower = parsed.path.lower()
    if any(path_lower.endswith(extension) for extension in _NON_PAGE_EXTENSIONS):
        return False, "non-page resource is evidence-only"
    return True, "safe scoped GET"


async def resolve_public_addresses(hostname: str) -> list[str]:
    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                hostname, None, type=socket.SOCK_STREAM
            )
        except (OSError, UnicodeError):
            return []
        addresses = sorted({record[4][0] for record in records})
    return addresses if public_ip_set(addresses) else []


class PinnedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, hostname: str, addresses: list[str]) -> None:
        self.hostname = hostname.lower().rstrip(".")
        self.addresses = tuple(addresses)

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        if host.lower().rstrip(".") != self.hostname:
            raise OSError("resolver received an unexpected hostname")
        results = []
        for address in self.addresses:
            address_family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            if family not in {socket.AF_UNSPEC, address_family}:
                continue
            results.append({
                "hostname": host,
                "host": address,
                "port": port,
                "family": address_family,
                "proto": socket.IPPROTO_TCP,
                "flags": socket.AI_NUMERICHOST,
            })
        if not results:
            raise OSError("no pinned address matches the requested family")
        return results

    async def close(self) -> None:
        return None


async def _fetch_page(url: str, scope: ScopeEvaluator) -> FetchResult | None:
    """Fetch one page after a final scope/DNS check, with redirects disabled."""
    allowed, _ = automatic_fetch_decision(url, scope)
    if not allowed:
        return None
    parsed = urlsplit(url)
    assert parsed.hostname is not None
    addresses = await resolve_public_addresses(parsed.hostname)
    if not addresses:
        return None
    resolver = PinnedResolver(parsed.hostname, addresses)
    connector = aiohttp.TCPConnector(
        resolver=resolver,
        use_dns_cache=False,
        force_close=True,
        limit=1,
        ssl=False,
    )
    timeout = aiohttp.ClientTimeout(
        total=CRAWL_TIMEOUT_SECONDS, connect=5, sock_connect=5, sock_read=7
    )
    headers = {
        "User-Agent": "OWL-OSINT-Scoped-Crawler/1.0",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    }
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=False,
        ) as session:
            async with session.get(url, allow_redirects=False) as response:
                connection = response.connection
                transport = connection.transport if connection is not None else None
                peer = transport.get_extra_info("peername") if transport is not None else None
                connect_ip = str(peer[0]) if isinstance(peer, tuple) and peer else addresses[0]
                payload = bytearray()
                truncated = False
                async for chunk in response.content.iter_chunked(64 * 1024):
                    remaining = MAX_RESPONSE_BYTES - len(payload)
                    if remaining <= 0:
                        truncated = True
                        break
                    payload.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                charset = response.charset or "utf-8"
                try:
                    body = bytes(payload).decode(charset, errors="replace")
                except (LookupError, UnicodeError):
                    body = bytes(payload).decode("utf-8", errors="replace")
                return FetchResult(
                    url=url,
                    status=response.status,
                    content_type=response.headers.get("content-type", "").split(";", 1)[0].lower(),
                    headers={name: response.headers[name] for name in _SAFE_RESPONSE_HEADERS if name in response.headers},
                    body=body,
                    bytes_read=len(payload),
                    truncated=truncated,
                    redirect_location=response.headers.get("location"),
                    connect_ip=connect_ip,
                )
    except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError):
        return None


def _finding(entity_type: str, entity_value: str, normalized: dict[str, Any], tags: list[str]) -> dict[str, Any]:
    return {
        "vector_type": "SERVICES",
        "entity_type": entity_type,
        "entity_value": entity_value,
        "severity": "INFO",
        "confidence": 1.0,
        "source_module": "scoped_crawler",
        "raw_data": {},
        "normalized_data": normalized,
        "tags": ["active", "verified-asset", "scoped-crawl", *tags],
    }


async def crawl_urls(urls: list[str], scope: ScopeEvaluator) -> list[dict[str, Any]]:
    """Breadth-first crawl of a bounded set of verified live URL seeds."""
    seeds: list[str] = []
    for value in urls:
        normalized = canonicalize_url(value, keep_query=False)
        if normalized and automatic_fetch_decision(normalized, scope)[0] and normalized not in seeds:
            seeds.append(normalized)
        if len(seeds) >= MAX_CRAWL_SEEDS:
            break

    frontier: list[tuple[str, int, str | None]] = [(url, 0, None) for url in seeds]
    queued = set(seeds)
    visited: set[str] = set()
    findings: list[dict[str, Any]] = []
    finding_keys: set[tuple[str, str]] = set()
    semaphore = asyncio.Semaphore(CRAWL_CONCURRENCY)

    def emit(finding: dict[str, Any]) -> None:
        key = (finding["entity_type"], finding["entity_value"])
        if key not in finding_keys and len(findings) < MAX_CRAWL_FINDINGS:
            finding_keys.add(key)
            findings.append(finding)

    async def fetch(entry: tuple[str, int, str | None]):
        async with semaphore:
            return entry, await _fetch_page(entry[0], scope)

    while frontier and len(visited) < MAX_CRAWL_PAGES:
        batch = frontier[: MAX_CRAWL_PAGES - len(visited)]
        frontier = frontier[len(batch):]
        results = await asyncio.gather(*(fetch(entry) for entry in batch))
        for (requested_url, depth, source_url), response in results:
            if requested_url in visited:
                continue
            visited.add(requested_url)
            if response is None:
                continue

            parsed_page = ParsedPage(None, None, (), (), ())
            if response.content_type in {"text/html", "application/xhtml+xml"}:
                parsed_page = parse_html_surface(response.body)
            emit(_finding("CRAWLED_PAGE", requested_url, {
                "url": requested_url,
                "status_code": response.status,
                "content_type": response.content_type,
                "title": parsed_page.title,
                "depth": depth,
                "source_url": source_url,
                "connect_ip": response.connect_ip,
                "bytes_read": response.bytes_read,
                "truncated": response.truncated,
                "content_sha256": hashlib.sha256(response.body.encode("utf-8", errors="replace")).hexdigest(),
                "headers": response.headers,
                "links_found": len(parsed_page.links),
                "forms_found": len(parsed_page.forms),
                "scripts_found": len(parsed_page.scripts),
            }, ["page", f"depth-{depth}"]))

            if response.redirect_location:
                target = canonicalize_url(urljoin(requested_url, response.redirect_location))
                if target and scope.evaluate_url(target).allowed:
                    fetch_allowed, reason = automatic_fetch_decision(target, scope)
                    template = endpoint_template(target)
                    emit(_finding("WEB_ENDPOINT", template, {
                        "url": template,
                        "source_url": requested_url,
                        "discovered_by": "redirect",
                        "depth": depth + 1,
                        "crawl_eligible": fetch_allowed,
                        "crawl_reason": reason,
                        "parameter_names": parameter_names(target),
                    }, ["endpoint", "redirect"]))
                    if fetch_allowed and depth < MAX_CRAWL_DEPTH and target not in queued:
                        queued.add(target)
                        frontier.append((target, depth + 1, requested_url))

            base_url = requested_url
            if parsed_page.base_href:
                candidate_base = canonicalize_url(urljoin(requested_url, parsed_page.base_href), keep_query=False)
                if candidate_base and scope.evaluate_url(candidate_base).allowed:
                    base_url = candidate_base

            for href in parsed_page.links:
                target = canonicalize_url(urljoin(base_url, href))
                if not target or not scope.evaluate_url(target).allowed:
                    continue
                fetch_allowed, reason = automatic_fetch_decision(target, scope)
                template = endpoint_template(target)
                names = parameter_names(target)
                emit(_finding("WEB_ENDPOINT", template, {
                    "url": template,
                    "source_url": requested_url,
                    "discovered_by": "link",
                    "depth": depth + 1,
                    "crawl_eligible": fetch_allowed,
                    "crawl_reason": reason,
                    "parameter_names": names,
                }, ["endpoint", "link"]))
                for name in names:
                    emit(_finding("WEB_PARAMETER", f"GET {name} @ {urlunsplit((*urlsplit(template)[:3], '', ''))}", {
                        "name": name,
                        "method": "GET",
                        "endpoint": template,
                        "source_url": requested_url,
                        "discovered_by": "query",
                    }, ["parameter", "query"]))
                if fetch_allowed and depth < MAX_CRAWL_DEPTH and target not in queued:
                    queued.add(target)
                    frontier.append((target, depth + 1, requested_url))

            for index, form in enumerate(parsed_page.forms):
                action = canonicalize_url(urljoin(base_url, form.action or requested_url))
                if not action or not scope.evaluate_url(action).allowed:
                    continue
                template = endpoint_template(action)
                fields = list(form.fields)
                emit(_finding("WEB_FORM", f"{form.method} {template} @ {requested_url} #{index + 1}", {
                    "action": template,
                    "method": form.method,
                    "fields": fields,
                    "field_count": len(fields),
                    "source_url": requested_url,
                    "submitted": False,
                }, ["form", form.method.lower()]))
                for item in fields:
                    emit(_finding("WEB_PARAMETER", f"{form.method} {item['name']} @ {template}", {
                        "name": item["name"],
                        "input_type": item["type"],
                        "method": form.method,
                        "endpoint": template,
                        "source_url": requested_url,
                        "discovered_by": "form",
                    }, ["parameter", "form"]))

            for src in parsed_page.scripts:
                target = canonicalize_url(urljoin(base_url, src))
                if not target or not scope.evaluate_url(target).allowed:
                    continue
                emit(_finding("JAVASCRIPT_ASSET", endpoint_template(target), {
                    "url": endpoint_template(target),
                    "source_url": requested_url,
                    "fetched": False,
                }, ["javascript", "evidence-only"]))

    return findings
