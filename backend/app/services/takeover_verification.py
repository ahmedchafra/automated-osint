"""Conservative, non-invasive subdomain-takeover verification.

This service refreshes CNAME/A/AAAA evidence for scoped subdomains and may
perform one bounded GET request against a resolving hostname.  It never
attempts to register, claim, upload to, authenticate with, or otherwise
modify a third-party service.  A provider error-page match is therefore
reported as a strong fingerprint, not proof that an account can claim it.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import ipaddress
import socket
from typing import Any

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver

from app.services.http_validation import public_ip_set
from app.services.scope import ScopeEvaluator


MAX_TAKEOVER_TARGETS = 100
TAKEOVER_CONCURRENCY = 5
MAX_FINGERPRINT_BYTES = 256 * 1024
TAKEOVER_TIMEOUT_SECONDS = 8

PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


@dataclass(frozen=True)
class ProviderFingerprint:
    name: str
    suffixes: tuple[str, ...]
    markers: tuple[str, ...]


PROVIDER_FINGERPRINTS = (
    ProviderFingerprint(
        "GitHub Pages",
        ("github.io",),
        ("there isn't a github pages site here",),
    ),
    ProviderFingerprint("Heroku", ("herokudns.com", "herokuapp.com"), ("no such app",)),
    ProviderFingerprint(
        "Amazon S3 website",
        ("s3-website.amazonaws.com", "s3-website-us-east-1.amazonaws.com"),
        ("nosuchbucket", "the specified bucket does not exist"),
    ),
    ProviderFingerprint(
        "Azure App Service",
        ("azurewebsites.net",),
        ("404 web site not found",),
    ),
    ProviderFingerprint("Fastly", ("fastly.net",), ("fastly error: unknown domain",)),
    ProviderFingerprint(
        "Shopify",
        ("myshopify.com",),
        ("sorry, this shop is currently unavailable",),
    ),
    ProviderFingerprint(
        "Vercel", ("vercel.app", "vercel-dns.com"), ("deployment_not_found",)
    ),
    ProviderFingerprint(
        "Read the Docs",
        ("readthedocs.io",),
        ("unknown to read the docs",),
    ),
    ProviderFingerprint("Surge", ("surge.sh",), ("project not found",)),
    ProviderFingerprint("Bitbucket Pages", ("bitbucket.io",), ("repository not found",)),
)


@dataclass(frozen=True)
class DnsQueryResult:
    records: tuple[str, ...]
    status: str
    error: str | None = None


@dataclass(frozen=True)
class DnsSnapshot:
    hostname: str
    cnames: tuple[str, ...]
    addresses: tuple[str, ...]
    cname_target_status: str
    query_errors: tuple[str, ...]


@dataclass(frozen=True)
class HttpFingerprintEvidence:
    url: str
    status_code: int
    connect_ip: str
    response_sha256: str
    bytes_read: int
    truncated: bool
    matched_marker: str | None


def _normalize_hostname(value: str) -> str | None:
    try:
        hostname = value.strip().lower().rstrip(".").encode("idna").decode("ascii")
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None
    if not hostname or "." not in hostname or len(hostname) > 253:
        return None
    return hostname


def provider_for_cnames(cnames: tuple[str, ...]) -> ProviderFingerprint | None:
    """Return a provider only on a DNS-label boundary suffix match."""
    for cname in cnames:
        target = cname.lower().rstrip(".")
        for provider in PROVIDER_FINGERPRINTS:
            if any(target == suffix or target.endswith(f".{suffix}") for suffix in provider.suffixes):
                return provider
            if (
                provider.name == "Amazon S3 website"
                and target.endswith(".amazonaws.com")
                and any(label.startswith("s3-website") for label in target.split("."))
            ):
                return provider
    return None


def matched_provider_marker(body: str, provider: ProviderFingerprint) -> str | None:
    lowered = body.casefold()
    return next((marker for marker in provider.markers if marker.casefold() in lowered), None)


class TakeoverDnsResolver:
    def __init__(self) -> None:
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.nameservers = PUBLIC_RESOLVERS
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 6.0

    async def query(self, name: str, record_type: str) -> DnsQueryResult:
        try:
            answers = await self.resolver.resolve(
                name, record_type, search=False, raise_on_no_answer=False
            )
            if answers.rrset is None:
                return DnsQueryResult((), "no_answer")
            records = tuple(str(answer).rstrip(".") for answer in answers)
            return DnsQueryResult(records, "ok" if records else "no_answer")
        except dns.resolver.NXDOMAIN:
            return DnsQueryResult((), "nxdomain")
        except dns.resolver.NoAnswer:
            return DnsQueryResult((), "no_answer")
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            return DnsQueryResult((), "error", exc.__class__.__name__)
        except Exception as exc:
            return DnsQueryResult((), "error", exc.__class__.__name__)

    async def snapshot(self, hostname: str) -> DnsSnapshot:
        cname_result, a_result, aaaa_result = await asyncio.gather(
            self.query(hostname, "CNAME"),
            self.query(hostname, "A"),
            self.query(hostname, "AAAA"),
        )
        cnames = tuple(dict.fromkeys(cname_result.records))
        addresses = tuple(dict.fromkeys((*a_result.records, *aaaa_result.records)))
        errors = tuple(
            f"{record_type}:{result.error}"
            for record_type, result in (
                ("CNAME", cname_result), ("A", a_result), ("AAAA", aaaa_result)
            )
            if result.error
        )

        target_status = "none"
        if cnames:
            target = cnames[-1]
            target_a, target_aaaa = await asyncio.gather(
                self.query(target, "A"), self.query(target, "AAAA")
            )
            target_errors = [
                f"target_{record_type}:{result.error}"
                for record_type, result in (("A", target_a), ("AAAA", target_aaaa))
                if result.error
            ]
            errors = (*errors, *target_errors)
            if target_a.records or target_aaaa.records:
                target_status = "resolves"
            elif target_a.status == "nxdomain" or target_aaaa.status == "nxdomain":
                target_status = "nxdomain"
            elif target_a.status == "error" or target_aaaa.status == "error":
                target_status = "error"
            else:
                target_status = "no_address"
        return DnsSnapshot(hostname, cnames, addresses, target_status, tuple(errors))


async def resolve_public_addresses(hostname: str) -> list[str]:
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError):
        return []
    addresses = sorted({record[4][0] for record in records})
    return addresses if public_ip_set(addresses) else []


class _PinnedResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, hostname: str, addresses: list[str]) -> None:
        self.hostname = hostname.lower().rstrip(".")
        self.addresses = tuple(addresses)

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        if host.lower().rstrip(".") != self.hostname:
            raise OSError("resolver received an unexpected hostname")
        results = []
        for address in self.addresses:
            address_family = (
                socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            )
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


async def fetch_provider_fingerprint(
    hostname: str, provider: ProviderFingerprint
) -> HttpFingerprintEvidence | None:
    """GET only the root page, without redirects, after public-IP pinning."""
    addresses = await resolve_public_addresses(hostname)
    if not addresses:
        return None
    timeout = aiohttp.ClientTimeout(
        total=TAKEOVER_TIMEOUT_SECONDS, connect=4, sock_connect=4, sock_read=5
    )
    headers = {
        "User-Agent": "OWL-OSINT-Takeover-Validator/1.0",
        "Accept": "text/html,application/xml;q=0.9,text/plain;q=0.8,*/*;q=0.1",
    }
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}/"
        connector = aiohttp.TCPConnector(
            resolver=_PinnedResolver(hostname, addresses),
            use_dns_cache=False,
            force_close=True,
            limit=1,
            ssl=False,
        )
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
                    async for chunk in response.content.iter_chunked(32 * 1024):
                        remaining = MAX_FINGERPRINT_BYTES - len(payload)
                        if remaining <= 0:
                            truncated = True
                            break
                        payload.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated = True
                            break
                    body = bytes(payload).decode("utf-8", errors="replace")
                    return HttpFingerprintEvidence(
                        url=url,
                        status_code=response.status,
                        connect_ip=connect_ip,
                        response_sha256=hashlib.sha256(payload).hexdigest(),
                        bytes_read=len(payload),
                        truncated=truncated,
                        matched_marker=matched_provider_marker(body, provider),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError, ValueError):
            continue
    return None


def build_takeover_finding(
    snapshot: DnsSnapshot,
    provider: ProviderFingerprint | None,
    http_evidence: HttpFingerprintEvidence | None,
) -> dict[str, Any] | None:
    """Create evidence only for dangling or provider-error states."""
    if provider and http_evidence and http_evidence.matched_marker:
        status = "provider_fingerprint_matched"
        severity = "HIGH"
        confidence = 0.98
        summary = "Provider-specific unconfigured-site response observed"
    elif provider and snapshot.cname_target_status in {"nxdomain", "no_address"}:
        status = "probable_dangling_provider"
        severity = "HIGH"
        confidence = 0.9
        summary = "Recognized provider CNAME has no current address records"
    elif snapshot.cnames and snapshot.cname_target_status in {"nxdomain", "no_address"}:
        status = "dangling_cname"
        severity = "LOW"
        confidence = 0.65
        summary = "CNAME target has no current address records"
    else:
        return None

    http_data: dict[str, Any] | None = None
    if http_evidence:
        http_data = {
            "url": http_evidence.url,
            "status_code": http_evidence.status_code,
            "connect_ip": http_evidence.connect_ip,
            "response_sha256": http_evidence.response_sha256,
            "bytes_read": http_evidence.bytes_read,
            "truncated": http_evidence.truncated,
            "matched_marker": http_evidence.matched_marker,
        }
    provider_name = provider.name if provider else None
    return {
        "vector_type": "INFRASTRUCTURE",
        "entity_type": "TAKEOVER_ASSESSMENT",
        "entity_value": snapshot.hostname,
        "severity": severity,
        "confidence": confidence,
        "source_module": "takeover_verification",
        "raw_data": {},
        "normalized_data": {
            "hostname": snapshot.hostname,
            "status": status,
            "summary": summary,
            "provider": provider_name,
            "cnames": list(snapshot.cnames),
            "addresses": list(snapshot.addresses),
            "cname_target_status": snapshot.cname_target_status,
            "dns_query_errors": list(snapshot.query_errors),
            "http_evidence": http_data,
            "claim_attempted": False,
            "validation_limits": (
                "DNS refresh and optional bounded root-page GET only; provider ownership "
                "or claimability was not tested."
            ),
            "remediation": (
                "Remove the stale DNS record or bind the referenced provider resource to an "
                "authorized account, then verify the DNS and provider configuration again."
            ),
        },
        "tags": [
            "active", "verified-scope", "takeover-assessment", status,
            *([provider_name.lower().replace(" ", "-")] if provider_name else []),
        ],
    }


async def verify_takeover_candidates(
    hostnames: list[str],
    scope: ScopeEvaluator,
    *,
    resolver: TakeoverDnsResolver | None = None,
) -> list[dict[str, Any]]:
    """Assess a bounded, deduplicated set of explicitly in-scope subdomains."""
    candidates: list[str] = []
    for value in hostnames:
        hostname = _normalize_hostname(value)
        if hostname and scope.evaluate_hostname(hostname).allowed and hostname not in candidates:
            candidates.append(hostname)
        if len(candidates) >= MAX_TAKEOVER_TARGETS:
            break

    dns_resolver = resolver or TakeoverDnsResolver()
    semaphore = asyncio.Semaphore(TAKEOVER_CONCURRENCY)

    async def assess(hostname: str) -> dict[str, Any] | None:
        async with semaphore:
            snapshot = await dns_resolver.snapshot(hostname)
            provider = provider_for_cnames(snapshot.cnames)
            http_evidence = None
            if provider and snapshot.addresses and public_ip_set(list(snapshot.addresses)):
                http_evidence = await fetch_provider_fingerprint(hostname, provider)
            return build_takeover_finding(snapshot, provider, http_evidence)

    results = await asyncio.gather(*(assess(hostname) for hostname in candidates))
    return [finding for finding in results if finding is not None]
