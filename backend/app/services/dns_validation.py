from __future__ import annotations

import secrets
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver


_RECORD_TYPES = ("A", "AAAA", "CNAME")


@dataclass(frozen=True)
class WildcardDnsResult:
    detected: bool = False
    signatures: frozenset[str] = field(default_factory=frozenset)
    responsive_samples: int = 0


async def _resolve_signature(
    resolver: dns.asyncresolver.Resolver, hostname: str
) -> set[str]:
    signature: set[str] = set()
    for record_type in _RECORD_TYPES:
        try:
            answers = await resolver.resolve(hostname, record_type)
            signature.update(
                f"{record_type}:{str(answer).lower().rstrip('.')}"
                for answer in answers
            )
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            continue
    return signature


async def detect_wildcard_dns(
    root_domain: str, *, samples: int = 3
) -> WildcardDnsResult:
    """Probe random nonexistent labels and identify wildcard DNS behavior."""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    resolver.timeout = 2.0
    resolver.lifetime = 4.0

    sample_signatures: list[set[str]] = []
    for _ in range(samples):
        label = f"osint-{secrets.token_hex(8)}.{root_domain}"
        signature = await _resolve_signature(resolver, label)
        if signature:
            sample_signatures.append(signature)

    # Requiring two responsive random names avoids classifying a transient or
    # poisoned one-off answer as a wildcard zone.
    detected = len(sample_signatures) >= 2
    combined = frozenset().union(*sample_signatures) if sample_signatures else frozenset()
    return WildcardDnsResult(
        detected=detected,
        signatures=combined,
        responsive_samples=len(sample_signatures),
    )


def finding_dns_signature(finding: dict) -> set[str]:
    records = (finding.get("normalized_data") or {}).get("dns_records") or {}
    return {
        f"{record_type}:{str(value).lower().rstrip('.')}"
        for record_type in _RECORD_TYPES
        for value in records.get(record_type, [])
    }


def matches_wildcard(finding: dict, wildcard: WildcardDnsResult) -> bool:
    if not wildcard.detected:
        return False
    signature = finding_dns_signature(finding)
    # A shared CDN address alone is not sufficient evidence. Classify the
    # candidate only when every observed DNS record is explained by the
    # wildcard samples; a distinct CNAME/address keeps it eligible.
    return bool(signature and signature.issubset(wildcard.signatures))
