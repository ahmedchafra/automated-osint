"""Reverse DNS collector — IP address to domain name discovery.

Performs PTR (pointer) DNS lookups on an IP address to discover the
canonical domain name(s) associated with it. Also attempts forward
confirmation (resolve the discovered domain back to the original IP)
to reduce false positives.

Entity types produced:
  - DOMAIN_METADATA: domain name discovered via PTR record

Passive: only queries public DNS servers, no API key required.
"""
from __future__ import annotations

import logging
from typing import List, Dict, Any

import dns.asyncresolver
import dns.exception
import dns.reversename

from collectors.base import BaseCollector, CollectorMetadata

logger = logging.getLogger("osint.reverse_dns")


class ReverseDnsCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="reverse_dns",
        vector="INFRASTRUCTURE",
        description="Reverse DNS (PTR) lookup — IP to domain name discovery",
        passive=False,
        requires_api_key=False,
    )

    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        self.resolver.timeout = 3.0
        self.resolver.lifetime = 8.0

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Perform PTR reverse lookup for the given IP address.

        Parameters
        ----------
        target : str
            An IPv4 or IPv6 address (validated by the caller).

        Returns
        -------
        List[Dict[str, Any]]
            A list with one entry per discovered PTR record.
            Each entry has type "DOMAIN_METADATA" and the domain
            as the value. Empty list if nothing found.
        """
        import ipaddress

        # Validate that target is an IP
        try:
            ipaddress.ip_address(target)
        except ValueError:
            logger.warning("reverse_dns: '%s' is not a valid IP address", target)
            return []

        target = target.strip()

        # Build the reverse-lookup name (e.g. 4.4.8.8.in-addr.arpa)
        try:
            rev_name = dns.reversename.from_address(target)
        except Exception as exc:
            logger.warning("reverse_dns: failed to build reverse name for %s: %s", target, exc)
            return []

        results: list[dict[str, Any]] = []
        seen: set[str] = set()

        try:
            answers = await self.resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                domain = str(rdata).rstrip(".").lower()
                if not domain or domain in seen:
                    continue
                seen.add(domain)

                entry: dict[str, Any] = {
                    "type": "DOMAIN_METADATA",
                    "value": domain,
                    "details": {
                        "ip": target,
                        "ptr_domain": domain,
                        "source": "reverse_dns",
                    },
                }

                # Forward-confirm: resolve the domain back and check if
                # the original IP appears in the A/AAAA records.
                confirmed = False
                try:
                    fwd_answers = await self.resolver.resolve(domain, "A")
                    for a in fwd_answers:
                        if str(a) == target:
                            confirmed = True
                            break
                    if not confirmed:
                        fwd_aaaa = await self.resolver.resolve(domain, "AAAA")
                        for a in fwd_aaaa:
                            if str(a) == target:
                                confirmed = True
                                break
                except Exception:
                    pass  # forward confirmation is best-effort

                entry["details"]["forward_confirmed"] = confirmed
                results.append(entry)

        except dns.resolver.NoAnswer:
            logger.debug("reverse_dns: no PTR record for %s", target)
        except dns.resolver.NXDOMAIN:
            logger.debug("reverse_dns: NXDOMAIN for PTR lookup of %s", target)
        except dns.exception.Timeout:
            logger.debug("reverse_dns: PTR lookup timed out for %s", target)
        except Exception as exc:
            logger.warning("reverse_dns: PTR lookup failed for %s: %s", target, exc)

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        details = raw.get("details", {})

        return {
            "entity_type": "DOMAIN_METADATA",
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.85 if details.get("forward_confirmed") else 0.5,
            "normalized_data": details,
        }
