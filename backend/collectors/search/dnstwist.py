"""dnstwist collector — lookalike domain detection.

Generates permutations of the target domain (typosquatting, homoglyphs, etc.)
and checks which ones resolve to live IPs. Helps detect phishing domains,
brand abuse, and attack surface expansion.

Three-tier approach:
  1. dnstwist Python library (most permutations, best detection)
  2. dnstwist.io API fallback
  3. Local permutation generator + DNS resolution (always works)
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx

from collectors.base import BaseCollector, CollectorMetadata


class DnstwistCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="dnstwist",
        vector="SEARCH",
        description="Lookalike domain detection via dnstwist permutation + DNS resolution",
        passive=True,
        requires_api_key=False,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        try:
            import dnstwist
            findings = await self._collect_with_library(target)
        except ImportError:
            findings = await self._collect_with_api(target)

        # Upgrade any lookalike that resolves (has live IPs) to a
        # PHISHING_SITE instead of keeping a duplicate LOOKALIKE_DOMAIN.
        # This avoids showing the same domain twice in the results.
        upgraded: list[Dict[str, Any]] = []
        for f in findings:
            ips = f.get("details", {}).get("resolved_ips", [])
            if ips:
                upgraded.append({
                    "type": "PHISHING_SITE",
                    "value": f["value"],
                    "details": {
                        **f["details"],
                        "classification_reason": "live_lookalike",
                    },
                })
            else:
                upgraded.append(f)
        return upgraded

    async def _collect_with_library(self, target: str) -> List[Dict[str, Any]]:
        import dnstwist
        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            None,
            lambda: dnstwist.run(domain=target, registered=True, format="json"),
        )
        findings = []
        for r in results:
            domain = r.get("domain", "")
            if not domain or domain == target:
                continue
            findings.append({
                "type": "LOOKALIKE_DOMAIN",
                "value": domain,
                "details": {
                    "original_domain": target,
                    "permutation_type": r.get("fuzzer", "unknown"),
                    "resolved_ips": r.get("dns_a", []),
                    "dns_mx": r.get("dns_mx", []),
                    "dns_ns": r.get("dns_ns", []),
                },
            })
        return findings

    async def _collect_with_api(self, target: str) -> List[Dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://dnstwist.io/api/v1/perm",
                    params={"domain": target},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    findings = []
                    for item in data.get("permutations", []):
                        domain = item.get("domain", "")
                        if not domain or domain == target:
                            continue
                        findings.append({
                            "type": "LOOKALIKE_DOMAIN",
                            "value": domain,
                            "details": {
                                "original_domain": target,
                                "permutation_type": item.get("type", "unknown"),
                                "resolved_ips": item.get("ips", []),
                            },
                        })
                    if findings:
                        return findings
        except Exception:
            pass
        return await self._basic_permutations(target)

    async def _basic_permutations(self, target: str) -> List[Dict[str, Any]]:
        import dns.asyncresolver
        parts = target.split(".")
        if len(parts) < 2:
            return []
        name = parts[0]
        tld = ".".join(parts[1:])

        perms = set()
        subs = {"a": ["@", "4"], "e": ["3"], "i": ["1", "l"], "o": ["0"], "s": ["5", "$"], "l": ["1", "i"]}
        for i, ch in enumerate(name):
            if ch in subs:
                for sub in subs[ch]:
                    perms.add(name[:i] + sub + name[i + 1 :] + "." + tld)
        for i in range(len(name)):
            perms.add(name[:i] + name[i + 1 :] + "." + tld)
        for i in range(len(name) - 1):
            swapped = name[:i] + name[i + 1] + name[i] + name[i + 2 :]
            perms.add(swapped + "." + tld)
        for prefix in ["www", "mail", "ftp", "admin", "secure", "login"]:
            perms.add(f"{prefix}-{target}")
            perms.add(f"{prefix}.{target}")
        for suffix in ["admin", "secure", "login", "api", "dev", "staging"]:
            perms.add(f"{name}-{suffix}.{tld}")
            perms.add(f"{name}.{suffix}.{tld}")

        results = []
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 2.0
        resolver.lifetime = 3.0

        async def check_perm(perm):
            try:
                answers = await resolver.resolve(perm, "A")
                ips = [str(r) for r in answers]
                return {
                    "type": "LOOKALIKE_DOMAIN",
                    "value": perm,
                    "details": {
                        "original_domain": target,
                        "permutation_type": "local_generation",
                        "resolved_ips": ips,
                    },
                }
            except Exception:
                return None

        tasks = [check_perm(p) for p in perms if p != target]
        resolved = await asyncio.gather(*tasks)
        return [r for r in resolved if r is not None]

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        raw_type = raw.get("type", "LOOKALIKE_DOMAIN")
        if raw_type == "PHISHING_SITE":
            return {
                "entity_type": "PHISHING_SITE",
                "entity_value": raw["value"],
                "severity": "HIGH",
                "confidence": 0.7,
                "normalized_data": raw.get("details", {}),
            }
        return {
            "entity_type": "LOOKALIKE_DOMAIN",
            "entity_value": raw["value"],
            "severity": "MEDIUM",
            "confidence": 0.8,
            "normalized_data": raw.get("details", {}),
        }
