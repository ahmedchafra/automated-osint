"""WhoIS / ASN Lookup collector.

Performs domain registration lookups (WhoIS) and IP-based ASN lookups
using the python-whois library. No API key required — queries the
public whois servers directly.

Entity types produced:
  - DOMAIN_METADATA: registrar, creation/expiration dates, name servers
  - ASN_INFO: autonomous system number, CIDR, organization, country
"""
from __future__ import annotations

import asyncio
import re
import socket
from typing import List, Dict, Any

from collectors.base import BaseCollector, CollectorMetadata

# ── Well-known whois servers ─────────────────────────────────────────
WHOIS_SERVERS: dict[str, str] = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
}

# ── ASN data helper ──────────────────────────────────────────────────
# Uses Team Cymru's whois server for ASN lookups (free, no key required).
ASN_WHOIS_HOST = "whois.cymru.com"
ASN_WHOIS_PORT = 43


def _query_whois(host: str, port: int, query: str, timeout: int = 15) -> str:
    """Raw whois query via TCP socket. Returns the response text."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.sendall(f"{query}\r\n".encode("utf-8"))
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    sock.close()
    return response.decode("utf-8", errors="replace")


def _extract_tld(domain: str) -> str:
    """Extract the top-level domain from a domain name."""
    parts = domain.strip().lower().rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-1]
    return ""


def _parse_whois_fields(text: str) -> dict[str, str]:
    """Parse key: value pairs from a whois response."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key and value and key not in fields:
                fields[key] = value
    return fields


def _lookup_tld_whois(domain: str) -> dict[str, Any]:
    """Query the appropriate whois server for a domain registration record."""
    tld = _extract_tld(domain)
    server = WHOIS_SERVERS.get(tld, "whois.iana.org")

    raw = _query_whois(server, 43, domain)
    parsed = _parse_whois_fields(raw)

    result: dict[str, Any] = {
        "raw_whois": raw,
        "whois_server": server,
    }

    # Map common fields to structured keys
    field_map = {
        "registrar": "registrar",
        "registrar iana id": "registrar_iana_id",
        "creation date": "creation_date",
        "created": "creation_date",
        "registered": "creation_date",
        "registration time": "creation_date",
        "expiration date": "expiration_date",
        "expiry date": "expiration_date",
        "registry expiry date": "expiration_date",
        "updated date": "updated_date",
        "last updated": "updated_date",
        "last update of whois database": "updated_date",
        "name server": "name_servers",
        "nserver": "name_servers",
        "dnssec": "dnssec",
        "status": "status",
    }

    for whois_field, result_key in field_map.items():
        if whois_field in parsed:
            value = parsed[whois_field]
            if result_key == "name_servers":
                # Name servers may appear on multiple lines
                if result_key not in result:
                    result[result_key] = []
                if isinstance(value, str):
                    # Some servers list multiple NS on one line
                    for ns in re.split(r"\s+", value):
                        ns = ns.strip().lower()
                        if ns and ns not in result[result_key]:
                            result[result_key].append(ns)
            else:
                if result_key not in result:
                    result[result_key] = value

    return result


def _lookup_asn(ip: str) -> dict[str, Any] | None:
    """Query Team Cymru for ASN info for a given IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    raw = _query_whois(ASN_WHOIS_HOST, ASN_WHOIS_PORT, ip)
    lines = raw.strip().splitlines()

    # Team Cymru format: ASN | IP | AS Name
    # Example: "15169 | 8.8.8.8 | GOOGLE - Google LLC, US"
    for line in lines:
        line = line.strip()
        if not line or line.startswith("AS ") or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            asn_raw = parts[0]
            as_name = parts[2] if len(parts) > 2 else ""

            # Strip 'AS' prefix if present (e.g. "AS15169" -> "15169")
            asn = asn_raw.replace("AS", "").strip()

            return {
                "asn": f"AS{asn}",
                "ip": parts[1] if len(parts) > 1 else ip,
                "as_name": as_name,
                "asn_number": asn,
            }

    return None


class WhoIsCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="whois_lookup",
        vector="INFRASTRUCTURE",
        description="WhoIS domain registration and ASN lookup (free, no API key)",
        passive=True,
        requires_api_key=False,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Collect whois data for a domain and ASN data for resolved IPs.

        The target can be a domain name or an IP address.
        - Domain: returns DOMAIN_METADATA with registrar, dates, name servers
        - IP: returns ASN_INFO with autonomous system number, CIDR, org
        """
        import ipaddress

        results: list[dict[str, Any]] = []

        # Try IP first
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False

        if is_ip:
            # ASN lookup
            asn_data = await asyncio.wait_for(
                asyncio.to_thread(_lookup_asn, target),
                timeout=20,
            )
            if asn_data:
                results.append({
                    "type": "ASN_INFO",
                    "value": asn_data.get("asn", f"ASN-{target}"),
                    "details": {
                        "ip": target,
                        "asn": asn_data.get("asn"),
                        "asn_number": asn_data.get("asn_number"),
                        "as_name": asn_data.get("as_name"),
                    },
                })
        else:
            # Domain whois lookup
            whois_data = await asyncio.wait_for(
                asyncio.to_thread(_lookup_tld_whois, target),
                timeout=20,
            )
            creation_date = whois_data.get("creation_date", "unknown")
            expiration_date = whois_data.get("expiration_date", "unknown")
            registrar = whois_data.get("registrar", "unknown")
            name_servers = whois_data.get("name_servers", [])

            results.append({
                "type": "DOMAIN_METADATA",
                "value": target,
                "details": {
                    "domain": target,
                    "registrar": registrar,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "name_servers": name_servers,
                    "whois_server": whois_data.get("whois_server"),
                    "raw_whois": whois_data.get("raw_whois", ""),
                },
            })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        details = raw.get("details", {})

        if raw["type"] == "ASN_INFO":
            return {
                "entity_type": "ASN_INFO",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.85,
                "normalized_data": details,
            }

        return {
            "entity_type": "DOMAIN_METADATA",
            "entity_value": raw["value"],
            "severity": "INFO",
            "confidence": 0.85,
            "normalized_data": details,
        }
