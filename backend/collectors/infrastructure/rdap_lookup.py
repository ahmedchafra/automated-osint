"""Standards-based RDAP enrichment for domains and IP addresses.

Authoritative service URLs are discovered from IANA's RDAP bootstrap
registries (RFC 9224). The collector is passive, needs no API key, and stores
only a compact normalized view while retaining the source response as finding
evidence through the standard collector wrapper.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any
from urllib.parse import quote, urljoin, urlparse

import httpx
import tldextract

from collectors.base import BaseCollector, CollectorMetadata


DNS_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
IPV4_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv4.json"
IPV6_BOOTSTRAP_URL = "https://data.iana.org/rdap/ipv6.json"
BOOTSTRAP_CACHE_SECONDS = 24 * 60 * 60
REQUEST_TIMEOUT_SECONDS = 20.0

_extract = tldextract.TLDExtract(suffix_list_urls=())
_bootstrap_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _registered_domain(value: str) -> str:
    hostname = value.strip().lower().rstrip(".").encode("idna").decode("ascii")
    extracted = _extract(hostname)
    return extracted.top_domain_under_public_suffix or hostname


def _https_service(services: list[Any], key: str) -> str | None:
    """Return the first HTTPS base URL whose bootstrap keys contain key."""
    normalized_key = key.lower().rstrip(".")
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        keys, urls = service
        if not isinstance(keys, list) or not isinstance(urls, list):
            continue
        if normalized_key not in {str(item).lower().rstrip(".") for item in keys}:
            continue
        for url in urls:
            if isinstance(url, str) and urlparse(url).scheme == "https":
                return url.rstrip("/") + "/"
    return None


def _ip_service(services: list[Any], address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Choose the most-specific IANA bootstrap network containing address."""
    matches: list[tuple[int, str]] = []
    for service in services:
        if not isinstance(service, list) or len(service) != 2:
            continue
        networks, urls = service
        if not isinstance(networks, list) or not isinstance(urls, list):
            continue
        https_url = next(
            (
                url.rstrip("/") + "/"
                for url in urls
                if isinstance(url, str) and urlparse(url).scheme == "https"
            ),
            None,
        )
        if not https_url:
            continue
        for value in networks:
            try:
                network = ipaddress.ip_network(str(value), strict=False)
            except ValueError:
                continue
            if network.version == address.version and address in network:
                matches.append((network.prefixlen, https_url))
    return max(matches, default=(0, None), key=lambda item: item[0])[1]


def _event_date(payload: dict[str, Any], action: str) -> str | None:
    for event in payload.get("events") or []:
        if isinstance(event, dict) and event.get("eventAction") == action:
            value = event.get("eventDate")
            return str(value) if value else None
    return None


def _entity_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for field in vcard[1]:
        if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
            return str(field[3])
    return None


def _entity_for_role(payload: dict[str, Any], role: str) -> dict[str, Any] | None:
    for entity in payload.get("entities") or []:
        if isinstance(entity, dict) and role in (entity.get("roles") or []):
            return entity
    return None


def _notices(payload: dict[str, Any]) -> list[str]:
    titles: list[str] = []
    for notice in payload.get("notices") or []:
        if isinstance(notice, dict) and notice.get("title"):
            titles.append(str(notice["title"]))
    return titles[:10]


def _domain_details(payload: dict[str, Any], query: str, server: str) -> dict[str, Any]:
    registrar = _entity_for_role(payload, "registrar") or {}
    secure_dns = payload.get("secureDNS") if isinstance(payload.get("secureDNS"), dict) else {}
    return {
        "domain": query,
        "handle": payload.get("handle"),
        "unicode_name": payload.get("unicodeName"),
        "registrar": _entity_name(registrar),
        "registrar_handle": registrar.get("handle"),
        "creation_date": _event_date(payload, "registration"),
        "expiration_date": _event_date(payload, "expiration"),
        "updated_date": _event_date(payload, "last changed"),
        "status": list(payload.get("status") or []),
        "name_servers": sorted(
            {
                str(item.get("ldhName")).lower().rstrip(".")
                for item in (payload.get("nameservers") or [])
                if isinstance(item, dict) and item.get("ldhName")
            }
        ),
        "dnssec": secure_dns.get("delegationSigned"),
        "port43": payload.get("port43"),
        "rdap_server": server,
        "notices": _notices(payload),
    }


def _network_details(payload: dict[str, Any], query: str, server: str) -> dict[str, Any]:
    registrant = _entity_for_role(payload, "registrant") or {}
    administrative = _entity_for_role(payload, "administrative") or {}
    organization = _entity_name(registrant) or _entity_name(administrative)
    return {
        "ip": query,
        "handle": payload.get("handle"),
        "network_name": payload.get("name"),
        "start_address": payload.get("startAddress"),
        "end_address": payload.get("endAddress"),
        "ip_version": payload.get("ipVersion"),
        "network_type": payload.get("type"),
        "country": payload.get("country"),
        "parent_handle": payload.get("parentHandle"),
        "organization": organization,
        "status": list(payload.get("status") or []),
        "registration_date": _event_date(payload, "registration"),
        "updated_date": _event_date(payload, "last changed"),
        "rdap_server": server,
        "notices": _notices(payload),
    }


class RdapCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="rdap_lookup",
        vector="INFRASTRUCTURE",
        description="Authoritative domain and IP registration data via RDAP",
        passive=True,
        requires_api_key=False,
    )

    async def _fetch_json(self, client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
        response = await client.get(url)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else None

    async def _bootstrap(self, client: httpx.AsyncClient, url: str) -> dict[str, Any]:
        cached = _bootstrap_cache.get(url)
        if cached and time.monotonic() - cached[0] < BOOTSTRAP_CACHE_SECONDS:
            return cached[1]
        payload = await self._fetch_json(client, url)
        if not payload:
            raise ValueError(f"IANA RDAP bootstrap returned no data: {url}")
        _bootstrap_cache[url] = (time.monotonic(), payload)
        return payload

    async def collect(self, target: str) -> list[dict[str, Any]]:
        headers = {
            "Accept": "application/rdap+json, application/json;q=0.9",
            "User-Agent": self.get_random_user_agent(),
        }
        async with httpx.AsyncClient(
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=True,
        ) as client:
            try:
                address = ipaddress.ip_address(target.strip())
            except ValueError:
                query = _registered_domain(target)
                tld = query.rsplit(".", 1)[-1]
                bootstrap = await self._bootstrap(client, DNS_BOOTSTRAP_URL)
                server = _https_service(bootstrap.get("services") or [], tld)
                if not server:
                    return []
                payload = await self._fetch_json(
                    client, urljoin(server, f"domain/{quote(query, safe='.-')}")
                )
                if not payload:
                    return []
                return [{
                    "type": "DOMAIN_METADATA",
                    "value": query,
                    "details": _domain_details(payload, query, server),
                    "rdap_response": payload,
                }]

            bootstrap_url = IPV4_BOOTSTRAP_URL if address.version == 4 else IPV6_BOOTSTRAP_URL
            bootstrap = await self._bootstrap(client, bootstrap_url)
            server = _ip_service(bootstrap.get("services") or [], address)
            if not server:
                return []
            query = str(address)
            payload = await self._fetch_json(
                client, urljoin(server, f"ip/{quote(query, safe=':.')}")
            )
            if not payload:
                return []
            return [{
                "type": "HOST_METADATA",
                "value": query,
                "details": _network_details(payload, query, server),
                "rdap_response": payload,
            }]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "entity_type": raw["type"],
            "entity_value": raw["value"],
            "severity": "INFO",
            "confidence": 0.95,
            "normalized_data": raw.get("details") or {},
        }
