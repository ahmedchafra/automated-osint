"""RIPEstat routing and ASN enrichment for IP addresses and ASNs."""
from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Any

import httpx

from collectors.base import BaseCollector, CollectorMetadata


RIPESTAT_BASE_URL = "https://stat.ripe.net/data"
SOURCE_APP = "automated-osint-dev"
REQUEST_TIMEOUT_SECONDS = 20.0
CACHE_SECONDS = 60 * 60
MAX_ORIGIN_ASNS = 3

_response_cache: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}


def _asn_number(value: str | int) -> str:
    return str(value).upper().removeprefix("AS")


def _visibility(payload: dict[str, Any], family: str) -> dict[str, int | float] | None:
    visibility = payload.get("visibility")
    if not isinstance(visibility, dict):
        return None
    data = visibility.get(family)
    if not isinstance(data, dict):
        return None
    seeing = int(data.get("ris_peers_seeing") or 0)
    total = int(data.get("total_ris_peers") or 0)
    return {
        "ris_peers_seeing": seeing,
        "total_ris_peers": total,
        "ratio": round(seeing / total, 4) if total else 0.0,
    }


def _route_objects(payload: dict[str, Any], asn: str) -> list[str]:
    try:
        number = int(_asn_number(asn))
    except ValueError:
        return []
    origins = payload.get("origins")
    if not isinstance(origins, list):
        return []
    for origin in origins:
        if isinstance(origin, dict) and origin.get("origin") == number:
            return sorted({str(value) for value in origin.get("route_objects") or []})
    return []


def _asn_details(
    asn: str,
    overview: dict[str, Any],
    *,
    ip: str | None = None,
    prefix: str | None = None,
    prefix_overview: dict[str, Any] | None = None,
    routing: dict[str, Any] | None = None,
    prefix_counts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    number = _asn_number(asn)
    routing = routing or {}
    prefix_overview = prefix_overview or {}
    block = overview.get("block") if isinstance(overview.get("block"), dict) else {}
    first_seen = routing.get("first_seen") if isinstance(routing.get("first_seen"), dict) else {}
    last_seen = routing.get("last_seen") if isinstance(routing.get("last_seen"), dict) else {}
    return {
        "ip": ip,
        "prefix": prefix,
        "asn": f"AS{number}",
        "asn_number": number,
        "as_name": overview.get("holder"),
        "holder": overview.get("holder"),
        "announced": overview.get("announced"),
        "prefix_announced": prefix_overview.get("announced"),
        "registry": block.get("name"),
        "registry_description": block.get("desc"),
        "first_seen": first_seen or None,
        "last_seen": last_seen or None,
        "visibility_v4": _visibility(routing, "v4"),
        "visibility_v6": _visibility(routing, "v6"),
        "route_objects": _route_objects(routing, number),
        "prefix_counts": prefix_counts,
        "query_time": routing.get("query_time") or overview.get("query_endtime"),
    }


class RipeStatCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="ripestat",
        vector="INFRASTRUCTURE",
        description="RIPE RIS prefix, origin ASN, and BGP visibility enrichment",
        passive=True,
        requires_api_key=False,
    )

    async def _query(
        self, client: httpx.AsyncClient, endpoint: str, resource: str
    ) -> dict[str, Any] | None:
        cache_key = (endpoint, resource.upper())
        cached = _response_cache.get(cache_key)
        if cached and time.monotonic() - cached[0] < CACHE_SECONDS:
            return cached[1]
        response = await client.get(
            f"{RIPESTAT_BASE_URL}/{endpoint}/data.json",
            params={"resource": resource, "sourceapp": SOURCE_APP},
        )
        if response.status_code == 404:
            return None
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            return None
        data = payload.get("data")
        if not isinstance(data, dict):
            return None
        _response_cache[cache_key] = (time.monotonic(), data)
        return data

    async def _collect_asn(
        self, client: httpx.AsyncClient, asn: str
    ) -> list[dict[str, Any]]:
        resource = f"AS{_asn_number(asn)}"
        overview, routing, prefixes = await asyncio.gather(
            self._query(client, "as-overview", resource),
            self._query(client, "routing-status", resource),
            self._query(client, "ris-prefixes", resource),
        )
        if not overview:
            return []
        counts = prefixes.get("counts") if isinstance(prefixes, dict) else None
        return [{
            "type": "ASN_INFO",
            "value": resource,
            "details": _asn_details(
                resource, overview, routing=routing, prefix_counts=counts
            ),
            "ripestat_response": {
                "as_overview": overview,
                "routing_status": routing,
                "ris_prefixes": prefixes,
            },
        }]

    async def _collect_ip(
        self, client: httpx.AsyncClient, address: str
    ) -> list[dict[str, Any]]:
        network = await self._query(client, "network-info", address)
        if not network:
            return []
        prefix = str(network.get("prefix") or "")
        network_asns = network.get("asns")
        if not isinstance(network_asns, list):
            return []
        asns = [
            _asn_number(value)
            for value in network_asns[:MAX_ORIGIN_ASNS]
            if str(value).strip()
        ]
        if not prefix or not asns:
            return []
        detail_results = await asyncio.gather(
            self._query(client, "prefix-overview", prefix),
            self._query(client, "routing-status", prefix),
            *(self._query(client, "as-overview", f"AS{asn}") for asn in asns),
        )
        prefix_overview, routing, *overview_results = detail_results
        results: list[dict[str, Any]] = []
        for asn, overview in zip(asns, overview_results):
            if not overview:
                continue
            results.append({
                "type": "ASN_INFO",
                "value": f"AS{asn}",
                "details": _asn_details(
                    asn,
                    overview,
                    ip=address,
                    prefix=prefix,
                    prefix_overview=prefix_overview,
                    routing=routing,
                ),
                "ripestat_response": {
                    "network_info": network,
                    "prefix_overview": prefix_overview,
                    "routing_status": routing,
                    "as_overview": overview,
                },
            })
        return results

    async def collect(self, target: str) -> list[dict[str, Any]]:
        value = target.strip()
        headers = {
            "Accept": "application/json",
            "User-Agent": self.get_random_user_agent(),
        }
        async with httpx.AsyncClient(
            headers=headers, timeout=REQUEST_TIMEOUT_SECONDS
        ) as client:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                match = re.fullmatch(r"(?i:AS)?(\d{1,10})", value)
                if not match:
                    return []
                return await self._collect_asn(client, match.group(1))
            return await self._collect_ip(client, str(address))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "entity_type": raw["type"],
            "entity_value": raw["value"],
            "severity": "INFO",
            "confidence": 0.95,
            "normalized_data": raw.get("details") or {},
        }
