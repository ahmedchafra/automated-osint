import asyncio

from collectors.infrastructure.ripestat import RipeStatCollector, _visibility


def test_ripestat_ip_enrichment_normalizes_prefix_and_bgp_context(monkeypatch):
    collector = RipeStatCollector()
    responses = {
        ("network-info", "1.1.1.1"): {"asns": ["13335"], "prefix": "1.1.1.0/24"},
        ("prefix-overview", "1.1.1.0/24"): {"announced": True},
        ("routing-status", "1.1.1.0/24"): {
            "first_seen": {"time": "2001-11-14T00:00:00", "origin": "19855"},
            "last_seen": {"time": "2026-10-23T08:00:00", "origin": "13335"},
            "visibility": {"v4": {"ris_peers_seeing": 92, "total_ris_peers": 94}},
            "origins": [{"origin": 13335, "route_objects": ["RADB", "APNIC"]}],
        },
        ("as-overview", "AS13335"): {
            "holder": "CLOUDFLARENET - Cloudflare, Inc.",
            "announced": True,
            "block": {"name": "ARIN", "desc": "Assigned by ARIN"},
        },
    }

    async def fake_query(client, endpoint, resource):
        return responses.get((endpoint, resource))

    monkeypatch.setattr(collector, "_query", fake_query)
    raw = asyncio.run(collector.collect("1.1.1.1"))
    normalized = collector.normalize(raw[0])

    assert normalized["entity_type"] == "ASN_INFO"
    assert normalized["entity_value"] == "AS13335"
    assert normalized["normalized_data"]["prefix"] == "1.1.1.0/24"
    assert normalized["normalized_data"]["holder"].startswith("CLOUDFLARENET")
    assert normalized["normalized_data"]["visibility_v4"]["ratio"] == 0.9787
    assert normalized["normalized_data"]["route_objects"] == ["APNIC", "RADB"]


def test_ripestat_visibility_handles_missing_peers():
    assert _visibility({}, "v4") is None
    assert _visibility({"visibility": {"v4": {}}}, "v4") == {
        "ris_peers_seeing": 0,
        "total_ris_peers": 0,
        "ratio": 0.0,
    }


def test_ripestat_rejects_malformed_network_asn_payload(monkeypatch):
    collector = RipeStatCollector()

    async def fake_query(client, endpoint, resource):
        return {"asns": "13335", "prefix": "1.1.1.0/24"}

    monkeypatch.setattr(collector, "_query", fake_query)

    assert asyncio.run(collector.collect("1.1.1.1")) == []


def test_ripestat_asn_enrichment_keeps_prefix_counts(monkeypatch):
    collector = RipeStatCollector()
    responses = {
        ("as-overview", "AS13335"): {
            "holder": "CLOUDFLARENET - Cloudflare, Inc.",
            "announced": True,
        },
        ("routing-status", "AS13335"): {},
        ("ris-prefixes", "AS13335"): {
            "counts": {
                "v4": {"originating": 2702, "transiting": 6539},
                "v6": {"originating": 2965, "transiting": 194},
            }
        },
    }

    async def fake_query(client, endpoint, resource):
        return responses.get((endpoint, resource))

    monkeypatch.setattr(collector, "_query", fake_query)
    raw = asyncio.run(collector.collect("AS13335"))

    assert raw[0]["details"]["prefix_counts"]["v4"]["originating"] == 2702
