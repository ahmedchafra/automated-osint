from app.workers.initial_scan import (
    _filter_discovery_findings,
    _public_ip,
    _valid_subdomain,
)
from collectors.identity.theharvester import TheHarvesterCollector


def test_discovered_names_stay_below_the_requested_domain():
    assert _valid_subdomain("www.example.com", "example.com")
    assert _valid_subdomain("example.com", "example.com")
    assert not _valid_subdomain("*.example.com", "example.com")
    assert not _valid_subdomain("example.com.attacker.test", "example.com")
    assert not _valid_subdomain("bad_label.example.com", "example.com")


def test_private_and_invalid_ips_do_not_enter_enrichment():
    assert _public_ip("8.8.8.8")
    assert not _public_ip("127.0.0.1")
    assert not _public_ip("192.168.1.1")
    assert not _public_ip("not-an-ip")


def test_discovery_filter_rejects_out_of_scope_records():
    records = [
        {"entity_type": "SUBDOMAIN", "entity_value": "www.example.com"},
        {"entity_type": "SUBDOMAIN", "entity_value": "evil.test"},
        {"entity_type": "IP_ADDRESS", "entity_value": "127.0.0.1"},
        {"entity_type": "EMAIL", "entity_value": "analyst@example.com"},
    ]
    filtered = _filter_discovery_findings(records, "example.com")
    assert [record["entity_value"] for record in filtered] == [
        "www.example.com",
        "analyst@example.com",
    ]


def test_theharvester_merge_validates_and_deduplicates():
    records = [
        {"kind": "subdomain", "value": "www.example.com"},
        {"kind": "subdomain", "value": "www.example.com"},
        {"kind": "subdomain", "value": "*.example.com"},
        {"kind": "subdomain", "value": "unrelated.test"},
        {"kind": "ip", "value": "127.0.0.1"},
        {"kind": "ip", "value": "8.8.8.8"},
    ]
    merged = TheHarvesterCollector._merge_results(
        records, domain="example.com"
    )
    assert merged == [
        {"kind": "subdomain", "value": "www.example.com"},
        {"kind": "ip", "value": "8.8.8.8"},
    ]
