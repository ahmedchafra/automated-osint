from app.workers.initial_scan import (
    _bounded_dns_candidates,
    _filter_discovery_findings,
    _public_ip,
    _valid_subdomain,
)
from collectors.identity.theharvester import TheHarvesterCollector
from app.services.asset_service import canonical_hostname, registrable_domain
from app.services.dns_validation import WildcardDnsResult, matches_wildcard
from app.services.http_validation import public_ip_set
from collectors.services.web_surface import _PageParser, _technology_names
from app.workers.active_validation import (
    parse_naabu_jsonl,
    parse_nmap_xml,
    parse_nuclei_jsonl,
)
from app.workers.domain_deep_analysis import _collector_specs
import httpx


def test_discovered_names_stay_below_the_requested_domain():
    assert _valid_subdomain("www.example.com", "example.com")
    assert _valid_subdomain("example.com", "example.com")
    assert not _valid_subdomain("*.example.com", "example.com")
    assert not _valid_subdomain("example.com.attacker.test", "example.com")
    assert not _valid_subdomain("bad_label.example.com", "example.com")


def test_dns_candidate_cap_always_keeps_apex_and_is_deterministic():
    candidates = _bounded_dns_candidates(
        "example.com",
        {"z.deep.example.com", "www.example.com", "api.example.com"},
        3,
    )
    assert candidates == ["example.com", "api.example.com", "www.example.com"]


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


def test_hostname_canonicalization_and_public_suffix_normalization():
    assert canonical_hostname("WWW.Example.CO.UK.") == "www.example.co.uk"
    assert registrable_domain("api.dev.example.co.uk") == "example.co.uk"


def test_wildcard_match_requires_shared_dns_evidence():
    wildcard = WildcardDnsResult(
        detected=True,
        signatures=frozenset({"A:203.0.113.10"}),
        responsive_samples=3,
    )
    matching = {
        "normalized_data": {
            "dns_records": {"A": ["203.0.113.10"]},
        }
    }
    distinct = {
        "normalized_data": {
            "dns_records": {"A": ["203.0.113.11"]},
        }
    }
    assert matches_wildcard(matching, wildcard)
    assert not matches_wildcard(distinct, wildcard)


def test_http_validation_rejects_private_or_mixed_address_sets():
    assert public_ip_set(["8.8.8.8", "2606:4700:4700::1111"])
    assert not public_ip_set(["127.0.0.1"])
    assert not public_ip_set(["8.8.8.8", "10.0.0.1"])
    assert not public_ip_set([])


def test_web_surface_parser_and_technology_fingerprints():
    parser = _PageParser()
    parser.feed(
        '<html><head><title> Example Portal </title>'
        '<meta name="generator" content="WordPress 6.8">'
        '<link rel="shortcut icon" href="/assets/icon.png"></head>'
        '<body><script src="/_next/static/app.js"></script></body></html>'
    )
    assert parser.title == "Example Portal"
    assert parser.generator == "WordPress 6.8"
    assert parser.favicon_href == "/assets/icon.png"
    technologies = _technology_names(
        httpx.Headers({"server": "cloudflare", "x-powered-by": "Express"}),
        '<script src="/_next/static/app.js"></script>',
        parser.generator,
    )
    assert {"Cloudflare", "Express", "WordPress 6.8", "Next.js"}.issubset(
        technologies
    )


def test_active_scanner_parsers_reject_noise_and_normalize_results():
    naabu = parse_naabu_jsonl(
        'not-json\n{"ip":"8.8.8.8","port":53,"protocol":"udp"}\n'
        '{"ip":"127.0.0.1","port":8000}\n'
    )
    assert len(naabu) == 1
    assert naabu[0]["entity_value"] == "8.8.8.8:53"
    assert naabu[0]["normalized_data"]["protocol"] == "udp"

    nmap = parse_nmap_xml(
        '<?xml version="1.0"?><nmaprun><host>'
        '<address addr="8.8.8.8" addrtype="ipv4"/><ports>'
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<service name="https" product="test-server" version="1.2">'
        '<cpe>cpe:/a:vendor:test-server:1.2</cpe></service></port>'
        '<port protocol="tcp" portid="22"><state state="closed"/></port>'
        '</ports></host></nmaprun>',
        "8.8.8.8",
    )
    assert len(nmap) == 1
    assert nmap[0]["normalized_data"]["service"] == "https"
    assert nmap[0]["normalized_data"]["version"] == "1.2"

    nuclei = parse_nuclei_jsonl(
        '{"template-id":"missing-hsts","matched-at":"https://example.test/",'
        '"host":"https://example.test","type":"http","info":'
        '{"name":"Missing HSTS","severity":"medium","classification":'
        '{"cve-id":["CVE-2026-0001"]}}}\n'
    )
    assert len(nuclei) == 1
    assert nuclei[0]["entity_type"] == "VULNERABILITY"
    assert nuclei[0]["severity"] == "MEDIUM"
    assert nuclei[0]["normalized_data"]["cve_ids"] == ["CVE-2026-0001"]


def test_domain_deep_analysis_gates_interactive_collectors_by_mode_and_asset_state():
    passive = {name for name, _ in _collector_specs("passive", True)}
    unverified = {name for name, _ in _collector_specs("active", False)}
    active = {name for name, _ in _collector_specs("active", True)}

    assert "web_surface" not in passive
    assert "version_detector" not in passive
    assert "web_surface" not in unverified
    assert "version_detector" not in unverified
    assert {"web_surface", "version_detector"}.issubset(active)
