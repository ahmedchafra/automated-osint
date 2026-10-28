import asyncio
import ipaddress

from collectors.infrastructure.rdap_lookup import (
    RdapCollector,
    _domain_details,
    _https_service,
    _ip_service,
    _registered_domain,
)


def test_rdap_bootstrap_selects_domain_and_most_specific_ip_service():
    services = [
        [["com", "net"], ["http://ignored.example", "https://rdap.registry.example/"]],
    ]
    assert _https_service(services, "COM") == "https://rdap.registry.example/"

    networks = [
        [["0.0.0.0/0"], ["https://rdap.default.example"]],
        [["203.0.113.0/24"], ["https://rdap.specific.example/"]],
    ]
    assert _ip_service(networks, ipaddress.ip_address("203.0.113.25")) == (
        "https://rdap.specific.example/"
    )


def test_rdap_domain_normalization_extracts_structured_registration_data():
    payload = {
        "handle": "EXAMPLE-HANDLE",
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        ],
        "entities": [{
            "handle": "376",
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
        }],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.NET."}],
        "secureDNS": {"delegationSigned": True},
    }
    details = _domain_details(payload, "example.com", "https://rdap.example/")
    normalized = RdapCollector().normalize({
        "type": "DOMAIN_METADATA", "value": "example.com", "details": details
    })

    assert _registered_domain("www.Example.CO.UK.") == "example.co.uk"
    assert details["registrar"] == "Example Registrar"
    assert details["name_servers"] == ["ns1.example.net"]
    assert details["dnssec"] is True
    assert normalized["entity_type"] == "DOMAIN_METADATA"
    assert normalized["confidence"] == 0.95


def test_registration_pipeline_bounds_only_rdap_ip_fanout(monkeypatch):
    from app.workers import initial_scan

    calls: list[tuple[str, str]] = []

    async def fake_run_tool(name, target, scan_id, session, publisher):
        calls.append((name, target))
        return [{"entity_value": target}]

    async def fake_persist(session, scan_id, findings):
        return len(findings)

    monkeypatch.setattr(initial_scan, "_run_tool", fake_run_tool)
    monkeypatch.setattr(initial_scan, "persist_findings", fake_persist)
    ips = {f"198.51.100.{index}" for index in range(1, 31)}

    created = asyncio.run(initial_scan._run_registration_enrichment(
        "example.com", ips, "scan-id", object(), object()
    ))

    assert len([call for call in calls if call[0] == "whois_lookup"]) == 31
    assert len([call for call in calls if call[0] == "rdap_lookup"]) == 26
    assert len([call for call in calls if call[0] == "ripestat"]) == 25
    assert created == 82
