import asyncio

from app.services import takeover_verification
from app.services.scope import ScopeEvaluator
from app.services.takeover_verification import (
    DnsSnapshot,
    HttpFingerprintEvidence,
    build_takeover_finding,
    matched_provider_marker,
    provider_for_cnames,
    verify_takeover_candidates,
)


def _scope() -> ScopeEvaluator:
    return ScopeEvaluator(
        {
            "allowed_domains": ["example.com"],
            "excluded_domains": ["admin.example.com"],
        },
        target_type="domain",
        target="example.com",
    )


def _snapshot(
    hostname: str = "docs.example.com",
    cnames: tuple[str, ...] = ("owner.github.io",),
    addresses: tuple[str, ...] = (),
    status: str = "nxdomain",
    errors: tuple[str, ...] = (),
) -> DnsSnapshot:
    return DnsSnapshot(hostname, cnames, addresses, status, errors)


def test_provider_matching_uses_dns_label_boundaries_and_regional_s3_names():
    assert provider_for_cnames(("owner.github.io",)).name == "GitHub Pages"
    assert provider_for_cnames(("cname.vercel-dns.com",)).name == "Vercel"
    assert provider_for_cnames(("bucket.s3-website.eu-west-1.amazonaws.com",)).name == (
        "Amazon S3 website"
    )
    assert provider_for_cnames(("notgithub.io.attacker.test",)) is None


def test_provider_marker_is_specific_to_the_matched_provider():
    github = provider_for_cnames(("owner.github.io",))
    assert github is not None
    assert matched_provider_marker(
        "<h1>There isn't a GitHub Pages site here.</h1>", github
    ) == "there isn't a github pages site here"
    assert matched_provider_marker("No such app", github) is None


def test_recognized_dangling_cname_is_probable_but_not_claim_proof():
    finding = build_takeover_finding(
        _snapshot(), provider_for_cnames(("owner.github.io",)), None
    )

    assert finding is not None
    assert finding["entity_type"] == "TAKEOVER_ASSESSMENT"
    assert finding["severity"] == "HIGH"
    assert finding["normalized_data"]["status"] == "probable_dangling_provider"
    assert finding["normalized_data"]["claim_attempted"] is False
    assert "not tested" in finding["normalized_data"]["validation_limits"]


def test_provider_error_page_is_stored_as_hashed_bounded_evidence():
    evidence = HttpFingerprintEvidence(
        url="https://docs.example.com/",
        status_code=404,
        connect_ip="93.184.216.34",
        response_sha256="a" * 64,
        bytes_read=123,
        truncated=False,
        matched_marker="there isn't a github pages site here",
    )
    finding = build_takeover_finding(
        _snapshot(addresses=("93.184.216.34",), status="resolves"),
        provider_for_cnames(("owner.github.io",)),
        evidence,
    )

    assert finding is not None
    assert finding["normalized_data"]["status"] == "provider_fingerprint_matched"
    assert finding["normalized_data"]["http_evidence"]["response_sha256"] == "a" * 64
    assert "body" not in finding["normalized_data"]["http_evidence"]


def test_dns_errors_and_healthy_provider_targets_are_not_reported():
    assert build_takeover_finding(
        _snapshot(status="error", errors=("target_A:Timeout",)),
        provider_for_cnames(("owner.github.io",)),
        None,
    ) is None
    assert build_takeover_finding(
        _snapshot(addresses=("93.184.216.34",), status="resolves"),
        provider_for_cnames(("owner.github.io",)),
        None,
    ) is None


def test_batch_is_bounded_to_scoped_unique_hosts_and_does_not_fetch_dangling(monkeypatch):
    seen: list[str] = []

    class Resolver:
        async def snapshot(self, hostname: str):
            seen.append(hostname)
            return _snapshot(hostname=hostname)

    async def unexpected_fetch(*args, **kwargs):
        raise AssertionError("a DNS-dangling hostname must not be fetched")

    monkeypatch.setattr(takeover_verification, "fetch_provider_fingerprint", unexpected_fetch)
    findings = asyncio.run(verify_takeover_candidates(
        [
            "docs.example.com",
            "DOCS.EXAMPLE.COM.",
            "admin.example.com",
            "outside.test",
            "127.0.0.1",
        ],
        _scope(),
        resolver=Resolver(),
    ))

    assert seen == ["docs.example.com"]
    assert len(findings) == 1


def test_private_or_failed_resolution_prevents_http_request(monkeypatch):
    github = provider_for_cnames(("owner.github.io",))
    assert github is not None

    async def private_addresses(hostname: str):
        assert hostname == "docs.example.com"
        return []

    monkeypatch.setattr(takeover_verification, "resolve_public_addresses", private_addresses)
    result = asyncio.run(takeover_verification.fetch_provider_fingerprint(
        "docs.example.com", github
    ))
    assert result is None


def test_active_worker_takeover_branch_publishes_progress(monkeypatch):
    from app.workers import active_validation

    expected = [{"entity_type": "TAKEOVER_ASSESSMENT", "entity_value": "docs.example.com"}]
    events: list[tuple[str, dict]] = []
    scope = _scope()

    async def fake_verify(hostnames: list[str], received_scope: ScopeEvaluator):
        assert hostnames == ["docs.example.com"]
        assert received_scope is scope
        return expected

    class Publisher:
        async def publish(self, scan_id: str, event: str, payload: dict):
            assert scan_id == "scan-1"
            events.append((event, payload))

    monkeypatch.setattr(active_validation, "verify_takeover_candidates", fake_verify)
    result = asyncio.run(active_validation._run_takeover_verification(
        ["docs.example.com"], scope, Publisher(), "scan-1"
    ))

    assert result == expected
    assert events == [
        ("active_tool_started", {"tool": "takeover_verification", "targets": 1}),
        ("active_tool_completed", {"tool": "takeover_verification", "findings": 1}),
    ]
