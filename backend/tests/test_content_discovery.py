import asyncio

from app.services import content_discovery
from app.services.content_discovery import ProbeResponse, discover_content
from app.services.scope import ScopeEvaluator


def _scope() -> ScopeEvaluator:
    return ScopeEvaluator(
        {
            "allowed_domains": ["example.com"],
            "excluded_url_paths": ["/private/*"],
            "allowed_ports": [443],
        },
        target_type="domain",
        target="example.com",
    )


def _response(url: str, body: str, status: int = 200, content_type: str = "text/html") -> ProbeResponse:
    import hashlib

    raw = body.encode()
    return ProbeResponse(
        url=url,
        status=status,
        content_type=content_type,
        content_length=len(raw),
        body_sha256=hashlib.sha256(raw).hexdigest(),
        body_text=body,
        bytes_read=len(raw),
        truncated=False,
        redirect_location=None,
        connect_ip="93.184.216.34",
    )


def test_common_profile_suppresses_custom_404_and_stores_no_body(monkeypatch):
    async def fake_fetch(url: str, scope: ScopeEvaluator):
        if ".__owl_missing_" in url:
            return _response(url, "Not found", status=200)
        if url.endswith("/robots.txt"):
            return _response(url, "User-agent: *\nDisallow: /internal", content_type="text/plain")
        return _response(url, "Not found", status=200)

    monkeypatch.setattr(content_discovery, "_fetch_probe", fake_fetch)
    findings = asyncio.run(discover_content(["https://example.com/app"], _scope(), "common"))

    assert [item["entity_value"] for item in findings] == ["https://example.com/robots.txt"]
    normalized = findings[0]["normalized_data"]
    assert normalized["response_body_stored"] is False
    assert normalized["baseline_compared"] is True
    assert "Disallow" not in str(findings)


def test_exposure_marker_raises_confidence_without_persisting_secret(monkeypatch):
    secret_body = "APP_KEY=do-not-store-this-value"

    async def fake_fetch(url: str, scope: ScopeEvaluator):
        if ".__owl_missing_" in url:
            return _response(url, "missing", status=404)
        if url.endswith("/.env"):
            return _response(url, secret_body, content_type="text/plain")
        return _response(url, "missing", status=404)

    monkeypatch.setattr(content_discovery, "_fetch_probe", fake_fetch)
    findings = asyncio.run(discover_content(["https://example.com/"], _scope(), "exposure"))

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["normalized_data"]["marker_id"] == "environment_assignment"
    assert "do-not-store-this-value" not in str(findings)


def test_private_and_out_of_scope_roots_are_never_probed(monkeypatch):
    fetched: list[str] = []

    async def fake_fetch(url: str, scope: ScopeEvaluator):
        fetched.append(url)
        return None

    monkeypatch.setattr(content_discovery, "_fetch_probe", fake_fetch)
    findings = asyncio.run(discover_content(
        ["http://127.0.0.1/", "https://outside.test/"], _scope(), "common",
    ))

    assert findings == []
    assert fetched == []
