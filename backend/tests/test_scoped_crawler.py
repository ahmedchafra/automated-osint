import asyncio

from app.services import scoped_crawler
from app.services.scope import ScopeEvaluator
from app.services.scoped_crawler import (
    FetchResult,
    automatic_fetch_decision,
    canonicalize_url,
    crawl_urls,
    endpoint_template,
    parse_html_surface,
    resolve_public_addresses,
)


def _scope() -> ScopeEvaluator:
    return ScopeEvaluator(
        {
            "allowed_domains": ["example.com"],
            "excluded_domains": ["admin.example.com"],
            "excluded_url_paths": ["/private/*"],
            "allowed_ports": [80, 443],
        },
        target_type="domain",
        target="example.com",
    )


def _response(url: str, body: str, *, status: int = 200, location: str | None = None) -> FetchResult:
    return FetchResult(
        url=url,
        status=status,
        content_type="text/html",
        headers={"content-type": "text/html"},
        body=body,
        bytes_read=len(body.encode()),
        truncated=False,
        redirect_location=location,
        connect_ip="93.184.216.34",
    )


def test_html_parser_extracts_links_scripts_and_form_field_names_only():
    page = parse_html_surface("""
        <html><head><title> Test  Portal </title><base href="/app/"></head>
        <body>
          <a href="users">Users</a><script src="/static/app.js"></script>
          <form action="/session" method="post">
            <input name="username" value="must-not-be-kept">
            <input name="password" type="password" value="secret">
            <button name="submit" value="yes">Login</button>
          </form>
        </body></html>
    """)

    assert page.title == "Test Portal"
    assert page.base_href == "/app/"
    assert page.links == ("users",)
    assert page.scripts == ("/static/app.js",)
    assert page.forms[0].method == "POST"
    assert page.forms[0].fields == (
        {"name": "username", "type": "input"},
        {"name": "password", "type": "password"},
        {"name": "submit", "type": "button"},
    )
    assert "secret" not in str(page.forms)


def test_url_normalization_templates_and_automatic_fetch_policy():
    scope = _scope()

    assert canonicalize_url("HTTPS://EXAMPLE.COM:443/a#fragment") == "https://example.com/a"
    assert canonicalize_url("https://user:pass@example.com/") is None
    assert endpoint_template("https://example.com/search?token=secret&q=hello&q=again") == (
        "https://example.com/search?q&token"
    )
    assert automatic_fetch_decision("https://example.com/about", scope)[0]
    assert not automatic_fetch_decision("https://example.com/search?q=value", scope)[0]
    assert not automatic_fetch_decision("https://example.com/delete/account", scope)[0]
    assert not automatic_fetch_decision("https://example.com/archive.zip", scope)[0]
    assert not automatic_fetch_decision("https://admin.example.com/", scope)[0]


def test_private_addresses_are_rejected_before_connection():
    assert asyncio.run(resolve_public_addresses("127.0.0.1")) == []
    assert asyncio.run(resolve_public_addresses("::1")) == []


def test_scoped_crawl_discovers_surface_without_fetching_risky_links(monkeypatch):
    root = "https://example.com/"
    about = "https://example.com/about"
    fetched: list[str] = []
    pages = {
        root: _response(root, """
            <html><head><title>Home</title></head><body>
              <a href="/about">About</a>
              <a href="/delete/account">Delete</a>
              <a href="/search?q=hello&token=secret">Search</a>
              <a href="https://outside.test/elsewhere">External</a>
              <script src="/assets/app.js"></script>
              <form action="/login" method="post">
                <input name="username"><input name="password" type="password">
              </form>
            </body></html>
        """),
        about: _response(about, '<a href="/">Home</a>'),
    }

    async def fake_fetch(url: str, scope: ScopeEvaluator):
        fetched.append(url)
        return pages.get(url)

    monkeypatch.setattr(scoped_crawler, "_fetch_page", fake_fetch)
    findings = asyncio.run(crawl_urls([root], _scope()))

    assert fetched == [root, about]
    assert {finding["entity_value"] for finding in findings if finding["entity_type"] == "CRAWLED_PAGE"} == {
        root, about,
    }
    endpoints = {
        finding["entity_value"]: finding["normalized_data"]
        for finding in findings if finding["entity_type"] == "WEB_ENDPOINT"
    }
    assert endpoints[about]["crawl_eligible"] is True
    assert endpoints["https://example.com/delete/account"]["crawl_eligible"] is False
    assert endpoints["https://example.com/search?q&token"]["crawl_eligible"] is False
    assert "secret" not in str(findings)
    assert not any("outside.test" in finding["entity_value"] for finding in findings)

    forms = [finding for finding in findings if finding["entity_type"] == "WEB_FORM"]
    assert len(forms) == 1
    assert forms[0]["normalized_data"]["submitted"] is False
    assert {item["name"] for item in forms[0]["normalized_data"]["fields"]} == {
        "username", "password",
    }
    assert [finding["entity_value"] for finding in findings if finding["entity_type"] == "JAVASCRIPT_ASSET"] == [
        "https://example.com/assets/app.js"
    ]


def test_redirect_is_scope_checked_and_followed_as_a_separate_request(monkeypatch):
    root = "https://example.com/"
    next_url = "https://example.com/next"
    fetched: list[str] = []

    async def fake_fetch(url: str, scope: ScopeEvaluator):
        fetched.append(url)
        if url == root:
            return _response(root, "", status=302, location="/next")
        return _response(next_url, "<title>Next</title>")

    monkeypatch.setattr(scoped_crawler, "_fetch_page", fake_fetch)
    findings = asyncio.run(crawl_urls([root], _scope()))

    assert fetched == [root, next_url]
    redirect = next(
        finding for finding in findings
        if finding["entity_type"] == "WEB_ENDPOINT" and finding["entity_value"] == next_url
    )
    assert redirect["normalized_data"]["discovered_by"] == "redirect"


def test_active_worker_crawl_branch_publishes_progress(monkeypatch):
    from app.workers import active_validation

    expected = [{"entity_type": "CRAWLED_PAGE", "entity_value": "https://example.com/"}]
    events: list[tuple[str, dict]] = []
    scope = _scope()

    async def fake_crawl(urls: list[str], received_scope: ScopeEvaluator):
        assert urls == ["https://example.com/"]
        assert received_scope is scope
        return expected

    class Publisher:
        async def publish(self, scan_id: str, event: str, payload: dict):
            assert scan_id == "scan-1"
            events.append((event, payload))

    monkeypatch.setattr(active_validation, "crawl_urls", fake_crawl)
    result = asyncio.run(active_validation._run_scoped_crawl(
        ["https://example.com/"], scope, Publisher(), "scan-1"
    ))

    assert result == expected
    assert events == [
        ("active_tool_started", {"tool": "scoped_crawler", "targets": 1}),
        ("active_tool_completed", {"tool": "scoped_crawler", "findings": 1}),
    ]
