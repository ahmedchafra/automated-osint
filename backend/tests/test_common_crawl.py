import asyncio

from collectors.search.common_crawl import (
    CommonCrawlCollector,
    _safe_capture_url,
)


def test_common_crawl_discovers_scoped_urls_and_subdomains(monkeypatch):
    collector = CommonCrawlCollector()
    collection = {
        "id": "CC-MAIN-2026-43",
        "name": "October 2026 Index",
        "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-43-index",
    }
    records = [
        {
            "url": "https://example.com/admin",
            "timestamp": "20261001000000",
            "status": "200",
            "mime": "text/html",
            "digest": "OLD",
        },
        {
            "url": "https://example.com/admin#fragment",
            "timestamp": "20261002000000",
            "status": "200",
            "mime": "text/html",
            "digest": "NEW",
        },
        {
            "url": "https://api.example.com/openapi.json",
            "timestamp": "20261003000000",
            "status": "200",
            "mime": "application/json",
            "digest": "API",
        },
        {"url": "https://notexample.com/poison", "timestamp": "20261004000000"},
        {"url": "ftp://files.example.com/archive", "timestamp": "20261005000000"},
    ]

    async def fake_collection(client):
        return collection

    async def fake_query(client, selected_collection, target):
        assert selected_collection == collection
        assert target == "example.com"
        return records

    monkeypatch.setattr(collector, "_get_latest_collection", fake_collection)
    monkeypatch.setattr(collector, "_query_collection", fake_query)

    normalized = asyncio.run(collector.execute("https://example.com/path"))
    historical = [item for item in normalized if item["entity_type"] == "HISTORICAL_URL"]
    subdomains = [item for item in normalized if item["entity_type"] == "SUBDOMAIN"]

    assert {item["entity_value"] for item in historical} == {
        "https://example.com/admin",
        "https://api.example.com/openapi.json",
    }
    admin = next(item for item in historical if item["entity_value"].endswith("/admin"))
    assert admin["normalized_data"]["timestamp"] == "20261002000000"
    assert admin["normalized_data"]["digest"] == "NEW"
    assert [item["entity_value"] for item in subdomains] == ["api.example.com"]


def test_common_crawl_capture_url_validation():
    assert _safe_capture_url("https://api.example.com:8443/v1#x", "example.com") == (
        "https://api.example.com:8443/v1",
        "api.example.com",
    )
    assert _safe_capture_url("https://evil-example.com/", "example.com") is None
    assert _safe_capture_url("https://user:pass@example.com/", "example.com") is None
