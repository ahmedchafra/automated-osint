"""Passive historical URL and subdomain discovery via Common Crawl CDXJ."""
from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Any
from urllib.parse import quote_plus, urlsplit, urlunsplit

import httpx

from collectors.base import BaseCollector, CollectorMetadata


COLLECTIONS_URL = "https://index.commoncrawl.org/collinfo.json"
INDEX_ORIGIN = "https://index.commoncrawl.org/"
REQUEST_TIMEOUT_SECONDS = 30.0
COLLECTION_CACHE_SECONDS = 24 * 60 * 60
MIN_REQUEST_INTERVAL_SECONDS = 1.1
MAX_INDEX_RECORDS = 1000
MAX_UNIQUE_URLS = 250
MAX_DISCOVERED_HOSTS = 100
MAX_URL_LENGTH = 4096
USER_AGENT = (
    "automated-osint-dev/0.1 "
    "(passive OSINT research collector; local development)"
)

_collection_cache: tuple[float, dict[str, Any]] | None = None
_request_lock = threading.Lock()
_last_request = 0.0


def _wait_for_request_slot() -> None:
    """Serialize this process's requests to respect the public API guidance."""
    global _last_request
    with _request_lock:
        remaining = MIN_REQUEST_INTERVAL_SECONDS - (time.monotonic() - _last_request)
        if remaining > 0:
            time.sleep(remaining)
        _last_request = time.monotonic()


def _target_hostname(target: str) -> str | None:
    value = target.strip()
    if "://" not in value:
        value = f"https://{value}"
    try:
        hostname = (urlsplit(value).hostname or "").encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    hostname = hostname.lower().rstrip(".")
    if not hostname or "." not in hostname or len(hostname) > 253:
        return None
    return hostname


def _safe_capture_url(value: object, target: str) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        return None
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
        or not hostname
        or (hostname != target and not hostname.endswith(f".{target}"))
    ):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    netloc = hostname if port is None else f"{hostname}:{port}"
    normalized = urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))
    return normalized, hostname


class CommonCrawlCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="common_crawl",
        vector="SEARCH",
        description="Common Crawl historical URL and subdomain discovery",
        passive=True,
        requires_api_key=False,
    )

    async def _get_latest_collection(
        self, client: httpx.AsyncClient
    ) -> dict[str, Any] | None:
        global _collection_cache
        if (
            _collection_cache is not None
            and time.monotonic() - _collection_cache[0] < COLLECTION_CACHE_SECONDS
        ):
            return _collection_cache[1]

        await asyncio.to_thread(_wait_for_request_slot)
        response = await client.get(COLLECTIONS_URL)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, list):
            return None
        for item in payload:
            if not isinstance(item, dict):
                continue
            api_url = item.get("cdx-api")
            collection_id = item.get("id")
            if (
                isinstance(api_url, str)
                and api_url.startswith(INDEX_ORIGIN)
                and isinstance(collection_id, str)
                and collection_id.startswith("CC-MAIN-")
            ):
                _collection_cache = (time.monotonic(), item)
                return item
        return None

    async def _query_collection(
        self,
        client: httpx.AsyncClient,
        collection: dict[str, Any],
        target: str,
    ) -> list[dict[str, Any]]:
        await asyncio.to_thread(_wait_for_request_slot)
        response = await client.get(
            str(collection["cdx-api"]),
            params={
                "url": target,
                "matchType": "domain",
                "output": "json",
                "fl": "url,timestamp,status,mime,digest,length,offset,filename",
                "filter": "status:200",
                "limit": str(MAX_INDEX_RECORDS),
            },
        )
        if response.status_code == 404:
            return []
        response.raise_for_status()

        records: list[dict[str, Any]] = []
        for line in response.text.splitlines()[:MAX_INDEX_RECORDS]:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
        return records

    async def collect(self, target: str) -> list[dict[str, Any]]:
        hostname = _target_hostname(target)
        if hostname is None:
            return []
        headers = {"Accept": "application/x-ndjson", "User-Agent": USER_AGENT}
        async with httpx.AsyncClient(
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as client:
            collection = await self._get_latest_collection(client)
            if collection is None:
                return []
            records = await self._query_collection(client, collection, hostname)

        captures: dict[str, dict[str, Any]] = {}
        discovered_hosts: dict[str, str] = {}
        for record in records:
            safe_url = _safe_capture_url(record.get("url"), hostname)
            if safe_url is None:
                continue
            url, captured_host = safe_url
            capture = {
                "type": "HISTORICAL_URL",
                "value": url,
                "capture": record,
                "collection": {
                    "id": collection.get("id"),
                    "name": collection.get("name"),
                    "from": collection.get("from"),
                    "to": collection.get("to"),
                    "index_url": str(collection.get("cdx-api")),
                },
            }
            previous = captures.get(url)
            if previous is None or str(record.get("timestamp", "")) > str(
                previous.get("capture", {}).get("timestamp", "")
            ):
                captures[url] = capture
            if captured_host != hostname:
                discovered_hosts.setdefault(captured_host, url)

        selected = sorted(
            captures.values(),
            key=lambda item: (
                str(item["value"]).count("/"),
                len(str(item["value"])),
                str(item["value"]),
            ),
        )[:MAX_UNIQUE_URLS]
        host_findings = [
            {
                "type": "SUBDOMAIN",
                "value": host,
                "evidence_url": evidence_url,
                "collection": {"id": collection.get("id")},
            }
            for host, evidence_url in sorted(discovered_hosts.items())
        ][:MAX_DISCOVERED_HOSTS]
        return [*host_findings, *selected]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if raw.get("type") == "SUBDOMAIN":
            return {
                "entity_type": "SUBDOMAIN",
                "entity_value": raw.get("value", ""),
                "severity": "INFO",
                "confidence": 0.9,
                "normalized_data": {
                    "historical_evidence_url": raw.get("evidence_url"),
                    "common_crawl_index": raw.get("collection", {}).get("id"),
                },
                "tags": ["historical", "common-crawl"],
            }

        capture = raw.get("capture") or {}
        collection = raw.get("collection") or {}
        filename = str(capture.get("filename") or "")
        index_api = str(collection.get("index_url") or "")
        value = str(raw.get("value") or "")
        return {
            "entity_type": "HISTORICAL_URL",
            "entity_value": value,
            "severity": "INFO",
            "confidence": 0.9,
            "normalized_data": {
                "original_url": value,
                "timestamp": capture.get("timestamp", ""),
                "status_code": capture.get("status", ""),
                "mime_type": capture.get("mime", ""),
                "content_type": capture.get("mime", ""),
                "content_length": (
                    int(str(capture.get("length")))
                    if str(capture.get("length") or "").isdigit()
                    else 0
                ),
                "digest": capture.get("digest", ""),
                "archive_source": "Common Crawl",
                "common_crawl_index": collection.get("id"),
                "common_crawl_name": collection.get("name"),
                "index_url": (
                    f"{index_api}?url={quote_plus(value)}&output=json" if index_api else ""
                ),
                "warc_filename": filename,
                "warc_offset": capture.get("offset", ""),
                "warc_url": f"https://data.commoncrawl.org/{filename}" if filename else "",
            },
            "tags": ["historical", "common-crawl"],
        }
