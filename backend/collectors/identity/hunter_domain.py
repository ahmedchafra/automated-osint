import asyncio
from typing import Any, Dict, List

import httpx

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class HunterDomainCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="hunter_domain",
        vector="IDENTITY",
        description="Hunter.io domain email discovery (paginated, rich profiles)",
        passive=True,
        requires_api_key=True,
        api_key_env="HUNTER_API_KEY",
    )

    API_URL = "https://api.hunter.io/v2/domain-search"
    PAGE_LIMIT = 10   # Free plan caps at 10; paid plans go to 100
    RATE_DELAY = 0.1  # Hunter allows 15 req/s, this is generous

    async def _fetch_page(self, client: httpx.AsyncClient, target: str,
                          offset: int, limit: int) -> dict | None:
        """Fetch one page from the Hunter domain-search endpoint."""
        try:
            resp = await client.get(
                self.API_URL,
                params={
                    "domain": target,
                    "api_key": settings.HUNTER_API_KEY,
                    "limit": limit,
                    "offset": offset,
                },
            )
            if resp.status_code == 400:
                if offset == 0:
                    # 400 on the first page means the plan doesn't support our limit
                    # (e.g. free plan caps at 10, we request 100). Log and return
                    # empty so the caller can fall through gracefully.
                    print(f"[hunter_domain] plan limit error (first page 400): {resp.text[:200]}")
                    return None
                # Pagination exhausted: offset exceeds plan cap — stop
                return None
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            # Surface 4xx/5xx but don't crash the whole pipeline
            print(f"[hunter_domain] HTTP error at offset {offset}: {exc}")
            return None

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not settings.HUNTER_API_KEY:
            return []

        emails: list[dict] = []
        offset = 0
        total_results: int | None = None
        first_page_data: dict | None = None

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                page = await self._fetch_page(client, target, offset, self.PAGE_LIMIT)
                if page is None:
                    # 400 or unrecoverable error — stop paginating
                    break

                data = page.get("data", {})
                meta = page.get("meta", {})

                # Store first page meta for domain-level metadata
                if first_page_data is None:
                    first_page_data = data

                # Total available results (only known reliably after first page)
                if total_results is None:
                    total_results = meta.get("results", 0)

                page_emails = data.get("emails", [])
                if not page_emails:
                    break

                emails.extend(page_emails)
                offset += self.PAGE_LIMIT

                # Stop if we've fetched everything the plan allows
                if total_results is not None and len(emails) >= total_results:
                    break

                await asyncio.sleep(self.RATE_DELAY)

        results: list[dict] = emails

        # Add a single domain-metadata finding from the first page
        if first_page_data and (
            first_page_data.get("organization") or first_page_data.get("pattern")
        ):
            results.append({
                "type": "domain_metadata",
                "value": target,
                "email_pattern": first_page_data.get("pattern"),
                "organization": first_page_data.get("organization"),
                "disposable": first_page_data.get("disposable"),
                "webmail": first_page_data.get("webmail"),
                "accept_all": first_page_data.get("accept_all"),
                "linked_domains": first_page_data.get("linked_domains", []),
            })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        if raw.get("type") == "domain_metadata":
            return {
                "entity_type": "DOMAIN_METADATA",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.9,
                "normalized_data": {
                    "domain": raw["value"],
                    "organization": raw.get("organization"),
                    "email_pattern": raw.get("email_pattern"),
                    "disposable": raw.get("disposable"),
                    "webmail": raw.get("webmail"),
                    "accept_all": raw.get("accept_all"),
                    "linked_domains": raw.get("linked_domains", []),
                },
            }

        email = raw.get("value") or raw.get("email")
        return {
            "entity_type": "EMAIL",
            "entity_value": email,
            "severity": "LOW",
            "confidence": float(raw.get("confidence") or 0) / 100 if raw.get("confidence") else 0.7,
            "normalized_data": {
                "email": email,
                "type": raw.get("type"),                   # "personal" | "generic"
                "first_name": raw.get("first_name"),
                "last_name": raw.get("last_name"),
                "position": raw.get("position"),
                "position_raw": raw.get("position_raw"),
                "department": raw.get("department"),
                "seniority": raw.get("seniority"),
                "linkedin": raw.get("linkedin"),
                "twitter": raw.get("twitter"),
                "phone_number": raw.get("phone_number"),
                "sources": raw.get("sources", []),
            },
        }

