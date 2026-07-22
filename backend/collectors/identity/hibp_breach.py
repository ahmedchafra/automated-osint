from typing import Any, Dict, List

import httpx

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class HibpBreachCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="hibp_breach",
        vector="IDENTITY",
        description="HaveIBeenPwned breach lookup",
        passive=True,
        requires_api_key=True,
        api_key_env="HIBP_API_KEY",
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not settings.HIBP_API_KEY or "@" not in target:
            return []

        headers = {
            "hibp-api-key": settings.HIBP_API_KEY,
            "user-agent": "automated-osint-platform",
        }
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers, params={"truncateResponse": "false"})
            if response.status_code == 404:
                return []
            response.raise_for_status()
            breaches = response.json()

        return [{"email": target, **breach} for breach in breaches]

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "BREACH",
            "entity_value": raw.get("Name"),
            "severity": "HIGH" if raw.get("IsVerified") else "MEDIUM",
            "confidence": 0.95 if raw.get("IsVerified") else 0.75,
            "normalized_data": {
                "email": raw.get("email"),
                "breach_name": raw.get("Name"),
                "breach_date": raw.get("BreachDate"),
                "data_classes": raw.get("DataClasses", []),
                "verified": raw.get("IsVerified"),
            },
        }

