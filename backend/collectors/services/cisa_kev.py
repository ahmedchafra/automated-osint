from typing import Any, Dict, List

import httpx

from collectors.base import BaseCollector, CollectorMetadata


class CisaKevCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="cisa_kev",
        vector="SERVICES",
        description="CISA Known Exploited Vulnerabilities catalog lookup",
        passive=True,
        requires_api_key=False,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not target.upper().startswith("CVE-"):
            return []

        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            data = response.json()

        cve = target.upper()
        return [
            item
            for item in data.get("vulnerabilities", [])
            if item.get("cveID", "").upper() == cve
        ]

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "CVE",
            "entity_value": raw["cveID"],
            "severity": "CRITICAL",
            "confidence": 1.0,
            "normalized_data": {
                "cve": raw["cveID"],
                "known_exploited": True,
                "vendor": raw.get("vendorProject"),
                "product": raw.get("product"),
                "due_date": raw.get("dueDate"),
                "required_action": raw.get("requiredAction"),
            },
            "tags": ["cisa-kev", "known-exploited"],
        }

