import httpx
from typing import List, Dict, Any

from collectors.base import BaseCollector, CollectorMetadata


class CrtshCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="crtsh",
        vector="INFRASTRUCTURE",
        description="Certificate Transparency logs subdomain enumeration",
        passive=True,
        requires_api_key=False
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        # Remove any protocol prefixes or trailing slashes
        target = target.replace("https://", "").replace("http://", "").split("/")[0]

        url = f"https://crt.sh/?q=%.{target}&output=json"

        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()

        results: list[dict] = []
        seen_serials: set[str] = set()
        seen_subdomains: set[str] = set()

        for entry in data:
            serial = str(entry.get("serial_number", ""))
            if not serial or serial in seen_serials:
                continue
            seen_serials.add(serial)

            # Extract unique subdomains from this cert entry
            subdomains: set[str] = set()
            for d in entry.get("name_value", "").split("\n"):
                d = d.strip().lower()
                if d.endswith(target) and not d.startswith("*"):
                    subdomains.add(d)
                    seen_subdomains.add(d)

            # Emit a TLS_CERT entry with full cert metadata
            results.append({
                "type": "TLS_CERT",
                "value": f"crtsh::{serial}",
                "cert_details": {
                    "source": "crtsh",
                    "target_domain": target,
                    "serial_number": serial,
                    "issuer_name": entry.get("issuer_name", ""),
                    "common_name": entry.get("common_name", ""),
                    "entry_timestamp": entry.get("entry_timestamp", ""),
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                    "id": entry.get("id"),
                    "subdomains": list(subdomains),
                },
            })

            # Emit one SUBDOMAIN per unique subdomain from this cert
            for sub in subdomains:
                if sub not in seen_subdomains:
                    seen_subdomains.add(sub)
                results.append({
                    "type": "SUBDOMAIN",
                    "value": sub,
                    "source": "crtsh",
                    "cert_serial": serial,
                })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        raw_type = raw.get("type", "")

        if raw_type == "TLS_CERT":
            cd = raw.get("cert_details", {})
            return {
                "entity_type": "TLS_CERT",
                "entity_value": raw.get("value", ""),
                "severity": "INFO",
                "confidence": 0.85,
                "normalized_data": {
                    "source": "crtsh",
                    "ip": "",  # crt.sh doesn't provide IP
                    "subject": {"CN": cd.get("common_name", "")},
                    "issuer": {"CN": cd.get("issuer_name", "")},
                    "serial": cd.get("serial_number", ""),
                    "not_before": cd.get("not_before", ""),
                    "not_after": cd.get("not_after", ""),
                    "entry_timestamp": cd.get("entry_timestamp", ""),
                    "crt_sh_id": cd.get("id"),
                    "subdomains_covered": cd.get("subdomains", []),
                },
            }

        # Default: SUBDOMAIN
        return {
            "entity_type": "SUBDOMAIN",
            "entity_value": raw.get("value", raw.get("subdomain", "")),
            "severity": "INFO",
            "confidence": 1.0,
            "normalized_data": {
                "source": "crtsh",
                "subdomain": raw.get("value", raw.get("subdomain", "")),
                "cert_serial": raw.get("cert_serial", ""),
            },
        }
