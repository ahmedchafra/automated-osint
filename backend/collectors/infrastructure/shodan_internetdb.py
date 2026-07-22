import httpx
from typing import List, Dict, Any

from collectors.base import BaseCollector, CollectorMetadata


class ShodanInternetDbCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="shodan_internetdb",
        vector="INFRASTRUCTURE",
        description="Shodan InternetDB for bulk IP enrichment (free, no API key needed)",
        passive=True,
        requires_api_key=False
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        # Target here should be an IP address
        # The scan orchestrator needs to pass IPs resolved from DNS to this collector
        # Since it only accepts IPs, we do a basic validation
        import ipaddress
        try:
            ipaddress.ip_address(target)
        except ValueError:
            # Not an IP address, ignore
            return []

        url = f"https://internetdb.shodan.io/{target}"

        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, headers=headers)

            # 404 means the IP is not in InternetDB, not necessarily an error
            if response.status_code == 404:
                return []

            response.raise_for_status()
            data = response.json()

        results: list[dict] = []

        hostnames = data.get("hostnames", [])
        tags = data.get("tags", [])
        cpes = data.get("cpes", [])

        # Extract open ports — now with full API context
        for port in data.get("ports", []):
            results.append({
                "type": "PORT_SERVICE",
                "value": f"{target}:{port}",
                "details": {
                    "port": port,
                    "ip": target,
                    "cpes": cpes,
                    "hostnames": hostnames,
                    "tags": tags,
                },
            })

        # Extract CVEs — enriched with API context
        for cve in data.get("vulns", []):
            results.append({
                "type": "CVE",
                "value": cve,
                "details": {
                    "cve": cve,
                    "ip": target,
                    "hostnames": hostnames,
                    "tags": tags,
                },
            })

        # Host metadata entry — preserves the full API snapshot
        if hostnames or tags or cpes:
            results.append({
                "type": "HOST_METADATA",
                "value": target,
                "details": {
                    "ip": target,
                    "hostnames": hostnames,
                    "tags": tags,
                    "cpes": cpes,
                    "source": "shodan_internetdb",
                },
            })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": raw["type"],
            "entity_value": raw["value"],
            "severity": "HIGH" if raw["type"] == "CVE" else "INFO",
            "confidence": 0.9,  # InternetDB is generally accurate but can be slightly outdated
            "normalized_data": raw["details"],
        }
