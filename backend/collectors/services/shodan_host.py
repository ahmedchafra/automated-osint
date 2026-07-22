import ipaddress
from typing import Any, Dict, List

import httpx

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class ShodanHostCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="shodan_host",
        vector="SERVICES",
        description="Shodan host enrichment (ports, banners, TLS, vulns, ASN)",
        passive=True,
        requires_api_key=True,
        api_key_env="SHODAN_API_KEY",
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not settings.SHODAN_API_KEY:
            return []
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return []

        url = f"https://api.shodan.io/shodan/host/{target}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, params={"key": settings.SHODAN_API_KEY})
            if response.status_code == 404:
                return []
            if response.status_code == 403:
                return []
            response.raise_for_status()
            data = response.json()

        findings = []

        # 1. Services/ports with rich banner data
        for service in data.get("data", []):
            port = service.get("port")
            if port:
                findings.append({
                    "type": "PORT_SERVICE",
                    "value": f"{target}:{port}",
                    "details": {
                        "ip": target,
                        "port": port,
                        "transport": service.get("transport"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "hostnames": data.get("hostnames", []),
                        "cpes": service.get("cpe", []),
                        "banner": service.get("banner", ""),
                        "devicetype": service.get("devicetype", ""),
                        "info": service.get("info", ""),
                        "cpe23": service.get("cpe23", []),
                        "tags": service.get("tags", []),
                        "vulns": service.get("vulns", {}),
                        "ssl": service.get("ssl", {}),
                        "location": service.get("location", {}),
                    },
                })

        # 2. TECHNOLOGY extraction from software/product data per service
        seen_tech = set()
        for service in data.get("data", []):
            product = service.get("product")
            if product:
                version = service.get("version")
                tech_value = f"{product} {version}".strip() if version else product
                if tech_value not in seen_tech:
                    seen_tech.add(tech_value)
                    findings.append({
                        "type": "TECHNOLOGY",
                        "value": tech_value,
                        "details": {
                            "ip": target,
                            "port": service.get("port"),
                            "product": product,
                            "version": version,
                            "cpes": service.get("cpe", []),
                            "category": service.get("devicetype", "software"),
                        },
                    })

        # 3. ASN/ISP metadata
        if data.get("asn") or data.get("isp"):
            findings.append({
                "type": "HOST_METADATA",
                "value": target,
                "details": {
                    "ip": target,
                    "asn": data.get("asn"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "os": data.get("os"),
                    "hostnames": data.get("hostnames", []),
                    "domains": data.get("domains", []),
                    "tags": data.get("tags", []),
                    "ports": data.get("ports", []),
                    "location": {
                        "country": data.get("country_name"),
                        "country_code": data.get("country_code"),
                        "region": data.get("region_name"),
                        "city": data.get("city"),
                        "latitude": data.get("latitude"),
                        "longitude": data.get("longitude"),
                    },
                },
            })

        # 4. Direct CVEs from Shodan
        vulns = data.get("vulns", {})
        for cve_id in vulns.keys():
            findings.append({
                "type": "CVE",
                "value": cve_id,
                "details": {
                    "ip": target,
                    "cve": cve_id,
                    "references": vulns[cve_id].get("references", []),
                    "verified": vulns[cve_id].get("verified", False),
                },
            })

        # 5. TLS certificates from Shodan
        for service in data.get("data", []):
            ssl = service.get("ssl", {})
            cert = ssl.get("cert", {})
            if cert.get("fingerprint"):
                fp = cert.get("fingerprint", "")
                if isinstance(fp, dict):
                    fp = fp.get("sha256", fp.get("sha1", str(fp)))
                findings.append({
                    "type": "TLS_CERT",
                    "value": fp,
                    "details": {
                        "ip": target,
                        "port": service.get("port"),
                        "subject": cert.get("subject", {}),
                        "issuer": cert.get("issuer", {}),
                        "fingerprint": fp,
                        "serial": cert.get("serial"),
                        "expires": cert.get("expires"),
                        "issued": cert.get("issued"),
                        "version": cert.get("version"),
                        "expired": cert.get("expired", False),
                    },
                })

        # 5. DNS/Domain info
        if data.get("hostnames") or data.get("domains"):
            findings.append({
                "type": "DNS_RECORD",
                "value": target,
                "details": {
                    "ip": target,
                    "hostnames": data.get("hostnames", []),
                    "domains": data.get("domains", []),
                },
            })

        return findings

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        raw_type = raw.get("type", "")
        details = raw.get("details", {})

        if raw_type == "PORT_SERVICE":
            return {
                "entity_type": "PORT_SERVICE",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.9,
                "normalized_data": details,
            }
        elif raw_type == "HOST_METADATA":
            return {
                "entity_type": "HOST_METADATA",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.85,
                "normalized_data": details,
            }
        elif raw_type == "CVE":
            return {
                "entity_type": "CVE",
                "entity_value": raw["value"],
                "severity": "HIGH",
                "confidence": 0.9,
                "normalized_data": details,
            }
        elif raw_type == "TLS_CERT":
            return {
                "entity_type": "TLS_CERT",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.95,
                "normalized_data": details,
            }
        elif raw_type == "TECHNOLOGY":
            return {
                "entity_type": "TECHNOLOGY",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.85,
                "normalized_data": details,
            }
        elif raw_type == "DNS_RECORD":
            return {
                "entity_type": "DNS_RECORD",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.8,
                "normalized_data": details,
            }

        return {
            "entity_type": raw_type,
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.7,
            "normalized_data": details,
        }
