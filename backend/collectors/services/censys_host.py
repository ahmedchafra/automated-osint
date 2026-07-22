import asyncio
import ipaddress
import logging
from typing import Any, Dict, List

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata

try:
    from censys_platform import SDK
    from censys_platform.models import SDKBaseError
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

logger = logging.getLogger("osint.censys_host")


class CensysHostCollector(BaseCollector):
    """Censys Platform v3 host enrichment via the official censys-platform SDK.

    Uses a Personal Access Token (PAT) for authentication.
    Free tier: 100 credits/month, 1 credit per host lookup.
    """

    metadata = CollectorMetadata(
        name="censys_host",
        vector="SERVICES",
        description="Censys Platform v3 host enrichment (PAT via censys-platform SDK)",
        passive=True,
        requires_api_key=True,
        api_key_env="CENSYS_API_SECRET",
    )

    def _get_client(self) -> "SDK":
        if not CENSYS_AVAILABLE:
            raise RuntimeError("censys-platform SDK not installed")
        token = settings.CENSYS_API_SECRET
        return SDK(personal_access_token=token)

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        if not CENSYS_AVAILABLE or not settings.CENSYS_API_SECRET:
            return []
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return []

        findings: List[Dict[str, Any]] = []
        try:
            host_data = await asyncio.wait_for(
                asyncio.to_thread(self._query_host, target),
                timeout=30,
            )
            if host_data is not None:
                findings.extend(self._extract_findings(host_data, target))
        except asyncio.TimeoutError:
            logger.warning("Censys host lookup timed out for %s", target)
        except SDKBaseError as e:
            logger.warning("Censys SDK error for %s: %s", target, e)
        except Exception as e:
            logger.exception("Censys host lookup failed for %s: %s", target, e)

        return findings

    def _query_host(self, target: str) -> Any:
        """Synchronous Censys SDK query — runs in executor thread."""
        with self._get_client() as sdk:
            return sdk.global_data.get_host(host_id=target)

    def _extract_findings(self, host_data: Any, target: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        # Convert SDK object to dict if needed
        if hasattr(host_data, "__dict__"):
            host_dict = self._object_to_dict(host_data)
        elif isinstance(host_data, dict):
            host_dict = host_data
        else:
            return findings

        # 1. Services/ports
        for service in host_dict.get("services", []):
            port = service.get("port")
            if not port:
                continue
            findings.append({
                "type": "PORT_SERVICE",
                "value": f"{target}:{port}",
                "details": {
                    "ip": target,
                    "port": port,
                    "service_name": service.get("service_name"),
                    "transport_protocol": service.get("transport_protocol"),
                    "banner": service.get("banner"),
                    "banner_hex": service.get("banner_hex"),
                    "tls": service.get("tls", {}),
                    "software": service.get("software", []),
                    "vulnerabilities": service.get("vulnerabilities", []),
                    "observed_at": service.get("observed_at"),
                    "extended_service_name": service.get("extended_service_name"),
                },
            })

        # 2. TECHNOLOGY extraction from software data per service
        seen_tech = set()
        for service in host_dict.get("services", []):
            for sw in service.get("software", []):
                product = sw.get("product", "") or sw.get("name", "")
                version = sw.get("version", "")
                if product:
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
                                "cpe": sw.get("cpe", ""),
                                "category": service.get("service_name", "software"),
                            },
                        })

        # 3. Host metadata (ASN, location, OS)
        asn = host_dict.get("autonomous_system", {}) or {}
        location = host_dict.get("location", {}) or {}
        os_data = host_dict.get("operating_system", {}) or {}

        if asn or location or os_data:
            software_cpes: list[str] = []
            for svc in host_dict.get("services", []):
                for sw in svc.get("software", []):
                    cpe = sw.get("cpe", "")
                    if cpe and cpe.startswith("cpe:"):
                        software_cpes.append(cpe)

            findings.append({
                "type": "HOST_METADATA",
                "value": target,
                "details": {
                    "ip": target,
                    "asn": {
                        "number": asn.get("asn"),
                        "name": asn.get("name"),
                        "description": asn.get("description"),
                        "bgp_prefix": asn.get("bgp_prefix"),
                        "country_code": asn.get("country_code"),
                    },
                    "location": {
                        "continent": location.get("continent"),
                        "country": location.get("country"),
                        "country_code": location.get("country_code"),
                        "city": location.get("city"),
                        "postal_code": location.get("postal_code"),
                        "timezone": location.get("timezone"),
                        "province": location.get("province"),
                        "coordinates": location.get("coordinates"),
                    },
                    "operating_system": os_data,
                    "tags": host_dict.get("tags", []),
                    "cpes": software_cpes[:20],
                },
            })

        # 4. DNS data
        dns = host_dict.get("dns", {}) or {}
        dns_names = dns.get("names", [])
        forward_dns = dns.get("forward_dns", {}) or {}
        reverse_dns = dns.get("reverse_dns", {}) or {}

        if dns_names or forward_dns or reverse_dns:
            findings.append({
                "type": "DNS_RECORD",
                "value": target,
                "details": {
                    "ip": target,
                    "dns_names": dns_names[:50] if dns_names else [],
                    "reverse_dns": reverse_dns,
                    "forward_dns_sample": dict(list(forward_dns.items())[:10]) if forward_dns else {},
                    "forward_dns_total": len(forward_dns) if forward_dns else 0,
                },
            })

        # 5. TLS certificates from services
        for service in host_dict.get("services", []):
            tls = service.get("tls", {}) or {}
            if not tls:
                continue
            cert = tls.get("certificate", {}) or {}
            if cert.get("fingerprint_sha256"):
                findings.append({
                    "type": "TLS_CERT",
                    "value": cert.get("fingerprint_sha256", ""),
                    "details": {
                        "ip": target,
                        "port": service.get("port"),
                        "subject": cert.get("subject", {}),
                        "issuer": cert.get("issuer", {}),
                        "fingerprint_sha256": cert.get("fingerprint_sha256"),
                        "fingerprint_sha1": cert.get("fingerprint_sha1"),
                        "names": cert.get("names", []),
                        "validity_start": cert.get("validity", {}).get("start") if cert.get("validity") else None,
                        "validity_end": cert.get("validity", {}).get("end") if cert.get("validity") else None,
                        "version": cert.get("version"),
                        "self_signed": cert.get("self_signed", False),
                    },
                })

        # 6. Vulnerabilities from services
        for service in host_dict.get("services", []):
            for vuln in service.get("vulnerabilities", []):
                findings.append({
                    "type": "CVE",
                    "value": vuln.get("cve", ""),
                    "details": {
                        "ip": target,
                        "port": service.get("port"),
                        "cve": vuln.get("cve"),
                        "severity": vuln.get("severity"),
                        "cvss": vuln.get("cvss"),
                        "description": vuln.get("description", ""),
                        "exploit_available": vuln.get("exploit_available"),
                        "patch_available": vuln.get("patch_available"),
                    },
                })

        return findings

    def _object_to_dict(self, obj: Any) -> Dict[str, Any]:
        """Recursively convert SDK Pydantic model objects to plain dicts."""
        if isinstance(obj, dict):
            return {k: self._object_to_dict(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._object_to_dict(item) for item in obj]
        # Pydantic v2 models
        if hasattr(obj, "model_dump"):
            return self._object_to_dict(obj.model_dump())
        # Pydantic v1 models
        if hasattr(obj, "dict"):
            return self._object_to_dict(obj.dict())
        if hasattr(obj, "__dict__"):
            return {k: self._object_to_dict(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
        if hasattr(obj, "__slots__"):
            return {slot: self._object_to_dict(getattr(obj, slot)) for slot in obj.__slots__ if hasattr(obj, slot)}
        return obj

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        raw_type = raw.get("type", "")
        details = raw.get("details", {})

        if raw_type == "PORT_SERVICE":
            return {
                "entity_type": "PORT_SERVICE",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.92,
                "normalized_data": details,
            }
        elif raw_type == "HOST_METADATA":
            return {
                "entity_type": "HOST_METADATA",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.9,
                "normalized_data": details,
            }
        elif raw_type == "DNS_RECORD":
            return {
                "entity_type": "DNS_RECORD",
                "entity_value": raw["value"],
                "severity": "INFO",
                "confidence": 0.85,
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
        elif raw_type == "CVE":
            severity_map = {
                "LOW": "LOW", "MEDIUM": "MEDIUM",
                "HIGH": "HIGH", "CRITICAL": "CRITICAL",
            }
            return {
                "entity_type": "CVE",
                "entity_value": raw["value"],
                "severity": severity_map.get(details.get("severity", ""), "HIGH"),
                "confidence": 0.95,
                "normalized_data": details,
            }

        return {
            "entity_type": raw_type,
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.7,
            "normalized_data": details,
        }
