import logging

import dns.asyncresolver
import dns.exception
import dns.resolver
from typing import List, Dict, Any

from collectors.base import BaseCollector, CollectorMetadata

logger = logging.getLogger("osint.dns_resolver")

class DnsResolverCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="dns_resolver",
        vector="INFRASTRUCTURE",
        description="Active DNS resolution for subdomains",
        passive=False,
        requires_api_key=False
    )

    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 5.0

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        target = target.strip().lower()
        results = {"target": target, "records": {}, "resolved_ips": []}
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME']
        
        for rtype in record_types:
            try:
                answers = await self.resolver.resolve(target, rtype)
                results["records"][rtype] = [str(rdata) for rdata in answers]
                
                # If it's an A or AAAA record, add to resolved_ips
                if rtype in ['A', 'AAAA']:
                    results["resolved_ips"].extend([str(rdata) for rdata in answers])
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                # Normal — this record type doesn't exist for this domain
                pass
            except dns.exception.Timeout:
                logger.debug("DNS %s lookup timed out for %s", rtype, target)
            except Exception as e:
                logger.warning("DNS %s lookup failed for %s: %s", rtype, target, e)
                
        # Return empty list if we didn't resolve anything useful
        if not results["records"]:
            return []
            
        return [results]

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "SUBDOMAIN",
            "entity_value": raw["target"],
            "severity": "INFO",
            "confidence": 1.0,
            "normalized_data": {
                "resolved_ips": raw["resolved_ips"],
                "dns_records": raw["records"]
            }
        }
