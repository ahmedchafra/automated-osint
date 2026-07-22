"""Cloud bucket discovery collector.

Checks for publicly-exposed cloud storage buckets (AWS S3, GCP GCS,
Azure Blob Storage) matching domain-derived naming patterns.

Auto-discovered by the collector registry — no registration needed.
"""
from __future__ import annotations

from typing import Any, Dict, List

import httpx

from collectors.base import BaseCollector, CollectorMetadata


class CloudBucketCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="cloud_bucket",
        vector="SEARCH",
        description="Check for public cloud storage buckets (S3, GCP, Azure) matching domain patterns",
        passive=True,
        requires_api_key=False,
    )

    # Bucket provider templates checked for each generated name.
    BUCKET_PROVIDERS: dict[str, dict[str, str]] = {
        "s3": {
            "url_template": "https://{bucket}.s3.amazonaws.com",
            "provider": "AWS S3",
        },
        "gcs": {
            "url_template": "https://storage.googleapis.com/{bucket}",
            "provider": "GCP GCS",
        },
        "azure": {
            "url_template": "https://{bucket}.blob.core.windows.net",
            "provider": "Azure Blob",
        },
    }

    TIMEOUT = 10.0

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        names = self._generate_bucket_names(target)
        findings: list[dict] = []

        async with httpx.AsyncClient(timeout=self.TIMEOUT) as client:
            for name in names:
                for provider_key, provider_info in self.BUCKET_PROVIDERS.items():
                    url = provider_info["url_template"].format(bucket=name)
                    try:
                        resp = await client.head(url, follow_redirects=False)
                        # Any 2xx or redirect indicates the bucket exists
                        if resp.status_code < 400:
                            findings.append({
                                "type": "CLOUD_BUCKET",
                                "value": url,
                                "details": {
                                    "bucket_name": name,
                                    "provider": provider_info["provider"],
                                    "url": url,
                                    "status_code": resp.status_code,
                                    "is_public": resp.status_code in (200, 204, 301, 302, 307),
                                },
                            })
                    except Exception:
                        continue

        return findings

    def _generate_bucket_names(self, domain: str) -> list[str]:
        """Generate likely bucket names from a domain."""
        name = domain.split(".")[0]
        candidates = {
            name,
            f"{name}-prod",
            f"{name}-dev",
            f"{name}-backup",
            f"{name}-data",
            f"{name}-assets",
            domain.replace(".", "-"),
            f"{domain.replace('.', '-')}-backup",
        }
        return list(candidates)

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "CLOUD_BUCKET",
            "entity_value": raw["value"],
            "severity": "MEDIUM",
            "confidence": 0.6,
            "normalized_data": raw.get("details", {}),
        }
