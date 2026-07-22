"""XposedOrNot breach collector.

Free API — no API key required.
Endpoints:
  GET /v1/check-email/{email}          — basic breach check
  GET /v1/breach-analytics?email={email} — detailed analytics with risk score
  GET /v1/breaches?domain={domain}     — all breaches for a domain

Rate limit: 2 req/sec per IP.
Docs: https://xposedornot.com/api
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import httpx

from collectors.base import BaseCollector, CollectorMetadata


class XposedOrNotBreachCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="xposedornot_breach",
        vector="IDENTITY",
        description="XposedOrNot email breach & paste lookup (free, no API key)",
        passive=True,
        requires_api_key=False,
    )

    BASE_URL = "https://api.xposedornot.com"

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Check an email against XposedOrNot breach and paste databases.

        Uses only the breach-analytics endpoint (1 req/email instead of 2).
        The check-email endpoint is stricter rate-limited and its data
        (breach count, names) is a subset of what breach-analytics returns.
        """
        if "@" not in target:
            return []

        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "application/json",
        }

        results: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(
            base_url=self.BASE_URL, timeout=30.0, headers=headers
        ) as client:
            data = await self._get_with_retry(
                client, "/v1/breach-analytics", params={"email": target}, max_retries=8
            )
            if data:
                # Skip emails with no breach hits — otherwise we'd create
                # empty BREACH findings for every email scanned, which pollutes
                # the UI with "1 breach" badges that show nothing when expanded.
                exposed = data.get("ExposedBreaches")
                breaches_details = (exposed.get("breaches_details") or []) if exposed else []
                if not breaches_details:
                    return []

                summary = data.get("BreachesSummary") or {}
                metrics = data.get("BreachMetrics") or {}
                pastes_summary = data.get("PastesSummary") or {}
                exposed_pastes = data.get("ExposedPastes", {})

                results.append({
                    "email": target,
                    "source": "breach-analytics",
                    "breach_count": summary.get("breach_count", 0),
                    "breaches_details": exposed.get("breaches_details") or [],
                    "risk_score": metrics.get("risk_score", 0),
                    "xposed_data_count": len(data.get("xposed_data") or []),
                    "paste_count": pastes_summary.get("paste_count", 0),
                    "paste_details": (exposed_pastes.get("pastes") or []) if exposed_pastes else [],
                    "metrics": metrics or {},
                })

        return results

    async def _get_with_retry(
        self, client: httpx.AsyncClient, path: str, params: dict | None = None, max_retries: int = 16
    ) -> dict | None:
        """GET with exponential backoff on 429 rate-limit responses.

        Waits out rate-limit windows by backing off progressively, capping
        each wait at 180s. With max_retries=16 this gives ~40 minutes of
        total budget before giving up on a single request.
        """
        for attempt in range(max_retries + 1):
            try:
                resp = await client.get(path, params=params)
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code == 429:
                    wait = min(2 ** (attempt + 1), 180)  # cap at 180s
                    await asyncio.sleep(wait)
                    continue
                return None
            except httpx.HTTPError:
                if attempt < max_retries:
                    await asyncio.sleep(2)
                    continue
                return None
        return None

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize XposedOrNot response into standard Finding format."""
        source = raw.get("source", "breach-analytics")

        if source == "check-email":
            breaches = raw.get("breaches", [])
            breach_name = breaches[0].get("breach_name", "Unknown") if breaches else "Unknown"
            return {
                "entity_type": "BREACH",
                "entity_value": f"{raw['email']}::{breach_name}",
                "severity": "HIGH" if raw.get("breach_count", 0) > 0 else "LOW",
                "confidence": 0.9,
                "normalized_data": {
                    "email": raw["email"],
                    "breach_count": raw.get("breach_count", 0),
                    "breaches": breaches,
                    "risk_score": raw.get("risk_score"),
                    "source": "xposedornot",
                },
            }

        # breach-analytics source
        details = raw.get("breaches_details", [])
        risk = raw.get("risk_score", 0)
        severity = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 20 else "LOW"

        # The API's BreachesSummary.breach_count can be 0 even when
        # ExposedBreaches.breaches_details has entries (e.g. low-risk records).
        # Use the actual detail count when the summary under-counts.
        summary_count = raw.get("breach_count", 0) or 0
        actual_count = len(details)
        breach_count = actual_count if actual_count > summary_count else summary_count

        return {
            "entity_type": "BREACH",
            "entity_value": raw["email"],
            "severity": severity,
            "confidence": 0.9,
            "normalized_data": {
                "email": raw["email"],
                "breach_count": breach_count,
                "breaches": [
                    {
                        "name": d.get("breach") or d.get("Name") or d.get("breach_name"),
                        "domain": d.get("domain"),
                        "breach_date": d.get("xposed_date") or d.get("BreachDate"),
                        "description": d.get("details") or "",
                        "data_classes": [
                            c.strip()
                            for c in (d.get("xposed_data") or "").split(";")
                            if c.strip()
                        ],
                        "password_risk": d.get("password_risk") or "",
                        "records_count": d.get("xposed_records", 0),
                        "references": d.get("references") or "",
                        "industry": d.get("industry") or "",
                        "verified": d.get("verified") in ("Yes", True),
                    }
                    for d in details
                ],
                "risk_score": risk,
                "paste_count": raw.get("paste_count", 0),
                "pastes": raw.get("paste_details", []),
                "metrics": raw.get("metrics", {}),
                "source": "xposedornot",
            },
        }
