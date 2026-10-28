"""Bounded live smoke test for public, passive OSINT data sources.

This is intentionally separate from pytest: upstream availability and result
counts change over time. It validates every returned finding against the same
contract used before database persistence and prints only a small summary.

Run inside the backend container:
    python scripts/source_smoke.py
    python scripts/source_smoke.py --include-slow
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.finding_contract import prepare_finding
from collectors.registry import registry


@dataclass(frozen=True)
class Probe:
    collector: str
    target: str
    slow: bool = False
    keyed: bool = False


PROBES = (
    Probe("crtsh", "example.com"),
    Probe("common_crawl", "example.com"),
    Probe("wayback_machine", "example.com"),
    Probe("dns_email_posture", "example.com"),
    Probe("dns_resolver", "example.com"),
    Probe("rdap_lookup", "example.com"),
    Probe("rdap_lookup", "1.1.1.1"),
    Probe("ripestat", "1.1.1.1"),
    Probe("shodan_internetdb", "1.1.1.1"),
    Probe("cisa_kev", "CVE-2021-44228"),
    Probe("nvd_cve", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
    Probe("subfinder", "example.com", slow=True),
    Probe("theharvester", "example.com", slow=True),
    Probe("dnstwist", "example.com", slow=True),
    Probe("ahmia", "example.com", slow=True),
    Probe("builtwith", "example.com", keyed=True),
    Probe("censys_host", "1.1.1.1", keyed=True),
    Probe("github_secrets", "example.com", slow=True, keyed=True),
    Probe("hunter_domain", "example.com", keyed=True),
    Probe("org_domain_discovery", "Example Domain", keyed=True),
    Probe("reverse_whois_whoxy", "Example", keyed=True),
    Probe("serper_dork_search", "site:example.com", keyed=True),
    Probe("serper_search", "example.com", keyed=True),
    Probe("shodan_host", "1.1.1.1", keyed=True),
)


def _sample_value(value: Any) -> str:
    text = str(value)
    return text if len(text) <= 100 else text[:97] + "..."


async def _run_probe(probe: Probe, timeout: float) -> dict[str, Any]:
    collector_class = registry.get_collector(probe.collector)
    metadata = collector_class.metadata
    if metadata.requires_api_key and not os.getenv(metadata.api_key_env or ""):
        return {
            "collector": probe.collector,
            "target": probe.target,
            "status": "skipped_missing_key",
            "count": 0,
        }

    try:
        findings = await asyncio.wait_for(
            collector_class().execute(probe.target), timeout=timeout
        )
        safe = [
            prepare_finding(item, default_source=probe.collector)
            for item in findings
        ]
        return {
            "collector": probe.collector,
            "target": probe.target,
            "status": "ok" if safe else "empty",
            "count": len(safe),
            "entity_types": sorted({item["entity_type"] for item in safe}),
            "sample_values": [_sample_value(item["entity_value"]) for item in safe[:3]],
        }
    except TimeoutError:
        return {
            "collector": probe.collector,
            "target": probe.target,
            "status": "timeout",
            "count": 0,
        }
    except Exception as exc:  # diagnostic CLI: report and continue the matrix
        return {
            "collector": probe.collector,
            "target": probe.target,
            "status": "error",
            "count": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }


async def main(
    include_slow: bool, slow_only: bool, keyed_only: bool, timeout: float
) -> int:
    if keyed_only:
        probes = [probe for probe in PROBES if probe.keyed]
    elif slow_only:
        probes = [probe for probe in PROBES if probe.slow and not probe.keyed]
    else:
        probes = [
            probe for probe in PROBES
            if not probe.keyed and (include_slow or not probe.slow)
        ]
    results = []
    for probe in probes:
        result = await _run_probe(probe, timeout)
        results.append(result)
        print(json.dumps(result, sort_keys=True), flush=True)

    failures = [item for item in results if item["status"] in {"error", "timeout"}]
    summary = {
        "probes": len(results),
        "with_results": sum(item["count"] > 0 for item in results),
        "empty": sum(item["status"] == "empty" for item in results),
        "skipped_missing_key": sum(
            item["status"] == "skipped_missing_key" for item in results
        ),
        "failures": len(failures),
    }
    print(json.dumps({"summary": summary}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--include-slow", action="store_true")
    parser.add_argument("--slow-only", action="store_true")
    parser.add_argument("--keyed-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=75.0)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(
        args.include_slow, args.slow_only, args.keyed_only, args.timeout
    )))
