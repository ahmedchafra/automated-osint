"""Domain deep analysis task.

Triggered when an analyst clicks "Conduct Deep Analysis" on a subdomain
row in the Infrastructure tab. Runs eight collectors IN PARALLEL:
  1. hunter_domain      — discovers ALL emails for the domain
  2. theharvester       — email/host/subdomain harvest (quick=free, full=all API keys)
  3. github_secrets     — finds leaked secrets/repos mentioning the domain
  4. dnstwist           — generates lookalike domain permutations
  5. builtwith          — web technology fingerprinting (BuiltWith Free API)
  6. http_headers       — HTTP response headers + redirect chain capture
  7. wayback_machine    — archive.org historical URL discovery
  8. version_detector   — probes HTTP headers & HTML for technology versions

After the parallel batch, two sequential steps run:
  1. Version enrichment — reads TECHNOLOGY and TECHNOLOGY_VERSION findings
     to build a tech_name → version map.
  2. Technology→CVE      — queries NVD for each product-like technology,
     filtering by version when detected.

The theHarvester supports two modes:
  - "quick":  free-only sources (24 sources, ~30s, no API key needed)
  - "full":   all 55 sources with all configured API keys (~900s)

When theHarvester mode is "auto" (the default), it checks whether any
theHarvester-relevant API keys are configured in the environment. If so,
it runs in full mode; otherwise it falls back to quick mode.

Each collector runs in its own thread with an isolated event loop.
Progress is published via Redis pubsub so the frontend updates live.
"""
from __future__ import annotations

import asyncio
from sqlalchemy import select

import redis.asyncio as aioredis

from app.config import settings
from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.models.finding import Finding
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.workers.task_utils import run_collector_for_scan, _run


def _clear_running_lock(scan_id: str, domain: str) -> None:
    """Delete the Redis lock key (best-effort). Runs on task completion so
    the same scan+domain can be re-analyzed immediately."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            loop.run_until_complete(client.delete(f"deep_analysis:running:{scan_id}:{domain}"))
            loop.run_until_complete(client.aclose())
        finally:
            loop.close()
    except Exception:
        pass  # best-effort cleanup

# TheHarvester API-key env var names the collector maps to YAML providers.
# If ANY of these has a non-empty value in the environment, full mode is
# used by default ("auto") instead of quick mode.
_TH_API_KEY_ATTRS = [
    "SHODAN_API_KEY", "HIBP_API_KEY", "HACKERTARGET_API_KEY",
    "BUFFEROVERUN_API_KEY", "VT_API_KEY", "LEAKIX_API_KEY",
    "DNSDUMPSTER_API_KEY", "SECURITYTRAILS_KEY", "FULLHUNT_API_KEY",
    "BEVIGIL_API_KEY", "TOMBA_API_KEY", "BRAVE_API_KEY",
    "DYMO_API_KEY", "NETLAS_API_KEY", "CRIMINALIP_API_KEY",
    "HUNTERHOW_API_KEY", "MOJEEK_API_KEY", "WINDVANE_API_KEY",
    "VENACUS_API_KEY", "ZOOMEYE_API_KEY", "BUILTWITH_API_KEY",
    "INTELX_API_KEY", "ONYPHE_API_KEY", "FOFA_API_KEY",
    "SHERLOCKEYE_API_KEY", "PENTESTTOOLS_API_KEY",
    "PROJECTDISCOVERY_KEY", "ROCKETREACH_API_KEY",
    "SECURITYSCORECARD_KEY", "WHOISXML_API_KEY",
    "DEHASHED_API_KEY", "LEAKLOOKUP_API_KEY",
]


def _has_theharvester_api_keys() -> bool:
    """Return True if at least one theHarvester API key is configured."""
    return any(
        bool(getattr(settings, attr, None))
        for attr in _TH_API_KEY_ATTRS
    )


@celery_app.task(name="domain_deep_analysis", bind=True, max_retries=1, default_retry_delay=10)
def domain_deep_analysis_task(self, scan_id: str, domain: str,
                               theharvester_mode: str = "auto"):
    """Celery task: run hunter + theharvester + github_secrets + dnstwist on a domain.

    Args:
        scan_id:           Scan UUID.
        domain:            Target domain.
        theharvester_mode: "auto" (detect API keys, default),
                            "quick" (free sources only, ~30s), or
                            "full" (all API-key sources, ~900s).
    """

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            await publisher.publish(scan_id, "domain_deep_analysis_started", {
                "domain": domain,
                "theharvester_mode": theharvester_mode,
                "collectors": [
                    "hunter_domain", "theharvester", "github_secrets", "dnstwist",
                    "builtwith", "http_headers", "wayback_machine", "version_detector",
                ],
            })

            # Choose theHarvester kwargs based on mode.
            # "auto" (default) uses full mode when >= 1 API key is configured.
            if theharvester_mode == "full" or (theharvester_mode == "auto" and _has_theharvester_api_keys()):
                theharvester_kwargs = {"free_only": False, "timeout": 900, "limit": 50000}
            else:
                theharvester_kwargs = {"free_only": True, "timeout": 300, "limit": 500}

            # Run all collectors in parallel with per-collector progress events
            async def run_collector_safe(name: str, target: str,
                                         collector_kwargs: dict | None = None) -> int:
                await publisher.publish(scan_id, "domain_deep_analysis_progress", {
                    "collector": name, "domain": domain, "status": "running",
                })
                try:
                    # AsyncSession is not safe for concurrent use. Each
                    # parallel collector owns and commits its own transaction;
                    # the orchestration session is reserved for the sequential
                    # correlation/CVE phase below.
                    async with AsyncSessionLocal() as collector_session:
                        found = await run_collector_for_scan(
                            name, target, scan_id, collector_session, publisher,
                            collector_kwargs=collector_kwargs,
                        )
                        await collector_session.commit()
                    count = len(found)
                    await publisher.publish(scan_id, "domain_deep_analysis_progress", {
                        "collector": name, "domain": domain, "status": "done",
                        "findings_count": count,
                    })
                    return count
                except Exception as e:
                    await publisher.publish(scan_id, "domain_deep_analysis_progress", {
                        "collector": name, "domain": domain, "status": "error",
                        "error": str(e),
                    })
                    return 0

            results = await asyncio.gather(
                run_collector_safe("hunter_domain", domain),
                run_collector_safe("theharvester", domain,
                                   collector_kwargs=theharvester_kwargs),
                run_collector_safe("github_secrets", domain),
                run_collector_safe("dnstwist", domain),
                run_collector_safe("builtwith", domain),
                run_collector_safe("http_headers", domain),
                run_collector_safe("wayback_machine", domain),
                run_collector_safe("version_detector", domain),
            )

            email_count, theharvester_count, secrets_count, lookalikes_count, \
                builtwith_count, http_count, wayback_count, version_count = results

            # End the orchestration transaction opened when the scan was read
            # so subsequent statements see all collector-session commits.
            await session.commit()

            # ── Phase 2: Version enrichment + CVE cross-reference ────
            # After BuiltWith + version_detector have persisted their findings,
            # read all TECHNOLOGY and TECHNOLOGY_VERSION rows.
            await session.flush()

            tech_result = await session.execute(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.entity_type == "TECHNOLOGY",
                )
            )
            tech_findings = tech_result.scalars().all()
            tech_names: set[str] = set()
            for f in tech_findings:
                nd = f.normalized_data or {}
                cat = (nd.get("category") or "").strip()
                if cat:
                    tech_names.add(cat)

            # Build a tech_name → version map from version_detector findings
            version_result = await session.execute(
                select(Finding).where(
                    Finding.scan_id == scan_id,
                    Finding.entity_type == "TECHNOLOGY_VERSION",
                )
            )
            version_map: dict[str, str] = {}
            for f in version_result.scalars().all():
                nd = f.normalized_data or {}
                tech = (nd.get("technology") or "").strip()
                ver = (nd.get("version") or "").strip()
                if tech and ver:
                    version_map[tech] = ver

            # Run technology_cve for each product-like name (sequential to
            # avoid hammering NVD). Pass the detected version when available.
            cve_count = 0
            tech_list = sorted(tech_names)
            for idx, tech_name in enumerate(tech_list, 1):
                await publisher.publish(scan_id, "domain_deep_analysis_progress", {
                    "collector": f"technology_cve:{tech_name}",
                    "domain": domain,
                    "status": "running",
                    "technology": tech_name,
                    "phase": "cve",
                    "index": idx,
                    "total": len(tech_list),
                })
                try:
                    # Pass detected version if we found one for this technology
                    cve_kwargs = {"domain": domain}
                    detected_version = version_map.get(tech_name)
                    if detected_version:
                        cve_kwargs["version"] = detected_version

                    found = await run_collector_for_scan(
                        "technology_cve", tech_name, scan_id, session, publisher,
                        collector_kwargs=cve_kwargs,
                    )
                    cve_count += len(found)
                    await publisher.publish(scan_id, "domain_deep_analysis_progress", {
                        "collector": f"technology_cve:{tech_name}",
                        "domain": domain,
                        "status": "done",
                        "technology": tech_name,
                        "phase": "cve",
                        "index": idx,
                        "total": len(tech_list),
                        "findings_count": len(found),
                    })
                except Exception as e:
                    await publisher.publish(scan_id, "domain_deep_analysis_progress", {
                        "collector": f"technology_cve:{tech_name}",
                        "domain": domain,
                        "status": "error",
                        "technology": tech_name,
                        "phase": "cve",
                        "index": idx,
                        "total": len(tech_list),
                        "error": str(e),
                    })

            total = (email_count + theharvester_count + secrets_count
                     + lookalikes_count + builtwith_count + http_count
                     + wayback_count + version_count + cve_count)

            await session.commit()
            await publisher.publish(scan_id, "domain_deep_analysis_completed", {
                "domain": domain,
                "theharvester_mode": theharvester_mode,
                "emails": email_count,
                "theharvester": theharvester_count,
                "secrets": secrets_count,
                "lookalikes": lookalikes_count,
                "builtwith": builtwith_count,
                "http_headers": http_count,
                "wayback_urls": wayback_count,
                "versions_detected": version_count,
                "technology_cves": cve_count,
                "total_findings": total,
            })
            return {
                "scan_id": scan_id,
                "domain": domain,
                "theharvester_mode": theharvester_mode,
                "emails": email_count,
                "theharvester": theharvester_count,
                "secrets": secrets_count,
                "lookalikes": lookalikes_count,
                "builtwith": builtwith_count,
                "http_headers": http_count,
                "wayback_urls": wayback_count,
                "versions_detected": version_count,
                "technology_cves": cve_count,
                "total_findings": total,
            }

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
    finally:
        _clear_running_lock(scan_id, domain)


@celery_app.task(name="github_secrets_scan", bind=True, max_retries=1, default_retry_delay=10)
def github_secrets_scan_task(self, scan_id: str, domain: str):
    """Lightweight task that only runs the github_secrets collector.

    Triggered from the Secrets tab's "Scan GitHub Secrets" button.
    Much faster than a full domain deep analysis since it only searches
    GitHub for leaked secrets and repos mentioning the domain.
    """

    async def run_task():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            publisher = ScanProgressPublisher()
            found = await run_collector_for_scan(
                "github_secrets", domain, scan_id, session, publisher,
            )
            await session.commit()
            return {"scan_id": scan_id, "domain": domain, "findings": len(found)}

    try:
        return _run(run_task())
    except Exception as exc:
        if self.request.retries < self.max_retries:
            raise self.retry(exc=exc)
        raise
