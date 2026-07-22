"""Unified scan pipeline.

Runs all 5 reconnaissance vectors sequentially with fine-grained progress
events published via Redis pubsub so the frontend can render a live
pipeline dashboard.

Pipeline order:
  Phase 1: INFRASTRUCTURE (crt.sh → subfinder → DNS → Shodan InternetDB → WhoIS/ASN)
  Phase 1b: SERVICES (Shodan Host + Censys → CPEs → NVD CVE → CISA KEV)
  Phase 2: IDENTITY (Hunter.io → email construction → XposedOrNot)
  Phase 3: SEARCH (dnstwist + GitHub secrets + Serper)
  Phase 4: USERNAME (maigret on discovered usernames — skipped if none)

Each tool publishes tool_started / tool_completed events so the frontend
can show live progress per tool. No hardcoded timeouts — tools run until
they finish. A 5-minute safety watchdog kills any tool that truly hangs.
"""
from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor

from app.workers.celery_app import celery_app
from app.database import AsyncSessionLocal
from app.workers.task_utils import _run, persist_findings
from app.models.scan import Scan
from app.services.progress import ScanProgressPublisher
from app.config import settings


TOOL_WATCHDOG_SECONDS = 300  # 5 minutes — only kills truly hung tools
logger = logging.getLogger("osint.unified_scan")

# Tools that need their own event loop (they call asyncio.get_event_loop() internally)
ISOLATED_TOOLS = {"holehe", "maigret", "subfinder", "crtsh", "dns_resolver"}


def _run_coro_in_thread(coro_factory, *args):
    """Run a coroutine in a fresh event loop in a separate thread.

    Used for collectors that call asyncio.get_event_loop() internally,
    which would conflict with the main pipeline's loop.
    """
    import threading
    result = {}
    def _worker():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result['value'] = loop.run_until_complete(coro_factory(*args))
        finally:
            loop.close()
    t = threading.Thread(target=_worker)
    t.start()
    t.join()
    return result.get('value', [])


def _run_tool_sync(collector_name: str, target: str) -> list[dict]:
    """Run a collector in an isolated thread+loop, return normalized findings."""
    from collectors.registry import registry
    cls = registry.get_collector(collector_name)
    collector = cls()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(
            asyncio.wait_for(
                collector.execute(target),
                timeout=TOOL_WATCHDOG_SECONDS,
            )
        )
    except asyncio.TimeoutError:
        logger.warning("Tool %s timed out after %ds on %s", collector_name, TOOL_WATCHDOG_SECONDS, target)
        return []
    except Exception as e:
        logger.exception("Tool %s failed on %s: %s", collector_name, target, e)
        return []
    finally:
        loop.close()


async def _run_tool(collector_name: str, target: str, scan_id: str,
                    session, publisher: ScanProgressPublisher,
                    thread_pool: ThreadPoolExecutor,
                    collector_kwargs: dict | None = None) -> list[dict]:
    """Run a single collector and return normalized findings.

    For tools that need isolation (holehe, maigret, etc.), runs them in a
    separate thread with their own event loop via the thread pool.
    For all other tools, runs them directly on the current loop.

    Args:
        collector_kwargs: Optional kwargs forwarded to the collector
                          constructor (e.g. ``{"free_only": True}`` for
                          theHarvester's quick mode).
    """
    start = time.monotonic()
    await publisher.publish(scan_id, "tool_started", {
        "tool": collector_name,
        "target": target,
    })

    try:
        if collector_name in ISOLATED_TOOLS:
            loop = asyncio.get_running_loop()
            findings = await loop.run_in_executor(
                thread_pool,
                _run_tool_sync,
                collector_name,
                target,
            )
        else:
            from collectors.registry import registry
            cls = registry.get_collector(collector_name)
            collector = cls(**(collector_kwargs or {}))
            findings = await asyncio.wait_for(
                collector.execute(target),
                timeout=TOOL_WATCHDOG_SECONDS,
            )

        elapsed = time.monotonic() - start
        await publisher.publish(scan_id, "tool_completed", {
            "tool": collector_name,
            "target": target,
            "collected": len(findings),
            "elapsed_seconds": round(elapsed, 1),
        })
        return findings
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start
        await publisher.publish(scan_id, "tool_timeout", {
            "tool": collector_name,
            "target": target,
            "elapsed_seconds": round(elapsed, 1),
            "watchdog_seconds": TOOL_WATCHDOG_SECONDS,
        })
        return []
    except Exception as e:
        elapsed = time.monotonic() - start
        await publisher.publish(scan_id, "tool_error", {
            "tool": collector_name,
            "target": target,
            "error": str(e),
            "elapsed_seconds": round(elapsed, 1),
        })
        return []


async def _run_pipeline(scan_id: str) -> dict:
    """Execute the full unified pipeline."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            return {"scan_id": scan_id, "status": "missing"}

        publisher = ScanProgressPublisher()
        scan.status = "RUNNING"
        await session.commit()

        await publisher.publish(scan_id, "scan_started", {
            "target_domain": scan.target_domain,
            "phases": ["INFRASTRUCTURE", "SERVICES", "IDENTITY", "SEARCH"],
        })

        total_findings = 0
        phase_results = {}
        thread_pool = ThreadPoolExecutor(max_workers=4)

        try:
            # ─── PHASE 1: INFRASTRUCTURE ──────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "INFRASTRUCTURE",
                "phase_index": 1,
                "tools": ["crtsh", "subfinder", "theharvester", "dns_resolver", "shodan_internetdb", "whois_lookup"],
            })

            all_subdomains = set()
            resolved_ips = set()
            theharvester_emails = set()

            # 1a. crt.sh
            crtsh_findings = await _run_tool("crtsh", scan.target_domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, crtsh_findings)
            for f in crtsh_findings:
                ev = f.get("entity_value", "")
                if ev:
                    all_subdomains.add(ev)

            # 1b. subfinder
            subfinder_findings = await _run_tool("subfinder", scan.target_domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, subfinder_findings)
            for f in subfinder_findings:
                ev = f.get("entity_value", "")
                if ev:
                    all_subdomains.add(ev)

            # 1c. theHarvester — search engine email/subdomain/IP harvest (free sources only)
            theharvester_findings = await _run_tool(
                "theharvester", scan.target_domain, scan_id, session, publisher, thread_pool,
                collector_kwargs={"free_only": True},
            )
            total_findings += await persist_findings(session, scan_id, theharvester_findings)
            for f in theharvester_findings:
                etype = f.get("entity_type", "")
                ev = f.get("entity_value", "")
                if etype == "SUBDOMAIN" and ev:
                    all_subdomains.add(ev)
                elif etype == "IP_ADDRESS" and ev:
                    resolved_ips.add(ev)
                elif etype == "EMAIL" and "@" in ev:
                    theharvester_emails.add(ev)

            # 1d. DNS resolution (bounded to 200 subdomains)
            from app.services.vectors.infrastructure import MAX_DNS_SUBDOMAINS, DNS_CONCURRENCY
            subdomains_to_resolve = {scan.target_domain} | all_subdomains
            if len(subdomains_to_resolve) > MAX_DNS_SUBDOMAINS:
                subdomains_to_resolve = set(list(subdomains_to_resolve)[:MAX_DNS_SUBDOMAINS])

            dns_findings_all = []
            semaphore = asyncio.Semaphore(DNS_CONCURRENCY)

            async def resolve_one(subdomain):
                async with semaphore:
                    return await _run_tool("dns_resolver", subdomain, scan_id, session, publisher, thread_pool)

            dns_tasks = [asyncio.create_task(resolve_one(s)) for s in sorted(subdomains_to_resolve)]
            dns_results = await asyncio.gather(*dns_tasks, return_exceptions=True)
            for result in dns_results:
                if isinstance(result, list):
                    dns_findings_all.extend(result)

            total_findings += await persist_findings(session, scan_id, dns_findings_all)
            for f in dns_findings_all:
                for ip in (f.get("normalized_data", {}) or {}).get("resolved_ips", []):
                    resolved_ips.add(ip)

            # 1e. Shodan InternetDB enrichment per IP
            for ip in sorted(resolved_ips):
                shodan_findings = await _run_tool("shodan_internetdb", ip, scan_id, session, publisher, thread_pool)
                total_findings += await persist_findings(session, scan_id, shodan_findings)

            # 1f. WhoIS / ASN Lookup on root domain and resolved IPs
            whois_findings = await _run_tool("whois_lookup", scan.target_domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, whois_findings)
            for ip in sorted(resolved_ips):
                asn_findings = await _run_tool("whois_lookup", ip, scan_id, session, publisher, thread_pool)
                total_findings += await persist_findings(session, scan_id, asn_findings)

            await session.commit()
            phase_results["INFRASTRUCTURE"] = {
                "subdomains": len(all_subdomains),
                "ips": len(resolved_ips),
                "findings": total_findings,
            }

            await publisher.publish(scan_id, "phase_completed", {
                "phase": "INFRASTRUCTURE",
                "phase_index": 1,
                "result": phase_results["INFRASTRUCTURE"],
            })

            # ─── PHASE 1b: SERVICES ───────────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "SERVICES",
                "phase_index": 2,
                "tools": ["shodan_host", "censys_host", "nvd_cve", "cisa_kev"],
            })

            services_findings = 0
            for ip in sorted(resolved_ips):
                for tool in ("shodan_host", "censys_host"):
                    tool_findings = await _run_tool(tool, ip, scan_id, session, publisher, thread_pool)
                    services_findings += len(tool_findings)
                    total_findings += await persist_findings(session, scan_id, tool_findings)

            # NVD CVE from discovered CPEs
            from app.models.finding import Finding
            from sqlalchemy import select
            cpe_values = set()
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id, Finding.entity_type == "PORT_SERVICE")
            )
            for finding in result.scalars().all():
                nd = finding.normalized_data or {}
                for key in ("cpes", "cpe23", "cpe"):
                    cpes = nd.get(key, [])
                    if isinstance(cpes, list):
                        for cpe in cpes:
                            if isinstance(cpe, str) and cpe.strip():
                                cpe_values.add(cpe.strip())

            nvd_count = 0
            for cpe in sorted(cpe_values):
                nvd_findings = await _run_tool("nvd_cve", cpe, scan_id, session, publisher, thread_pool)
                nvd_count += len(nvd_findings)
                total_findings += await persist_findings(session, scan_id, nvd_findings)

            # CISA KEV
            kev_count = 0
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id, Finding.entity_type == "CVE")
            )
            for finding in result.scalars().all():
                if finding.entity_value:
                    kev_findings = await _run_tool("cisa_kev", finding.entity_value, scan_id, session, publisher, thread_pool)
                    kev_count += len(kev_findings)
                    total_findings += await persist_findings(session, scan_id, kev_findings)

            await session.commit()
            phase_results["SERVICES"] = {
                "tools_findings": services_findings,
                "cves": nvd_count,
                "kev": kev_count,
                "total": total_findings,
            }

            await publisher.publish(scan_id, "phase_completed", {
                "phase": "SERVICES",
                "phase_index": 2,
                "result": phase_results["SERVICES"],
            })

            # ─── PHASE 2: IDENTITY ────────────────────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "IDENTITY",
                "phase_index": 3,
                "tools": ["hunter_domain", "xposedornot_breach", "h8mail"],
            })

            # Hunter.io
            hunter_findings = await _run_tool("hunter_domain", scan.target_domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, hunter_findings)
            await session.commit()

            # Collect emails from hunter results + theHarvester-discovered emails
            emails = set()
            for f in hunter_findings:
                ev = f.get("entity_value", "")
                if "@" in ev:
                    emails.add(ev)
            emails.update(theharvester_emails)

            # XposedOrNot breach check per email
            breach_count = 0
            for email in sorted(emails):
                breach_findings = await _run_tool("xposedornot_breach", email, scan_id, session, publisher, thread_pool)
                breach_count += len(breach_findings)
                total_findings += await persist_findings(session, scan_id, breach_findings)
                await asyncio.sleep(0.6)  # Rate limit: 2 req/sec

            # h8mail breach/reputation check per email (complementary sources)
            h8mail_total = 0
            for email in sorted(emails):
                h8mail_findings = await _run_tool("h8mail", email, scan_id, session, publisher, thread_pool)
                h8mail_total += len(h8mail_findings)
                total_findings += await persist_findings(session, scan_id, h8mail_findings)

            await session.commit()
            phase_results["IDENTITY"] = {
                "emails": len(emails),
                "breaches": breach_count,
                "h8mail_findings": h8mail_total,
                "total": total_findings,
            }

            await publisher.publish(scan_id, "phase_completed", {
                "phase": "IDENTITY",
                "phase_index": 3,
                "result": phase_results["IDENTITY"],
            })

            # ─── PHASE 3: SEARCH / THREAT INTEL ───────────────────────────
            await publisher.publish(scan_id, "phase_started", {
                "phase": "SEARCH",
                "phase_index": 4,
                "tools": ["dnstwist", "github_secrets", "serper_search"],
            })

            # dnstwist
            dnstwist_findings = await _run_tool("dnstwist", scan.target_domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, dnstwist_findings)

            # GitHub secrets
            gh_findings = await _run_tool("github_secrets", scan.target_domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, gh_findings)

            # Serper search
            serper_findings = await _run_tool("serper_search", scan.target_domain, scan_id, session, publisher, thread_pool)
            total_findings += await persist_findings(session, scan_id, serper_findings)

            await session.commit()
            phase_results["SEARCH"] = {
                "lookalikes": len(dnstwist_findings),
                "github_leaks": len(gh_findings),
                "dork_results": len(serper_findings),
                "total": total_findings,
            }

            await publisher.publish(scan_id, "phase_completed", {
                "phase": "SEARCH",
                "phase_index": 4,
                "result": phase_results["SEARCH"],
            })

            # ─── CORRELATION ───────────────────────────────────────────────
            from app.services.correlation import CorrelationEngine
            links_created = await CorrelationEngine(session, scan_id).run()
            await session.commit()

            # ─── COMPLETE ──────────────────────────────────────────────────
            scan.status = "COMPLETED"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
            await session.commit()

            await publisher.publish(scan_id, "scan_completed", {
                "status": "COMPLETED",
                "total_findings": total_findings,
                "links_created": links_created,
                "phases": phase_results,
            })

            return {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "total_findings": total_findings,
                "links_created": links_created,
            }
        except Exception:
            scan.status = "FAILED"
            from datetime import datetime, timezone
            scan.completed_at = datetime.now(timezone.utc)
            await session.commit()
            await publisher.publish(scan_id, "scan_failed", {"status": "FAILED"})
            raise
        finally:
            thread_pool.shutdown(wait=False)


# ── DISABLED ─────────────────────────────────────────────────────────────
# No frontend code dispatches this task. The unified pipeline that ran all 5
# vectors automatically has been replaced by the phased scan model:
#   - POST /initial  → Phase 1 infra (free APIs)
#   - POST /org      → domain discovery (Serper + Whoxy) — user picks domain
#   - POST /ip       → IP recon with domain convergence
#   - On-demand enrichment via the workspace (Shodan, Hunter, h8mail, etc.)
#
# @celery_app.task(name="execute_unified_scan", bind=True, max_retries=1, default_retry_delay=10)
# def execute_unified_scan_task(self, scan_id: str):
#     try:
#         return _run(_run_pipeline(scan_id))
#     except Exception as exc:
#         if self.request.retries < self.max_retries:
#             raise self.retry(exc=exc)
#         raise
