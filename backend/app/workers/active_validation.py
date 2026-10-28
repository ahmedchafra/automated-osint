"""Explicit active-validation DAG for verified scan assets.

This task is deliberately separate from discovery. It may only run for scans
created in ``active`` mode and consumes the persisted canonical asset inventory:

    verified public IPs -> Naabu -> Nmap service fingerprinting
    verified live URLs  -> Nuclei safe template scan
                        -> TLS posture assessment
                        -> bounded scoped crawl
    scoped subdomains   -> DNS/provider takeover verification

The network, web, TLS, crawl, and takeover branches run in parallel. Nmap remains
chained behind Naabu so it only touches ports that were confirmed open.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from pathlib import Path
import shutil
import socket
import tempfile
from typing import Any
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.asset import Asset
from app.models.scan import Scan
from app.services.correlation import CorrelationEngine
from app.services.http_validation import public_ip_set
from app.services.progress import ScanProgressPublisher
from app.services.scope import ScopeEvaluator
from app.services.scoped_crawler import MAX_CRAWL_PAGES, MAX_CRAWL_SEEDS, crawl_urls
from app.services.takeover_verification import (
    MAX_TAKEOVER_TARGETS,
    verify_takeover_candidates,
)
from app.services.tls_assessment import MAX_TLS_TARGETS, assess_tls_urls
from app.workers.celery_app import celery_app
from app.workers.task_utils import _run, persist_findings


logger = logging.getLogger("osint.active_validation")

MAX_ACTIVE_IPS = 50
MAX_NMAP_HOSTS = 25
MAX_ACTIVE_URLS = 50
NMAP_CONCURRENCY = 2
MAX_NUCLEI_FINDINGS = 5000
NUCLEI_TEMPLATES = Path("/opt/nuclei-templates")


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


async def _hostname_is_public(hostname: str) -> bool:
    """Re-resolve immediately before active use to reduce stale/DNS-rebind risk."""
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError):
        return False
    addresses = sorted({record[4][0] for record in records})
    return public_ip_set(addresses)


async def _run_process(
    *command: str,
    timeout: float,
) -> tuple[str, str]:
    """Run an argv-only subprocess with a hard timeout (never via a shell)."""
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.communicate()
        raise RuntimeError(f"{command[0]} exceeded its {int(timeout)}s timeout")
    except asyncio.CancelledError:
        process.kill()
        await process.communicate()
        raise
    decoded_stdout = stdout.decode("utf-8", errors="replace")
    decoded_stderr = stderr.decode("utf-8", errors="replace")
    if process.returncode != 0:
        detail = decoded_stderr.strip()[-1000:] or f"exit code {process.returncode}"
        raise RuntimeError(f"{command[0]} failed: {detail}")
    return decoded_stdout, decoded_stderr


def parse_naabu_jsonl(output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for line in output.splitlines():
        try:
            item = json.loads(line)
            host = str(item.get("ip") or item.get("host") or "").strip()
            port = int(item.get("port"))
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
        if not _public_ip(host) or not 1 <= port <= 65535 or (host, port) in seen:
            continue
        seen.add((host, port))
        protocol = str(item.get("protocol") or "tcp").lower()
        findings.append({
            "vector_type": "SERVICES",
            "entity_type": "PORT_SERVICE",
            "entity_value": f"{host}:{port}",
            "severity": "INFO",
            "confidence": 0.9,
            "source_module": "naabu",
            "raw_data": item,
            "normalized_data": {
                "ip": host,
                "port": port,
                "protocol": protocol,
                "state": "open",
                "scanner": "naabu",
            },
            "tags": ["active", "verified-asset", "open-port"],
        })
    return findings


def parse_nmap_xml(output: str, target: str) -> list[dict[str, Any]]:
    xml_start = output.find("<?xml")
    if xml_start >= 0:
        output = output[xml_start:]
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return []

    findings: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        address_node = host_node.find("address[@addrtype='ipv4']")
        if address_node is None:
            address_node = host_node.find("address")
        address = address_node.get("addr", target) if address_node is not None else target
        if not _public_ip(address):
            continue
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            try:
                port = int(port_node.get("portid", "0"))
            except ValueError:
                continue
            service_node = port_node.find("service")
            service = service_node.attrib if service_node is not None else {}
            cpes = [node.text for node in port_node.findall("./service/cpe") if node.text]
            normalized = {
                "ip": address,
                "port": port,
                "protocol": port_node.get("protocol", "tcp"),
                "state": "open",
                "service": service.get("name"),
                "product": service.get("product"),
                "version": service.get("version"),
                "extra_info": service.get("extrainfo"),
                "cpe": cpes,
                "scanner": "nmap",
            }
            findings.append({
                "vector_type": "SERVICES",
                "entity_type": "PORT_SERVICE",
                "entity_value": f"{address}:{port}",
                "severity": "INFO",
                "confidence": 0.95,
                "source_module": "nmap",
                "raw_data": {"service": service, "cpe": cpes},
                "normalized_data": normalized,
                "tags": ["active", "verified-asset", "service-fingerprint"],
            })
    return findings


def parse_nuclei_jsonl(output: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    allowed_severity = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        template_id = str(item.get("template-id") or item.get("templateID") or "unknown")
        matched_at = str(item.get("matched-at") or item.get("matched") or item.get("host") or "")
        if not matched_at or (template_id, matched_at) in seen:
            continue
        seen.add((template_id, matched_at))
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        severity = str(info.get("severity") or "info").upper()
        if severity not in allowed_severity:
            severity = "INFO"
        classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
        cve_ids = classification.get("cve-id") or classification.get("cve_id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        finding_name = str(info.get("name") or template_id)
        findings.append({
            "vector_type": "SERVICES",
            "entity_type": "VULNERABILITY",
            "entity_value": f"{template_id} @ {matched_at}",
            "severity": severity,
            "confidence": 0.9,
            "source_module": "nuclei",
            "raw_data": item,
            "normalized_data": {
                "template_id": template_id,
                "name": finding_name,
                "matched_at": matched_at,
                "host": item.get("host"),
                "type": item.get("type"),
                "severity": severity,
                "description": info.get("description"),
                "reference": info.get("reference") or [],
                "cve_ids": cve_ids,
                "scanner": "nuclei",
            },
            "tags": ["active", "verified-asset", "nuclei", severity.lower()],
        })
        if len(findings) >= MAX_NUCLEI_FINDINGS:
            break
    return findings


def _require_tool(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"required active scanner '{name}' is not installed")
    return path


async def _run_naabu(
    ips: list[str], directory: Path, allowed_ports: list[int]
) -> list[dict[str, Any]]:
    if not ips:
        return []
    target_file = directory / "naabu-targets.txt"
    target_file.write_text("\n".join(ips) + "\n", encoding="utf-8")
    port_args = ["-ports", ",".join(str(port) for port in allowed_ports)] if allowed_ports else ["-top-ports", "100"]
    stdout, _ = await _run_process(
        _require_tool("naabu"), "-list", str(target_file), "-json", "-silent",
        *port_args, "-rate", "100", "-timeout", "3s", "-retries", "1", timeout=300,
    )
    findings = parse_naabu_jsonl(stdout)
    return [
        finding for finding in findings
        if not allowed_ports or finding["normalized_data"]["port"] in allowed_ports
    ]


async def _run_nmap_for_host(
    host: str, ports: list[int], semaphore: asyncio.Semaphore
) -> list[dict[str, Any]]:
    async with semaphore:
        stdout, _ = await _run_process(
            _require_tool("nmap"), "-sV", "-Pn", "-T3", "--version-light",
            "--host-timeout", "90s", "-p", ",".join(str(port) for port in ports),
            "-oX", "-", host, timeout=120,
        )
        return parse_nmap_xml(stdout, host)


async def _run_network_branch(
    ips: list[str], directory: Path, publisher: ScanProgressPublisher, scan_id: str,
    allowed_ports: list[int],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    await publisher.publish(scan_id, "active_tool_started", {"tool": "naabu", "targets": len(ips)})
    naabu_findings = await _run_naabu(ips, directory, allowed_ports)
    await publisher.publish(scan_id, "active_tool_completed", {"tool": "naabu", "findings": len(naabu_findings)})

    ports_by_host: dict[str, set[int]] = {}
    for finding in naabu_findings:
        data = finding["normalized_data"]
        ports_by_host.setdefault(data["ip"], set()).add(data["port"])
    selected = sorted(ports_by_host.items())[:MAX_NMAP_HOSTS]
    await publisher.publish(scan_id, "active_tool_started", {"tool": "nmap", "targets": len(selected)})
    semaphore = asyncio.Semaphore(NMAP_CONCURRENCY)
    results = await asyncio.gather(*(
        _run_nmap_for_host(host, sorted(ports), semaphore)
        for host, ports in selected
    ))
    nmap_findings = [finding for group in results for finding in group]
    await publisher.publish(scan_id, "active_tool_completed", {"tool": "nmap", "findings": len(nmap_findings)})
    return naabu_findings, nmap_findings


async def _run_nuclei(
    urls: list[str], directory: Path, publisher: ScanProgressPublisher, scan_id: str
) -> list[dict[str, Any]]:
    await publisher.publish(scan_id, "active_tool_started", {"tool": "nuclei", "targets": len(urls)})
    if not urls:
        await publisher.publish(scan_id, "active_tool_completed", {"tool": "nuclei", "findings": 0})
        return []
    target_file = directory / "nuclei-targets.txt"
    target_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    command = [
        _require_tool("nuclei"), "-list", str(target_file), "-jsonl", "-silent",
        "-omit-raw", "-omit-template",
        "-disable-redirects", "-exclude-tags", "dos,fuzz,intrusive,headless",
        "-no-interactsh", "-disable-update-check",
        "-rate-limit", "20", "-concurrency", "5", "-timeout", "10", "-retries", "1",
    ]
    if NUCLEI_TEMPLATES.is_dir():
        command.extend(["-templates", str(NUCLEI_TEMPLATES)])
    stdout, _ = await _run_process(*command, timeout=600)
    findings = parse_nuclei_jsonl(stdout)
    await publisher.publish(scan_id, "active_tool_completed", {"tool": "nuclei", "findings": len(findings)})
    return findings


async def _run_tls_assessment(
    urls: list[str], publisher: ScanProgressPublisher, scan_id: str
) -> list[dict[str, Any]]:
    https_targets = {
        (parsed.hostname.lower().rstrip("."), parsed.port or 443)
        for url in urls
        if (parsed := urlparse(url)).scheme == "https" and parsed.hostname
    }
    target_count = min(len(https_targets), MAX_TLS_TARGETS)
    await publisher.publish(
        scan_id, "active_tool_started", {"tool": "tls_assessment", "targets": target_count}
    )
    findings = await assess_tls_urls(urls)
    await publisher.publish(
        scan_id, "active_tool_completed", {"tool": "tls_assessment", "findings": len(findings)}
    )
    return findings


async def _run_scoped_crawl(
    urls: list[str],
    scope: ScopeEvaluator,
    publisher: ScanProgressPublisher,
    scan_id: str,
) -> list[dict[str, Any]]:
    target_count = min(len(urls), MAX_CRAWL_SEEDS)
    await publisher.publish(
        scan_id, "active_tool_started", {"tool": "scoped_crawler", "targets": target_count}
    )
    findings = await crawl_urls(urls, scope)
    await publisher.publish(
        scan_id, "active_tool_completed", {"tool": "scoped_crawler", "findings": len(findings)}
    )
    return findings


async def _run_takeover_verification(
    hostnames: list[str],
    scope: ScopeEvaluator,
    publisher: ScanProgressPublisher,
    scan_id: str,
) -> list[dict[str, Any]]:
    target_count = min(len(hostnames), MAX_TAKEOVER_TARGETS)
    await publisher.publish(
        scan_id,
        "active_tool_started",
        {"tool": "takeover_verification", "targets": target_count},
    )
    findings = await verify_takeover_candidates(hostnames, scope)
    await publisher.publish(
        scan_id,
        "active_tool_completed",
        {"tool": "takeover_verification", "findings": len(findings)},
    )
    return findings


async def _verified_targets(
    session, scan: Scan
) -> tuple[list[str], list[str], list[str]]:
    scan_id = scan.id
    evaluator = ScopeEvaluator(
        scan.scope_manifest, target_type=scan.target_type, target=scan.target_domain
    )
    result = await session.execute(
        select(Asset).where(
            Asset.scan_id == scan_id,
            Asset.in_scope.is_(True),
            Asset.wildcard_suspected.is_(False),
        )
    )
    assets = result.scalars().all()
    ips: set[str] = set()
    urls: set[str] = set()
    takeover_hostnames: set[str] = set()
    for asset in assets:
        if asset.asset_type == "IP_ADDRESS" and asset.state in {"RESOLVED", "LIVE"}:
            decision = evaluator.evaluate_asset("IP_ADDRESS", asset.canonical_value, derived=True)
            if decision.allowed and _public_ip(asset.canonical_value):
                ips.add(asset.canonical_value)
        if asset.asset_type in {"DOMAIN", "SUBDOMAIN"} and asset.state in {"RESOLVED", "LIVE"}:
            host_decision = evaluator.evaluate_asset(asset.asset_type, asset.canonical_value)
            if host_decision.allowed:
                ips.update(
                    value for value in (asset.resolved_ips or [])
                    if evaluator.evaluate_ip(value, derived_from_allowed_host=True).allowed
                )
        if asset.asset_type == "SUBDOMAIN":
            host_decision = evaluator.evaluate_asset("SUBDOMAIN", asset.canonical_value)
            if host_decision.allowed:
                takeover_hostnames.add(asset.canonical_value.lower().rstrip("."))
        if asset.asset_type == "URL" and asset.state == "LIVE":
            parsed = urlparse(asset.canonical_value)
            url_decision = evaluator.evaluate_asset("URL", asset.canonical_value)
            if url_decision.allowed and parsed.hostname and await _hostname_is_public(parsed.hostname):
                urls.add(asset.canonical_value)
    return (
        sorted(ips)[:MAX_ACTIVE_IPS],
        sorted(urls)[:MAX_ACTIVE_URLS],
        sorted(takeover_hostnames)[:MAX_TAKEOVER_TARGETS],
    )


async def _run_active_validation(scan_id: str) -> dict[str, Any]:
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        if scan.scan_mode != "active":
            raise PermissionError("active validation requires a scan created in active mode")

        publisher = ScanProgressPublisher()
        ips, urls, takeover_hostnames = await _verified_targets(session, scan)
        scope = ScopeEvaluator(
            scan.scope_manifest, target_type=scan.target_type, target=scan.target_domain
        )
        allowed_ports = list((scan.scope_manifest or {}).get("allowed_ports") or [])
        await publisher.publish(scan_id, "active_validation_started", {
            "ip_targets": len(ips),
            "url_targets": len(urls),
            "takeover_targets": len(takeover_hostnames),
            "limits": {
                "ips": MAX_ACTIVE_IPS,
                "urls": MAX_ACTIVE_URLS,
                "crawl_seeds": MAX_CRAWL_SEEDS,
                "crawl_pages": MAX_CRAWL_PAGES,
                "takeover_targets": MAX_TAKEOVER_TARGETS,
            },
        })

        with tempfile.TemporaryDirectory(prefix="osint-active-") as temp_dir:
            directory = Path(temp_dir)
            network_task = _run_network_branch(
                ips, directory, publisher, scan_id, allowed_ports
            )
            nuclei_task = _run_nuclei(urls, directory, publisher, scan_id)
            tls_task = _run_tls_assessment(urls, publisher, scan_id)
            crawl_task = _run_scoped_crawl(urls, scope, publisher, scan_id)
            takeover_task = _run_takeover_verification(
                takeover_hostnames, scope, publisher, scan_id
            )
            (
                (naabu_findings, nmap_findings),
                nuclei_findings,
                tls_findings,
                crawl_findings,
                takeover_findings,
            ) = await asyncio.gather(
                network_task, nuclei_task, tls_task, crawl_task, takeover_task
            )

        findings = [
            *naabu_findings,
            *nmap_findings,
            *nuclei_findings,
            *tls_findings,
            *crawl_findings,
            *takeover_findings,
        ]
        persisted = await persist_findings(session, scan_id, findings, default_vector="SERVICES")
        await session.flush()
        links_created = await CorrelationEngine(session, scan_id).run()
        await session.commit()
        result = {
            "scan_id": scan_id,
            "targets": {
                "ips": len(ips),
                "urls": len(urls),
                "takeover_hostnames": len(takeover_hostnames),
            },
            "findings": {
                "naabu": len(naabu_findings),
                "nmap": len(nmap_findings),
                "nuclei": len(nuclei_findings),
                "tls_assessment": len(tls_findings),
                "scoped_crawler": len(crawl_findings),
                "takeover_verification": len(takeover_findings),
                "persisted": persisted,
            },
            "links_created": links_created,
        }
        await publisher.publish(scan_id, "active_validation_completed", result)
        return result


@celery_app.task(name="active_validation", bind=True, max_retries=0)
def active_validation_task(self, scan_id: str):
    return _run(_run_active_validation(scan_id))
