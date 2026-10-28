"""Bounded browser capture for verified web assets.

The primary hostname is pinned to the IP address verified immediately before
launch. Cross-origin requests, redirects, non-GET requests, downloads, and
explicitly excluded paths are blocked at the browser routing layer.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from fnmatch import fnmatch
import hashlib
import ipaddress
from pathlib import Path
import socket
from urllib.parse import urlparse

from playwright.async_api import async_playwright


VIEWPORT_WIDTH = 1365
VIEWPORT_HEIGHT = 768
CAPTURE_TIMEOUT_MS = 20_000


@dataclass(frozen=True)
class ScreenshotCaptureResult:
    sha256: str
    width: int
    height: int
    page_title: str | None
    status_code: int | None
    blocked_requests: int


async def resolve_public_ips(hostname: str) -> list[str]:
    """Resolve a hostname and reject mixed public/private responses."""
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        )
    except (OSError, UnicodeError):
        return []
    addresses = sorted({record[4][0] for record in records})
    try:
        if not addresses or not all(ipaddress.ip_address(value).is_global for value in addresses):
            return []
    except ValueError:
        return []
    return addresses


def storage_path(root: str | Path, storage_key: str) -> Path:
    """Resolve a database storage key without permitting path traversal."""
    base = Path(root).resolve()
    candidate = (base / storage_key).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError("invalid screenshot storage key")
    return candidate


def _same_origin(candidate: str, expected: str) -> bool:
    left = urlparse(candidate)
    right = urlparse(expected)
    left_port = left.port or (443 if left.scheme == "https" else 80)
    right_port = right.port or (443 if right.scheme == "https" else 80)
    return (
        left.scheme == right.scheme
        and left.hostname == right.hostname
        and left_port == right_port
    )


async def capture_url(
    url: str,
    output_path: Path,
    *,
    pinned_ip: str,
    excluded_paths: list[str] | None = None,
) -> ScreenshotCaptureResult:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("screenshot target must be an HTTP(S) URL")
    if not ipaddress.ip_address(pinned_ip).is_global:
        raise ValueError("screenshot target IP must be public")
    excluded_paths = excluded_paths or []
    output_path.parent.mkdir(parents=True, exist_ok=True)
    blocked_requests = 0

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-default-apps",
                "--disable-extensions",
                "--disable-sync",
                f"--host-resolver-rules=MAP {parsed.hostname} {pinned_ip}, EXCLUDE localhost",
            ],
        )
        try:
            context = await browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                ignore_https_errors=True,
                accept_downloads=False,
                java_script_enabled=True,
                service_workers="block",
            )
            page = await context.new_page()
            page.set_default_timeout(CAPTURE_TIMEOUT_MS)

            async def route_request(route, request):
                nonlocal blocked_requests
                request_path = urlparse(request.url).path or "/"
                is_redirected_navigation = (
                    request.is_navigation_request()
                    and request.url.rstrip("/") != url.rstrip("/")
                )
                blocked = (
                    request.method not in {"GET", "HEAD"}
                    or not _same_origin(request.url, url)
                    or is_redirected_navigation
                    or any(fnmatch(request_path, pattern) for pattern in excluded_paths)
                    or request.resource_type in {"websocket", "eventsource", "media"}
                )
                if blocked:
                    blocked_requests += 1
                    await route.abort("blockedbyclient")
                else:
                    await route.continue_()

            await page.route("**/*", route_request)
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))
            response = await page.goto(
                url, wait_until="domcontentloaded", timeout=CAPTURE_TIMEOUT_MS
            )
            await page.add_style_tag(content="*,*::before,*::after{animation:none!important;transition:none!important}")
            await page.wait_for_timeout(750)
            title = (await page.title()).strip()[:500] or None
            await page.screenshot(
                path=str(output_path),
                full_page=False,
                animations="disabled",
                timeout=CAPTURE_TIMEOUT_MS,
            )
            payload = output_path.read_bytes()
            return ScreenshotCaptureResult(
                sha256=hashlib.sha256(payload).hexdigest(),
                width=VIEWPORT_WIDTH,
                height=VIEWPORT_HEIGHT,
                page_title=title,
                status_code=response.status if response else None,
                blocked_requests=blocked_requests,
            )
        except Exception:
            output_path.unlink(missing_ok=True)
            raise
        finally:
            await browser.close()


async def capture_static_html(html: str, output_path: Path) -> ScreenshotCaptureResult:
    """Network-free render used by integration tests and local diagnostics."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        try:
            context = await browser.new_context(
                viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
                service_workers="block",
            )
            page = await context.new_page()
            await page.route("**/*", lambda route: route.abort("blockedbyclient"))
            await page.set_content(html, wait_until="domcontentloaded")
            title = (await page.title()).strip()[:500] or None
            await page.screenshot(path=str(output_path), full_page=False)
            payload = output_path.read_bytes()
            return ScreenshotCaptureResult(
                sha256=hashlib.sha256(payload).hexdigest(),
                width=VIEWPORT_WIDTH,
                height=VIEWPORT_HEIGHT,
                page_title=title,
                status_code=None,
                blocked_requests=0,
            )
        finally:
            await browser.close()
