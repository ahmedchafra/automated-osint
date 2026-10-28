"""Read-only browser smoke test for the running Vite application.

Usage (from the repository root):
    python frontend/scripts/ui_smoke.py --scan-id <completed-scan-id>

The script authenticates as the local API development user, visits every
route, opens every scan workspace tab, and fails on browser exceptions,
console errors, HTTP API failures, auth redirects, or React error boundaries.
It never submits a scan or triggers an assessment action.
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
from jose import jwt
from playwright.sync_api import Page, sync_playwright


REPO_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_URL = "http://127.0.0.1:5173"
API_URL = "http://127.0.0.1:8000"


def _env() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in (REPO_ROOT / "backend" / ".env").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _token(config: dict[str, str]) -> str:
    with httpx.Client(base_url=API_URL, timeout=20) as client:
        response = client.get(
            "/api/auth/me", headers={"X-API-Key": config["API_KEY"]}
        )
        response.raise_for_status()
        user = response.json()
    payload = {
        "sub": user["id"],
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
    }
    return jwt.encode(
        payload,
        config.get("JWT_SECRET_KEY", "osint-jwt-secret-change-in-production-12345"),
        algorithm=config.get("JWT_ALGORITHM", "HS256"),
    )


def _assert_page(page: Page, label: str, expected_path: str | None = None) -> dict[str, object]:
    page.wait_for_timeout(900)
    text = page.locator("body").inner_text()
    lowered = text.lower()
    if page.url.endswith("/login") and label not in {"login", "register"}:
        raise AssertionError(f"{label}: unexpectedly redirected to login")
    if expected_path is not None and not page.url.endswith(expected_path):
        raise AssertionError(
            f"{label}: expected path {expected_path!r}, got {page.url!r}"
        )
    if "something went wrong" in lowered or "application error" in lowered:
        raise AssertionError(f"{label}: React error boundary is visible")
    headings = page.locator("h1, h2").all_inner_texts()
    return {
        "label": label,
        "url": page.url,
        "headings": headings[:4],
        "body_chars": len(text),
    }


def run(
    scan_id: str,
    screenshot_dir: str | None = None,
    test_scope_save: bool = False,
) -> dict[str, object]:
    config = _env()
    token = _token(config)
    page_errors: list[str] = []
    console_errors: list[str] = []
    failed_api: list[str] = []
    results: list[dict[str, object]] = []
    current_view = {"label": "startup"}
    output_dir = Path(screenshot_dir).resolve() if screenshot_dir else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)

        # Public auth pages are checked without a stored session.
        public = browser.new_page(viewport={"width": 1440, "height": 1000})
        for label, path in (("login", "/login"), ("register", "/register")):
            public.goto(FRONTEND_URL + path, wait_until="domcontentloaded")
            results.append(_assert_page(public, label, path))
        public.close()

        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        context.add_init_script(
            "localStorage.setItem('owl_osint_token', " + json.dumps(token) + ")"
        )
        page = context.new_page()
        page.on(
            "pageerror",
            lambda error: page_errors.append(
                f"{current_view['label']}: {error}\n{getattr(error, 'stack', '')}"
            ),
        )
        page.on(
            "console",
            lambda message: console_errors.append(
                f"{current_view['label']}: {message.text}"
            )
            if message.type == "error"
            else None,
        )
        page.on(
            "response",
            lambda response: failed_api.append(f"{response.status} {response.url}")
            if response.status >= 400 and "/api/" in response.url
            else None,
        )

        routes = (
            ("dashboard", "/"),
            ("new_scan", "/scans/new"),
            ("scan_history", "/scans"),
            ("scan_workspace", f"/scans/{scan_id}"),
            ("scan_details", f"/scans/{scan_id}/details"),
            ("assistant", f"/assistant/{scan_id}"),
            ("settings", "/settings"),
            ("entity_graph", f"/graph/{scan_id}"),
            ("admin_users", "/admin/users"),
        )
        for label, path in routes:
            current_view["label"] = label
            page.goto(FRONTEND_URL + path, wait_until="domcontentloaded")
            if label == "dashboard":
                page.locator(".ws-header").wait_for(state="visible", timeout=15_000)
            if label == "scan_workspace":
                page.locator(".workspace-header").wait_for(state="visible", timeout=15_000)
            results.append(_assert_page(page, label, path))

            if output_dir and label in {"dashboard", "scan_workspace"}:
                page.screenshot(path=output_dir / f"{label}.png", full_page=True)

            if label == "scan_workspace":
                for tab in (
                    "Overview", "All Evidence", "Infrastructure", "Identity", "Web OSINT", "Secrets",
                    "Threat Intel", "Brand Protection",
                ):
                    current_view["label"] = f"workspace:{tab}"
                    control = page.get_by_role(
                        "button", name=re.compile(rf"^{re.escape(tab)}\b")
                    ).first
                    control.wait_for(state="visible", timeout=10_000)
                    control.click()
                    results.append(_assert_page(page, f"workspace:{tab}"))
                    if tab == "Overview":
                        page.get_by_test_id("workspace-overview").wait_for(state="visible")
                        page.get_by_role("button", name="Edit scope").click()
                        page.get_by_role("button", name="Save and reclassify").wait_for(state="visible")
                        if test_scope_save:
                            page.get_by_role("button", name="Save and reclassify").click()
                            page.get_by_text("Updated", exact=True).wait_for(state="visible", timeout=15_000)
                        else:
                            page.get_by_role("button", name="Cancel").click()
                    if tab == "All Evidence":
                        explorer = page.get_by_test_id("evidence-explorer")
                        explorer.wait_for(state="visible")
                        page.locator(".evidence-expand").first.click()
                        page.get_by_text("Normalized data", exact=True).first.wait_for(state="visible")
                        page.get_by_text("First seen", exact=True).first.wait_for(state="visible")
                        page.get_by_text("Revision", exact=True).first.wait_for(state="visible")
                        next_button = explorer.get_by_role("button", name="Next")
                        if next_button.is_enabled():
                            next_button.click()
                            explorer.get_by_text(re.compile(r"Page 2 of \d+")).wait_for(state="visible")
                    if tab == "Secrets":
                        page.get_by_role("heading", name="GitHub exposure review").wait_for(state="visible")
                        secret_cards = page.get_by_test_id("github-secret-card")
                        if secret_cards.count() > 25:
                            raise AssertionError("workspace:Secrets rendered more than one page of evidence cards")
                        if secret_cards.count():
                            repo_label = secret_cards.first.locator(".ws-secret-repo").inner_text()
                            if "::" in repo_label:
                                raise AssertionError("workspace:Secrets displayed the compound finding identifier as a repository name")
                        if page.locator(".ws-code-block").count():
                            raise AssertionError("workspace:Secrets rendered stored secret content")
                    if output_dir and tab in {"Overview", "All Evidence", "Infrastructure", "Secrets"}:
                        page.screenshot(
                            path=output_dir / f"workspace-{tab.lower().replace(' ', '-')}.png",
                            full_page=True,
                        )

            if label == "entity_graph":
                page.locator("canvas").first.wait_for(state="attached", timeout=10_000)

        # Small-screen contract: the shell, overview, and evidence controls
        # must remain usable without making the document itself overflow.
        mobile_context = browser.new_context(viewport={"width": 390, "height": 844})
        mobile_context.add_init_script(
            "localStorage.setItem('owl_osint_token', " + json.dumps(token) + ")"
        )
        mobile = mobile_context.new_page()
        current_view["label"] = "mobile_workspace"
        mobile.on("pageerror", lambda error: page_errors.append(f"mobile_workspace: {error}"))
        mobile.on(
            "console",
            lambda message: console_errors.append(f"mobile_workspace: {message.text}")
            if message.type == "error" else None,
        )
        mobile.goto(FRONTEND_URL + f"/scans/{scan_id}", wait_until="domcontentloaded")
        mobile.locator(".workspace-header").wait_for(state="visible", timeout=15_000)
        results.append(_assert_page(mobile, "mobile_workspace"))
        overflow = mobile.evaluate("document.documentElement.scrollWidth > window.innerWidth + 1")
        if overflow:
            raise AssertionError("mobile_workspace: document has horizontal overflow")
        mobile.get_by_role("button", name=re.compile(r"^All Evidence\b")).first.click()
        mobile.get_by_test_id("evidence-explorer").wait_for(state="visible")
        results.append(_assert_page(mobile, "mobile_workspace:evidence"))
        if output_dir:
            mobile.screenshot(path=output_dir / "workspace-mobile.png", full_page=True)
        mobile_context.close()

        browser.close()

    # React may log a request failure and also render a useful error state; API
    # failures are still defects in this end-to-end contract and fail the run.
    report = {
        "pages_checked": len(results),
        "results": results,
        "page_errors": page_errors,
        "console_errors": console_errors,
        "failed_api": sorted(set(failed_api)),
    }
    if page_errors or console_errors or failed_api:
        raise AssertionError(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--screenshot-dir")
    parser.add_argument(
        "--test-scope-save",
        action="store_true",
        help="Save the existing scope unchanged to exercise API and DB persistence.",
    )
    arguments = parser.parse_args()
    print(json.dumps(run(
        arguments.scan_id,
        arguments.screenshot_dir,
        arguments.test_scope_save,
    ), indent=2))
