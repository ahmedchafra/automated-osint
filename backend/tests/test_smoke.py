from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


API_KEY = "osint-local-dev-key-12345"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    import app.config
    import app.database
    import app.main

    db_path = Path(tmp_path) / "test_backend.db"
    test_engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)
    test_session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)

    monkeypatch.setattr(app.config.settings, "API_KEY", API_KEY, raising=False)
    monkeypatch.setattr(app.config.settings, "REDIS_URL", "redis://localhost:6379/0", raising=False)
    monkeypatch.setattr(app.config.settings, "AUTO_CREATE_DB", True, raising=False)
    app.database.engine = test_engine
    app.database.AsyncSessionLocal = test_session_factory
    app.main.engine = test_engine
    app.main.settings = app.config.settings

    from app.main import app

    def fake_apply_async(*, args, kwargs, task_id):
        return SimpleNamespace(id=task_id)

    monkeypatch.setattr(
        "app.api.scans.execute_scan_task.apply_async", fake_apply_async
    )
    monkeypatch.setattr(
        "app.api.scans.content_discovery_task.apply_async", fake_apply_async
    )

    with TestClient(app) as test_client:
        yield test_client

    import asyncio

    asyncio.run(test_engine.dispose())


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["message"] == "OSINT Platform API is running"
    assert payload["database"] == "ok"


def test_api_key_reconciles_legacy_system_user_to_active_admin(client):
    import asyncio

    from sqlalchemy import select

    from app.database import AsyncSessionLocal
    from app.models.user import User

    headers = {"X-API-Key": API_KEY}
    first = client.get("/api/auth/me", headers=headers)
    assert first.status_code == 200

    async def make_legacy():
        async with AsyncSessionLocal() as session:
            user = (
                await session.execute(select(User).where(User.username == "__api__"))
            ).scalar_one()
            user.role = "user"
            user.is_active = False
            await session.commit()

    asyncio.run(make_legacy())
    reconciled = client.get("/api/auth/me", headers=headers)
    assert reconciled.status_code == 200
    assert reconciled.json()["role"] == "admin"
    assert reconciled.json()["is_active"] is True


def test_content_discovery_requires_active_mode_and_verified_live_url(client):
    import asyncio

    from app.database import AsyncSessionLocal
    from app.services.asset_service import upsert_asset

    headers = {"X-API-Key": API_KEY}
    validated = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "validated"},
    ).json()["scan"]
    blocked = client.post(
        f"/api/scans/{validated['id']}/content-discovery",
        headers=headers,
        json={"profile": "common"},
    )
    assert blocked.status_code == 409
    assert "Active mode" in blocked.json()["detail"]

    active = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "active"},
    ).json()["scan"]
    empty = client.post(
        f"/api/scans/{active['id']}/content-discovery",
        headers=headers,
        json={"profile": "common"},
    )
    assert empty.status_code == 409
    assert "No verified in-scope live URLs" in empty.json()["detail"]

    async def seed_live_url():
        async with AsyncSessionLocal() as session:
            await upsert_asset(
                session,
                scan_id=active["id"],
                asset_type="URL",
                value="https://example.com/",
                state="LIVE",
                source_module="http_probe",
                in_scope=True,
            )
            await session.commit()

    asyncio.run(seed_live_url())
    accepted = client.post(
        f"/api/scans/{active['id']}/content-discovery",
        headers=headers,
        json={"profile": "exposure"},
    )
    assert accepted.status_code == 202
    assert accepted.json()["profile"] == "exposure"
    jobs = client.get(f"/api/scans/{active['id']}/jobs", headers=headers).json()
    discovery_job = next(job for job in jobs if job["job_type"] == "content_discovery")
    assert discovery_job["stage"] == "content_discovery"
    assert discovery_job["status"] == "QUEUED"


def test_scan_crud_flow(client):
    headers = {"X-API-Key": API_KEY}

    create_response = client.post(
        "/api/scans",
        headers=headers,
        json={
            "target_domain": "example.com",
            "selected_vectors": ["INFRASTRUCTURE"],
            "target_usernames": ["example"],
        },
    )
    assert create_response.status_code == 202
    created = create_response.json()
    scan_id = created["scan"]["id"]
    assert created["task_id"]
    assert created["scan"]["status"] == "QUEUED"
    assert created["scan"]["scan_mode"] == "validated"
    assert created["scan"]["target_usernames"] == ["example"]

    list_response = client.get("/api/scans", headers=headers)
    assert list_response.status_code == 200
    scans = list_response.json()
    assert len(scans) == 1
    assert scans[0]["target_domain"] == "example.com"

    detail_response = client.get(f"/api/scans/{scan_id}", headers=headers)
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["id"] == scan_id
    assert detail["findings"] == []

    jobs_response = client.get(f"/api/scans/{scan_id}/jobs", headers=headers)
    assert jobs_response.status_code == 200
    jobs = jobs_response.json()
    assert len(jobs) == 1
    assert jobs[0]["celery_task_id"] == created["task_id"]
    assert jobs[0]["status"] == "QUEUED"
    assert jobs[0]["stage"] == "full_scan"

    assets_response = client.get(f"/api/scans/{scan_id}/assets", headers=headers)
    assert assets_response.status_code == 200
    assert assets_response.json() == []


def test_scan_facets_are_exact_database_aggregates(client):
    import asyncio

    from app.database import AsyncSessionLocal
    from app.models.finding import Finding
    from app.services.asset_service import upsert_asset

    headers = {"X-API-Key": API_KEY}
    created = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "facets.example", "selected_vectors": ["INFRASTRUCTURE"]},
    )
    assert created.status_code == 202
    scan_id = created.json()["scan"]["id"]

    async def seed():
        async with AsyncSessionLocal() as session:
            session.add_all([
                Finding(
                    scan_id=scan_id, vector_type="INFRASTRUCTURE",
                    entity_type="SUBDOMAIN", entity_value="www.facets.example",
                    severity="INFO", confidence=1.0, source_module="fixture_dns",
                    raw_data={}, normalized_data={}, tags=[],
                ),
                Finding(
                    scan_id=scan_id, vector_type="SEARCH",
                    entity_type="LEAKED_SECRET", entity_value="https://github.com/acme/repo::config.env",
                    severity="HIGH", confidence=0.9, source_module="github_secrets",
                    raw_data={}, normalized_data={"secret_type": "API_KEY"}, tags=["github"],
                ),
            ])
            await upsert_asset(
                session, scan_id=scan_id, asset_type="SUBDOMAIN",
                value="www.facets.example", state="LIVE", source_module="fixture_dns",
                in_scope=True,
            )
            await session.commit()

    asyncio.run(seed())
    response = client.get(f"/api/scans/{scan_id}/facets", headers=headers)
    assert response.status_code == 200
    facets = response.json()
    assert facets["findings_total"] == 2
    assert facets["findings_by_entity_type"] == {"LEAKED_SECRET": 1, "SUBDOMAIN": 1}
    assert facets["findings_by_severity"] == {"HIGH": 1, "INFO": 1}
    assert facets["findings_by_source"] == {"fixture_dns": 1, "github_secrets": 1}
    assert facets["assets_total"] == 1
    assert facets["assets_in_scope"] == 1
    assert facets["assets_by_state"] == {"LIVE": 1}
    assert facets["jobs_total"] == 1
    assert facets["jobs_by_status"] == {"QUEUED": 1}


def test_repeated_finding_refreshes_lifecycle_and_revision(client):
    import asyncio

    from sqlalchemy import select

    from app.database import AsyncSessionLocal
    from app.models.finding import Finding
    from app.workers.task_utils import persist_findings

    headers = {"X-API-Key": API_KEY}
    created = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "lifecycle.example", "selected_vectors": ["SEARCH"]},
    ).json()
    scan_id = created["scan"]["id"]

    async def observe_twice():
        async with AsyncSessionLocal() as session:
            first = {
                "vector_type": "SEARCH",
                "entity_type": "LEAKED_SECRET",
                "entity_value": "https://github.com/acme/repo::config.env",
                "severity": "LOW",
                "confidence": 0.3,
                "source_module": "github_secrets",
                "raw_data": {"type": "code_match"},
                "normalized_data": {"secret_type": "UNKNOWN_SECRET"},
                "tags": ["classifier:v1"],
            }
            assert await persist_findings(
                session, scan_id, [first], observed_for="lifecycle.example"
            ) == 1
            await session.commit()

            revised = {
                **first,
                "severity": "HIGH",
                "confidence": 0.95,
                "normalized_data": {"secret_type": "API_KEY", "classifier_version": 2},
                "tags": ["classifier:v2"],
            }
            assert await persist_findings(
                session, scan_id, [revised], observed_for="lifecycle.example"
            ) == 0
            await session.commit()

            finding = (
                await session.execute(
                    select(Finding).where(Finding.scan_id == scan_id)
                )
            ).scalar_one()
            assert finding.observation_count == 2
            assert finding.revision == 2
            assert finding.severity == "HIGH"
            assert finding.normalized_data["classifier_version"] == 2
            assert finding.last_observed_for == "lifecycle.example"
            assert finding.last_seen_at >= finding.first_seen_at
            return finding.id

    finding_id = asyncio.run(observe_twice())
    response = client.get(
        f"/api/findings/?scan_id={scan_id}&entity_type=LEAKED_SECRET",
        headers=headers,
    )
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["id"] == finding_id
    assert item["observation_count"] == 2
    assert item["revision"] == 2
    assert item["first_seen_at"]
    assert item["last_seen_at"]

def test_scan_creation_persists_scope_manifest(client):
    response = client.post(
        "/api/scans",
        headers={"X-API-Key": API_KEY},
        json={
            "target_domain": "example.com",
            "selected_vectors": ["INFRASTRUCTURE"],
            "scope_manifest": {
                "allowed_domains": ["example.com"],
                "excluded_domains": ["admin.example.com"],
                "excluded_url_paths": ["/logout", "/delete/*"],
                "allowed_ports": [80, 443],
            },
        },
    )

    assert response.status_code == 202
    scope = response.json()["scan"]["scope_manifest"]
    assert scope["allowed_domains"] == ["example.com"]
    assert scope["excluded_domains"] == ["admin.example.com"]
    assert scope["allowed_ports"] == [80, 443]

    blocked = client.post(
        f"/api/scans/{response.json()['scan']['id']}/domain-deep-analysis",
        headers={"X-API-Key": API_KEY},
        json={"domain": "admin.example.com", "theharvester_mode": "quick"},
    )
    assert blocked.status_code == 409
    assert "outside scan scope" in blocked.json()["detail"]


def test_asset_observation_timeline_endpoint(client):
    import asyncio

    from app.database import AsyncSessionLocal
    from app.services.asset_service import upsert_asset

    headers = {"X-API-Key": API_KEY}
    scan = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "validated"},
    ).json()["scan"]

    async def seed_observations():
        async with AsyncSessionLocal() as session:
            await upsert_asset(
                session,
                scan_id=scan["id"],
                asset_type="SUBDOMAIN",
                value="www.example.com",
                source_module="crtsh",
            )
            await upsert_asset(
                session,
                scan_id=scan["id"],
                asset_type="SUBDOMAIN",
                value="www.example.com",
                state="RESOLVED",
                source_module="dns_resolver",
                dns_records={"A": ["93.184.216.34"]},
                resolved_ips=["93.184.216.34"],
            )
            await session.commit()

    asyncio.run(seed_observations())

    response = client.get(
        f"/api/scans/{scan['id']}/asset-observations",
        headers=headers,
        params={"canonical_value": "www.example.com"},
    )
    assert response.status_code == 200
    timeline = response.json()
    assert len(timeline) == 2
    assert {event["event_type"] for event in timeline} == {
        "DISCOVERED", "STATE_CHANGED",
    }
    assert timeline[0]["canonical_value"] == "www.example.com"
    assert timeline[0]["observed_at"]
    assert timeline[0]["evidence"]["reported_state"] == "RESOLVED"

    summary_response = client.get(
        f"/api/scans/{scan['id']}/asset-observation-summary",
        headers=headers,
    )
    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert len(summary) == 1
    assert summary[0]["observation_count"] == 2
    assert summary[0]["first_observed_at"]
    assert summary[0]["last_observed_at"]


def test_active_assessment_findings_persist_and_serialize(client):
    import asyncio

    from app.database import AsyncSessionLocal
    from app.workers.task_utils import persist_findings

    headers = {"X-API-Key": API_KEY}
    scan = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "active"},
    ).json()["scan"]

    async def seed_tls_finding():
        async with AsyncSessionLocal() as session:
            created = await persist_findings(session, scan["id"], [{
                "vector_type": "SERVICES",
                "entity_type": "TLS_ASSESSMENT",
                "entity_value": "tls://example.com:443",
                "severity": "INFO",
                "confidence": 1.0,
                "source_module": "tls_assessment",
                "normalized_data": {
                    "hostname": "example.com",
                    "supported_protocols": {"TLSv1.3": {"cipher": "TLS_AES_256_GCM_SHA384"}},
                    "certificate": {"hostname_valid": True},
                    "issues": [],
                },
                "tags": ["active", "tls"],
            }, {
                "vector_type": "SERVICES",
                "entity_type": "WEB_ENDPOINT",
                "entity_value": "https://example.com/search?q",
                "severity": "INFO",
                "confidence": 1.0,
                "source_module": "scoped_crawler",
                "normalized_data": {
                    "url": "https://example.com/search?q",
                    "source_url": "https://example.com/",
                    "crawl_eligible": False,
                    "crawl_reason": "query-bearing URL is evidence-only",
                    "parameter_names": ["q"],
                },
                "tags": ["active", "scoped-crawl", "endpoint"],
            }, {
                "vector_type": "INFRASTRUCTURE",
                "entity_type": "TAKEOVER_ASSESSMENT",
                "entity_value": "docs.example.com",
                "severity": "HIGH",
                "confidence": 0.9,
                "source_module": "takeover_verification",
                "normalized_data": {
                    "hostname": "docs.example.com",
                    "status": "probable_dangling_provider",
                    "provider": "GitHub Pages",
                    "cnames": ["owner.github.io"],
                    "claim_attempted": False,
                },
                "tags": ["active", "takeover-assessment"],
            }])
            await session.commit()
            return created

    assert asyncio.run(seed_tls_finding()) == 3
    response = client.get(
        "/api/findings/",
        headers=headers,
        params={"scan_id": scan["id"], "entity_type": "TLS_ASSESSMENT"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["entity_type"] == "TLS_ASSESSMENT"
    assert payload["items"][0]["normalized_data"]["certificate"]["hostname_valid"] is True

    crawl_response = client.get(
        "/api/findings/",
        headers=headers,
        params={"scan_id": scan["id"], "entity_type": "WEB_ENDPOINT"},
    )
    assert crawl_response.status_code == 200
    crawl_payload = crawl_response.json()
    assert crawl_payload["total"] == 1
    assert crawl_payload["items"][0]["normalized_data"]["parameter_names"] == ["q"]

    takeover_response = client.get(
        "/api/findings/",
        headers=headers,
        params={"scan_id": scan["id"], "entity_type": "TAKEOVER_ASSESSMENT"},
    )
    assert takeover_response.status_code == 200
    takeover_payload = takeover_response.json()
    assert takeover_payload["total"] == 1
    assert takeover_payload["items"][0]["normalized_data"]["provider"] == "GitHub Pages"
    assert takeover_payload["items"][0]["normalized_data"]["claim_attempted"] is False


def test_screenshot_capture_gating_dispatch_and_authenticated_image(monkeypatch, client, tmp_path):
    import asyncio

    from app.config import settings
    from app.database import AsyncSessionLocal
    from app.models.asset import Asset
    from app.models.scan import Scan
    from app.models.screenshot import ScreenshotEvidence
    from app.workers.screenshot_capture import screenshot_capture_task

    headers = {"X-API-Key": API_KEY}
    monkeypatch.setattr(settings, "SCREENSHOT_STORAGE_PATH", str(tmp_path), raising=False)

    passive = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "passive"},
    ).json()["scan"]
    passive_response = client.post(
        f"/api/scans/{passive['id']}/screenshots/capture", headers=headers
    )
    assert passive_response.status_code == 409

    validated = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "validated"},
    ).json()["scan"]
    empty_response = client.post(
        f"/api/scans/{validated['id']}/screenshots/capture", headers=headers
    )
    assert empty_response.status_code == 409

    png_payload = b"\x89PNG\r\n\x1a\nfixture"
    screenshot_id = "screenshot-fixture"
    key = f"{validated['id']}/{screenshot_id}.png"

    async def seed_evidence():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, validated["id"])
            scan.status = "COMPLETED"
            asset = Asset(
                scan_id=validated["id"],
                asset_type="URL",
                value="https://example.com/",
                canonical_value="https://example.com/",
                state="LIVE",
                in_scope=True,
                scope_reason="matches allowed domain",
                wildcard_suspected=False,
                source_modules=["test"],
                evidence_count=1,
                dns_records={},
                resolved_ips=[],
                http_metadata={"status_code": 200},
            )
            session.add(asset)
            await session.flush()
            path = tmp_path / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(png_payload)
            session.add(ScreenshotEvidence(
                id=screenshot_id,
                scan_id=validated["id"],
                asset_id=asset.id,
                url=asset.canonical_value,
                storage_key=key,
                sha256="a" * 64,
                width=1365,
                height=768,
                page_title="Screenshot fixture",
                status_code=200,
                capture_metadata={"blocked_requests": 2},
            ))
            await session.commit()

    asyncio.run(seed_evidence())
    monkeypatch.setattr(
        screenshot_capture_task,
        "apply_async",
        lambda *, args, kwargs, task_id: SimpleNamespace(id=task_id),
    )
    started = client.post(
        f"/api/scans/{validated['id']}/screenshots/capture", headers=headers
    )
    assert started.status_code == 202
    assert started.json()["targets"] == 1

    listing = client.get(
        f"/api/scans/{validated['id']}/screenshots", headers=headers
    )
    assert listing.status_code == 200
    records = listing.json()
    assert len(records) == 1
    assert records[0]["sha256"] == "a" * 64
    assert records[0]["page_title"] == "Screenshot fixture"
    assert records[0]["capture_metadata"]["blocked_requests"] == 2

    image = client.get(
        f"/api/scans/{validated['id']}/screenshots/{screenshot_id}/image",
        headers=headers,
    )
    assert image.status_code == 200
    assert image.headers["content-type"] == "image/png"
    assert image.content == png_payload

    deleted = client.delete(
        f"/api/scans/{validated['id']}", headers=headers
    )
    assert deleted.status_code == 204
    assert not (tmp_path / key).exists()


def test_cancel_scan_revokes_exact_task(monkeypatch, client):
    headers = {"X-API-Key": API_KEY}
    created = client.post(
        "/api/scans",
        headers=headers,
        json={
            "target_domain": "example.com",
            "selected_vectors": ["INFRASTRUCTURE"],
            "target_usernames": [],
        },
    ).json()
    scan_id = created["scan"]["id"]
    expected_task_id = created["task_id"]

    calls = []
    from app.workers.celery_app import celery_app

    monkeypatch.setattr(
        celery_app.control,
        "revoke",
        lambda task_id, **kwargs: calls.append((task_id, kwargs)),
    )
    response = client.post(f"/api/scans/{scan_id}/cancel", headers=headers)

    assert response.status_code == 200
    assert response.json()["revoked"] is True
    assert response.json()["revoked_task_ids"] == [expected_task_id]
    assert calls == [
        (expected_task_id, {"terminate": True, "signal": "SIGTERM"})
    ]
    detail = client.get(f"/api/scans/{scan_id}", headers=headers).json()
    assert detail["status"] == "CANCELLED"


def test_active_validation_is_mode_gated_and_deduplicated(monkeypatch, client):
    headers = {"X-API-Key": API_KEY}
    validated = client.post(
        "/api/scans",
        headers=headers,
        json={
            "target_domain": "example.com",
            "scan_mode": "validated",
            "selected_vectors": ["INFRASTRUCTURE"],
            "target_usernames": [],
        },
    ).json()["scan"]
    rejected = client.post(
        f"/api/scans/{validated['id']}/active-validation", headers=headers
    )
    assert rejected.status_code == 409

    active = client.post(
        "/api/scans",
        headers=headers,
        json={
            "target_domain": "authorized.example",
            "scan_mode": "active",
            "selected_vectors": ["INFRASTRUCTURE"],
            "target_usernames": [],
        },
    ).json()["scan"]

    from app.workers.active_validation import active_validation_task

    monkeypatch.setattr(
        active_validation_task,
        "apply_async",
        lambda *, args, kwargs, task_id: SimpleNamespace(id=task_id),
    )
    started = client.post(
        f"/api/scans/{active['id']}/active-validation", headers=headers
    )
    assert started.status_code == 202
    duplicate = client.post(
        f"/api/scans/{active['id']}/active-validation", headers=headers
    )
    assert duplicate.status_code == 409


def test_cancel_completed_scan_revokes_active_child_job(monkeypatch, client):
    import asyncio
    from datetime import datetime, timezone

    from sqlalchemy import select

    from app.database import AsyncSessionLocal
    from app.models.scan import Scan
    from app.models.scan_job import ScanJob

    headers = {"X-API-Key": API_KEY}
    created = client.post(
        "/api/scans",
        headers=headers,
        json={
            "target_domain": "example.com",
            "selected_vectors": ["INFRASTRUCTURE"],
            "target_usernames": [],
        },
    ).json()
    scan_id = created["scan"]["id"]
    child_task_id = "child-enrichment-task"

    async def seed_active_child():
        async with AsyncSessionLocal() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = "COMPLETED"
            scan.completed_at = datetime.now(timezone.utc)
            primary_job = (
                await session.execute(
                    select(ScanJob).where(ScanJob.scan_id == scan_id)
                )
            ).scalar_one()
            primary_job.status = "COMPLETED"
            primary_job.completed_at = datetime.now(timezone.utc)
            session.add(
                ScanJob(
                    scan_id=scan_id,
                    celery_task_id=child_task_id,
                    job_type="shodan_enrich",
                    stage="service_enrichment",
                    status="RUNNING",
                    progress={},
                    result_summary={},
                )
            )
            await session.commit()

    asyncio.run(seed_active_child())

    calls = []
    from app.workers.celery_app import celery_app

    monkeypatch.setattr(
        celery_app.control,
        "revoke",
        lambda task_id, **kwargs: calls.append((task_id, kwargs)),
    )
    response = client.post(f"/api/scans/{scan_id}/cancel", headers=headers)

    assert response.status_code == 200
    assert response.json()["revoked_task_ids"] == [child_task_id]
    assert calls == [
        (child_task_id, {"terminate": True, "signal": "SIGTERM"})
    ]
    detail = client.get(f"/api/scans/{scan_id}", headers=headers).json()
    assert detail["status"] == "COMPLETED"
    jobs = client.get(f"/api/scans/{scan_id}/jobs", headers=headers).json()
    child = next(job for job in jobs if job["celery_task_id"] == child_task_id)
    assert child["status"] == "CANCELLED"


def test_new_collectors_are_registered():
    from collectors.registry import registry

    expected = {
        "shodan_host",
        "censys_host",
        "cisa_kev",
        "hunter_domain",
        "hibp_breach",
        "serper_search",
        "simple_username_profiler",
        "xposedornot_breach",
        "holehe",
        "maigret",
        "github_secrets",
        "telegram_monitor",
    }

    assert expected.issubset(registry.get_all_collectors().keys())


def test_crtsh_deduplicates_subdomains_across_certificates(monkeypatch):
    import asyncio

    from collectors.infrastructure.crtsh import CrtshCollector

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return [
                {
                    "serial_number": "1",
                    "name_value": "www.example.com\napi.example.com",
                },
                {
                    "serial_number": "2",
                    "name_value": "www.example.com\nmail.example.com",
                },
            ]

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, *args, **kwargs):
            return FakeResponse()

    monkeypatch.setattr(
        "collectors.infrastructure.crtsh.httpx.AsyncClient", FakeClient
    )
    results = asyncio.run(CrtshCollector().collect("example.com"))

    subdomains = [
        result["value"] for result in results if result["type"] == "SUBDOMAIN"
    ]
    assert sorted(subdomains) == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]
    assert len([result for result in results if result["type"] == "TLS_CERT"]) == 2
    www = next(
        result for result in results
        if result["type"] == "SUBDOMAIN" and result["value"] == "www.example.com"
    )
    assert www["cert_serials"] == ["1", "2"]


def test_scan_websocket_stream(monkeypatch, client):
    class FakeStreamer:
        async def stream(self, websocket, scan_id):
            await websocket.send_json({"event": "connected", "scan_id": scan_id})
            await websocket.send_text('{"event":"scan_completed","scan_id":"abc"}')

    from app.api.ws import get_scan_event_streamer
    from app.main import app

    app.dependency_overrides[get_scan_event_streamer] = lambda: FakeStreamer()

    with client.websocket_connect(
        "/ws/scans/abc", headers={"X-API-Key": API_KEY}
    ) as websocket:
        first = websocket.receive_json()
        second = websocket.receive_text()

    app.dependency_overrides.clear()

    assert first["event"] == "connected"
    assert first["scan_id"] == "abc"
    assert second == '{"event":"scan_completed","scan_id":"abc"}'


def test_correlation_links_are_queryable(client):
    import asyncio

    from app.database import AsyncSessionLocal
    from app.models.finding import Finding
    from app.models.scan import Scan
    from app.models.user import User
    from app.services.correlation import CorrelationEngine

    async def seed_and_correlate():
        async with AsyncSessionLocal() as session:
            owner = User(
                username="correlation-owner",
                email="correlation@example.com",
                hashed_password="not-used-in-this-test",
            )
            session.add(owner)
            await session.flush()
            scan = Scan(
                target_domain="example.com",
                selected_vectors=["INFRASTRUCTURE"],
                owner_id=owner.id,
            )
            session.add(scan)
            await session.flush()

            subdomain = Finding(
                scan_id=scan.id,
                vector_type="INFRASTRUCTURE",
                entity_type="SUBDOMAIN",
                entity_value="www.example.com",
                severity="INFO",
                confidence=1.0,
                source_module="dns_resolver",
                raw_data={},
                normalized_data={"resolved_ips": ["93.184.216.34"]},
                tags=[],
            )
            ip = Finding(
                scan_id=scan.id,
                vector_type="INFRASTRUCTURE",
                entity_type="IP_ADDRESS",
                entity_value="93.184.216.34",
                severity="INFO",
                confidence=1.0,
                source_module="dns_resolver",
                raw_data={},
                normalized_data={"ip": "93.184.216.34"},
                tags=[],
            )
            port = Finding(
                scan_id=scan.id,
                vector_type="INFRASTRUCTURE",
                entity_type="PORT_SERVICE",
                entity_value="93.184.216.34:443",
                severity="INFO",
                confidence=0.9,
                source_module="shodan_internetdb",
                raw_data={},
                normalized_data={"ip": "93.184.216.34", "port": 443},
                tags=[],
            )
            cve = Finding(
                scan_id=scan.id,
                vector_type="INFRASTRUCTURE",
                entity_type="CVE",
                entity_value="CVE-2024-0001",
                severity="HIGH",
                confidence=0.9,
                source_module="shodan_internetdb",
                raw_data={},
                normalized_data={"ip": "93.184.216.34", "cve": "CVE-2024-0001"},
                tags=[],
            )
            session.add_all([subdomain, ip, port, cve])
            await session.flush()

            links_created = await CorrelationEngine(session, scan.id).run()
            await session.commit()
            return scan.id, links_created

    scan_id, links_created = asyncio.run(seed_and_correlate())
    assert links_created == 3

    response = client.get(
        f"/api/links?scan_id={scan_id}",
        headers={"X-API-Key": API_KEY},
    )

    assert response.status_code == 200
    link_types = {link["link_type"] for link in response.json()}
    assert link_types == {"RESOLVES_TO", "HAS_PORT", "HAS_VULNERABILITY"}


def test_every_entity_type_round_trips_through_storage_and_api(client):
    """Guard the collector -> DB -> Pydantic response contract end to end."""
    import asyncio

    from app.database import AsyncSessionLocal
    from app.schemas.enums import EntityType
    from app.workers.task_utils import persist_findings

    headers = {"X-API-Key": API_KEY}
    scan = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "passive"},
    ).json()["scan"]

    async def seed_all_types():
        findings = [
            {
                "vector_type": "INFRASTRUCTURE",
                "entity_type": entity_type.value,
                "entity_value": f"fixture:{entity_type.value.lower()}",
                "severity": "INFO",
                "confidence": 0.75,
                "source_module": "contract_fixture",
                "raw_data": {"kind": entity_type.value},
                "normalized_data": {"display": entity_type.value},
                "tags": ["contract-test"],
            }
            for entity_type in EntityType
        ]
        async with AsyncSessionLocal() as session:
            created = await persist_findings(session, scan["id"], findings)
            await session.commit()
            return created

    assert asyncio.run(seed_all_types()) == len(EntityType)

    response = client.get(
        "/api/findings/",
        headers=headers,
        params={"scan_id": scan["id"], "limit": 100000},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == len(EntityType)
    assert {item["entity_type"] for item in payload["items"]} == {
        entity_type.value for entity_type in EntityType
    }
    assert all(isinstance(item["raw_data"], dict) for item in payload["items"])
    assert all(isinstance(item["normalized_data"], dict) for item in payload["items"])
    assert all(item["source_module"] == "contract_fixture" for item in payload["items"])


def test_vector_context_checkpoint_preserves_savepoint_and_database_dedup(client):
    import asyncio

    from sqlalchemy import func, select

    from app.database import AsyncSessionLocal
    from app.models.finding import Finding
    from app.models.scan import Scan
    from app.services.vectors.context import VectorContext

    headers = {"X-API-Key": API_KEY}
    scan = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "passive"},
    ).json()["scan"]

    class Publisher:
        async def publish(self, *args, **kwargs):
            return None

    async def exercise_context():
        async with AsyncSessionLocal() as session:
            db_scan = await session.get(Scan, scan["id"])
            ctx = VectorContext(
                db=session,
                scan_id=db_scan.id,
                target_domain=db_scan.target_domain,
                target_usernames=[],
                publisher=Publisher(),
            )
            await ctx.load_seen_findings()
            async with session.begin_nested():
                first = await ctx.persist([{
                    "vector_type": "INFRASTRUCTURE",
                    "entity_type": "SUBDOMAIN",
                    "entity_value": "www.example.com",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "source_module": "duplicate_fixture",
                }])
                await ctx.commit()
                second = await ctx.persist([{
                    "vector_type": "SERVICES",
                    "entity_type": "SUBDOMAIN",
                    "entity_value": "www.example.com",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "source_module": "duplicate_fixture",
                }])
                await ctx.commit()
            await session.commit()
            count = (
                await session.execute(
                    select(func.count(Finding.id)).where(
                        Finding.scan_id == scan["id"],
                        Finding.source_module == "duplicate_fixture",
                    )
                )
            ).scalar_one()
            return first, second, count

    assert asyncio.run(exercise_context()) == (1, 0, 1)


def test_passive_infrastructure_creates_candidate_assets_without_direct_probes(
    client, monkeypatch
):
    import asyncio

    from sqlalchemy import select

    from app.database import AsyncSessionLocal
    from app.models.asset import Asset
    from app.models.scan import Scan
    from app.services.vectors import infrastructure
    from app.services.vectors.context import VectorContext

    headers = {"X-API-Key": API_KEY}
    scan = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "passive"},
    ).json()["scan"]
    requested: list[str] = []

    class FakeCollector:
        def __init__(self, name):
            self.name = name

        async def execute(self, target):
            requested.append(self.name)
            if self.name == "crtsh":
                return [{
                    "vector_type": "INFRASTRUCTURE",
                    "entity_type": "SUBDOMAIN",
                    "entity_value": "www.example.com",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "source_module": "crtsh",
                }]
            if self.name == "rdap_lookup":
                return [{
                    "vector_type": "INFRASTRUCTURE",
                    "entity_type": "DOMAIN_METADATA",
                    "entity_value": target,
                    "severity": "INFO",
                    "confidence": 1.0,
                    "source_module": "rdap_lookup",
                }]
            return []

    def fake_get_collector(name):
        return lambda: FakeCollector(name)

    monkeypatch.setattr(infrastructure.registry, "get_collector", fake_get_collector)

    class Publisher:
        async def publish(self, *args, **kwargs):
            return None

    async def exercise():
        async with AsyncSessionLocal() as session:
            db_scan = await session.get(Scan, scan["id"])
            ctx = VectorContext(
                db=session,
                scan_id=db_scan.id,
                target_domain=db_scan.target_domain,
                target_usernames=[],
                publisher=Publisher(),
                target_type=db_scan.target_type,
                scan_mode=db_scan.scan_mode,
                scope_manifest=db_scan.scope_manifest,
            )
            await ctx.load_seen_findings()
            async with session.begin_nested():
                await infrastructure.run(ctx)
            await session.commit()
            return list((await session.execute(
                select(Asset).where(Asset.scan_id == scan["id"])
            )).scalars().all())

    assets = asyncio.run(exercise())
    assert {(asset.asset_type, asset.canonical_value, asset.state) for asset in assets} == {
        ("DOMAIN", "example.com", "CANDIDATE"),
        ("SUBDOMAIN", "www.example.com", "CANDIDATE"),
    }
    assert "dns_email_posture" not in requested
    assert "dns_resolver" not in requested
    assert "web_surface" not in requested

    response = client.get(f"/api/scans/{scan['id']}/assets", headers=headers)
    assert response.status_code == 200
    assert {item["state"] for item in response.json()} == {"CANDIDATE"}


def test_validated_infrastructure_promotes_assets_and_exposes_them_via_api(
    client, monkeypatch
):
    import asyncio

    from app.database import AsyncSessionLocal
    from app.models.scan import Scan
    from app.services.dns_validation import WildcardDnsResult
    from app.services.vectors import infrastructure
    from app.services.vectors.context import VectorContext

    headers = {"X-API-Key": API_KEY}
    scan = client.post(
        "/api/scans",
        headers=headers,
        json={"target_domain": "example.com", "scan_mode": "validated"},
    ).json()["scan"]

    class FakeCollector:
        def __init__(self, name):
            self.name = name

        async def execute(self, target):
            if self.name == "crtsh":
                return [{
                    "vector_type": "INFRASTRUCTURE",
                    "entity_type": "SUBDOMAIN",
                    "entity_value": "www.example.com",
                    "severity": "INFO",
                    "confidence": 1.0,
                    "source_module": "crtsh",
                }]
            if self.name == "dns_resolver":
                return [{
                    "vector_type": "INFRASTRUCTURE",
                    "entity_type": "SUBDOMAIN",
                    "entity_value": target,
                    "severity": "INFO",
                    "confidence": 1.0,
                    "source_module": "dns_resolver",
                    "normalized_data": {
                        "resolved_ips": ["93.184.216.34"],
                        "dns_records": {"A": ["93.184.216.34"]},
                    },
                }]
            return []

    monkeypatch.setattr(
        infrastructure.registry,
        "get_collector",
        lambda name: lambda: FakeCollector(name),
    )

    async def no_wildcard(target):
        return WildcardDnsResult()

    async def live_probe(hostname, expected_ips):
        return {
            "url": f"https://{hostname}/",
            "scheme": "https",
            "status_code": 200,
            "headers": {"server": "fixture"},
            "redirect_location": None,
            "elapsed_ms": 1,
        }

    monkeypatch.setattr(infrastructure, "detect_wildcard_dns", no_wildcard)
    monkeypatch.setattr(infrastructure, "probe_http", live_probe)

    class Publisher:
        async def publish(self, *args, **kwargs):
            return None

    async def exercise():
        async with AsyncSessionLocal() as session:
            db_scan = await session.get(Scan, scan["id"])
            ctx = VectorContext(
                db=session,
                scan_id=db_scan.id,
                target_domain=db_scan.target_domain,
                target_usernames=[],
                publisher=Publisher(),
                target_type=db_scan.target_type,
                scan_mode=db_scan.scan_mode,
                scope_manifest=db_scan.scope_manifest,
            )
            await ctx.load_seen_findings()
            async with session.begin_nested():
                await infrastructure.run(ctx)
            await session.commit()

    asyncio.run(exercise())
    response = client.get(f"/api/scans/{scan['id']}/assets", headers=headers)
    assert response.status_code == 200
    assets = {(item["asset_type"], item["canonical_value"]): item for item in response.json()}
    assert all(item["created_at"] <= item["updated_at"] for item in response.json())
    assert assets[("DOMAIN", "example.com")]["state"] == "LIVE"
    assert assets[("SUBDOMAIN", "www.example.com")]["state"] == "LIVE"
    assert assets[("IP_ADDRESS", "93.184.216.34")]["state"] == "RESOLVED"
    assert assets[("URL", "https://example.com/")]["state"] == "LIVE"
    assert assets[("URL", "https://www.example.com/")]["state"] == "LIVE"
    assert assets[("URL", "https://example.com/")]["http_metadata"]["status_code"] == 200
