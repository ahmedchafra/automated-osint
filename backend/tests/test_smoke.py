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
