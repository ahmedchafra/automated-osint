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

    def fake_delay(scan_id):
        return SimpleNamespace(id=f"task-{scan_id}")

    monkeypatch.setattr("app.api.scans.execute_scan_task.delay", fake_delay)

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
    assert created["task_id"] == f"task-{scan_id}"
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
