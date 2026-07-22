# Backend Status

## Implemented

- FastAPI app skeleton with `/health` in [`app/main.py`](./app/main.py)
- Central API router with scans, findings, and dashboard routes in [`app/api/router.py`](./app/api/router.py)
- Async SQLAlchemy engine and session factory in [`app/database.py`](./app/database.py)
- Core models for scans, findings, entity links, and AI queries in [`app/models`](./app/models)
- Scan API with:
  - `POST /api/scans`
  - `GET /api/scans`
  - `GET /api/scans/{id}`
- WebSocket endpoint for scan progress at `/ws/scans/{id}`
- Celery app configured with Redis broker/backend in [`app/workers/celery_app.py`](./app/workers/celery_app.py)
- Celery task entrypoint for scan execution in [`app/workers/scan_tasks.py`](./app/workers/scan_tasks.py)
- Scan orchestrator for infrastructure vector processing in [`app/services/scan_service.py`](./app/services/scan_service.py)
- Redis pub/sub progress publisher in [`app/services/progress.py`](./app/services/progress.py)
- Redis-backed WebSocket event streamer in [`app/services/streaming.py`](./app/services/streaming.py)
- Infrastructure correlation engine for `RESOLVES_TO`, `HAS_PORT`, and `HAS_VULNERABILITY` links in [`app/services/correlation.py`](./app/services/correlation.py)
- Entity link API at `GET /api/links`
- Infrastructure collectors for:
  - `crt.sh`
  - DNS resolution
  - Shodan InternetDB
- Docker support for API, worker, Postgres, and Redis in [`docker-compose.yml`](../docker-compose.yml)
- Backend smoke tests in [`tests/test_smoke.py`](./tests/test_smoke.py)

## Next

- Replace the current infrastructure-only workflow with vector-specific Celery orchestration
- Add collectors for services/vulnerabilities, identity/leaks, username profiling, and AI search
- Expand correlation beyond infrastructure links into identity, breach, search, and username entities
- Add Alembic migrations for the final PostgreSQL schema instead of relying on auto-create
- Add integration tests that run against real Postgres and Redis containers
- Add validation and normalization helpers for scan inputs and finding payloads
- Add rate limiting / retry policy controls for external collectors

## Verified

- Python bytecode compilation passes for `backend/app` and `backend/collectors`
- Import smoke checks pass for the FastAPI app and Celery app
- Auth-gated scan routes respond correctly when the API key is provided
- `POST /api/scans` returns `202 Accepted` in the smoke test with Celery stubbed
- `GET /api/scans` and `GET /api/scans/{id}` return the persisted scan record in the smoke test
- WebSocket route `/ws/scans/{id}` streams mocked scan events in the smoke test
- `GET /api/links` returns correlated infrastructure graph edges in the smoke test
- Current smoke suite result: `4 passed`

## Test Commands

Run from `backend/`:

```powershell
python -m pytest
```

Run with the virtualenv directly:

```powershell
& .\.venv\Scripts\python.exe -m pytest
```
