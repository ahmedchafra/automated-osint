# � OSINT Platform � Complete Handover

Read this first. It covers everything to understand, run, and scale the project.

## 1. What It Does

Automated OSINT & Attack Surface Management platform.
- **Phase 1** (auto, passive, free): crt.sh, subfinder, DNS, Shodan InternetDB. No API keys. Completes in seconds.
- **Phase 2** (on-demand enrichment, paid): UI buttons trigger Shodan Host, Censys Host, Hunter, GitHub secrets, dnstwist, Telegram monitoring, breach checks, AI Google dorking.

Findings stored in Postgres, correlated into entity graph. React workspace with 5 tabs (Infrastructure, Identity, Secrets, Threat Intel, Brand Protection).

**Brand:** "OWL OSINT" in the sidebar UI.

## 2. Architecture

```
Frontend (Vite React 19) :5173
    |
    v  axios + X-API-Key
Backend API (FastAPI) :8000  prefix:/api  WS:/ws
    |
    v  Celery task dispatch
Workers (ForkPool, async)
    |
    v
Postgres :5432 (osint_platform)   Redis :6379 (broker + pubsub)
    ^
    |
Collector Layer (~20 collectors, auto-discovered via registry)
```

## 3. Quick Start

```
./start.sh    (builds, waits for health)
curl http://localhost:8000/health
cd frontend && npm run dev
```

## 4. Authentication

All `/api/*` routes and the WebSocket require the API key in ONE of:
- Header: `X-API-Key: osint-local-dev-key-12345`
- Query param: `?api_key=osint-local-dev-key-12345` (WebSocket uses this)
- Subprotocol header: `Sec-WebSocket-Protocol: api-key.<value>` (browser fallback)

Frontend reads key from `import.meta.env.VITE_API_KEY` with hardcoded fallback to the dev key.
Backend enforces via `get_api_key()` dependency in `backend/app/core/security.py:7`.

## 5. Services & Ports

| Service | URL |
|---------|-----|
| API | http://localhost:8000 |
| Swagger docs | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| Frontend dev | http://localhost:5173 |
| Frontend prod | http://localhost:80 |
| Celery Flower | http://localhost:5555 |
| Postgres | localhost:5432 (user/pass: postgres/postgres) |
| Redis | localhost:6379 |

## 6. Data Model

**6 tables** all inheriting `BaseModel` (`backend/app/models/base.py`) which adds:
- `id` (UUID primary key)
- `created_at` (timestamptz)

| Table | Key columns | Purpose |
|-------|-------------|---------|
| `scans` | target_domain, status, selected_vectors(JSON), target_usernames(JSON), completed_at | Scan lifecycle |
| `findings` | scan_id(FK), vector_type, entity_type, entity_value, severity, confidence, source_module, raw_data(JSON), normalized_data(JSON), tags(JSON), search_vector(tsvector, Postgres-only) | All evidence records |
| `entity_links` | scan_id(FK), source_finding_id(FK), target_finding_id(FK), link_type, confidence | Correlation edges |
| `ai_queries` | scan_id(FK), user_prompt, generated_dork, model_used, search_results(JSON) | AI dork audit trail |

**Scan statuses:** QUEUED, PENDING, RUNNING, COMPLETED, FAILED

**Finding entity types** (`backend/app/schemas/enums.py`):
SUBDOMAIN, IP_ADDRESS, PORT_SERVICE, CVE, EMAIL, BREACH, PROFILE, DORK_RESULT, TECHNOLOGY, OPEN_PORT, GITHUB_REPO, LEAKED_SECRET, TELEGRAM_CHANNEL, TELEGRAM_MESSAGE, TLS_CERT, HOST_METADATA, DNS_RECORD, DOMAIN_METADATA, EMAIL_PLATFORM, LOOKALIKE_DOMAIN

**Vector types:** INFRASTRUCTURE, SERVICES, IDENTITY, SEARCH, USERNAME

**Link types (correlation engine):** RESOLVES_TO, HAS_PORT, MATCHES_CVE, HAS_VULNERABILITY, BREACHED_IN, REFERENCES, EXPOSED_IN

## 7. Taxonomy (ALL enums live in one file)

`backend/app/schemas/enums.py` is the single source of truth for:
- VectorType, EntityType, Severity, LinkType, ScanStatus enums
- `SEVERITY_ORDER` dict (INFO=0 < LOW < MEDIUM < HIGH < CRITICAL=4)

**Every schema, model column, and frontend dropdown uses these enums.** Add new types here first.

## 8. Collector Layer

Auto-discovered at import time via `CollectorRegistry.discover_collectors()` (`backend/collectors/registry.py`) which uses `pkgutil.walk_packages` to find every `BaseCollector` subclass.

Each collector must provide `CollectorMetadata` (name, vector, description, passive, requires_api_key, api_key_env) and implement `collect(target) -> List[Dict]` and `normalize(raw) -> Dict`. `BaseCollector.execute()` wraps both with 3-retry backoff.

### Infrastructure collectors
| Name | File | What it does |
|------|------|-------------|
| `crtsh` | `collectors/infrastructure/crtsh.py` | Certificate transparency logs |
| `subfinder` | `collectors/infrastructure/subfinder.py` | Subdomain enumeration (40+ sources, subprocess) |
| `dns_resolver` | `collectors/infrastructure/dns_resolver.py` | DNS A/AAAA resolution |
| `shodan_internetdb` | `collectors/infrastructure/shodan_internetdb.py` | Free host lookup (no API key) |

### Identity collectors
| Name | File | Requires |
|------|------|---------|
| `hunter_domain` | `collectors/identity/hunter_domain.py` | HUNTER_API_KEY |
| `hibp_breach` | `collectors/identity/hibp_breach.py` | HIBP_API_KEY |
| `holehe` | `collectors/identity/holehe.py` | None (holehe lib) |
| `github_secrets` | `collectors/identity/github_secrets.py` | GITHUB_TOKEN (env, not in config) |
| `xposedornot_breach` | `collectors/identity/xposedornot.py` | None |

### Services collectors
| Name | File | Requires |
|------|------|---------|
| `shodan_host` | `collectors/services/shodan_host.py` | SHODAN_API_KEY |
| `censys_host` | `collectors/services/censys_host.py` | CENSYS_API_SECRET (PAT token) |
| `nvd_cve` | `collectors/services/nvd_cve.py` | NVD_API_KEY (optional, raises rate limit) |
| `cisa_kev` | `collectors/services/cisa_kev.py` | None |
| `xposedornot` | (identity/xposedornot.py) | None |

### Search collectors
| Name | File | Requires |
|------|------|---------|
| `dnstwist` | `collectors/search/dnstwist.py` | None (library / API / local fallback chain) |
| `serper_dork_search` | `collectors/search/serper_dork_search.py` | SERPER_API_KEY |
| `serper_search` | `collectors/search/serper_search.py` | SERPER_API_KEY |
| `telegram_monitor` | `collectors/search/telegram_monitor.py` | TG_API_ID + TG_API_HASH (Telethon) |

### Username collectors
| Name | File | Requires |
|------|------|---------|
| `maigret` | `collectret.py` | None |
| `simple_profiler` | `collectors/username/simple_profiler.py` | None |

**Collector pattern:** `normalize()` must return dict with keys: `entity_type`, `entity_value`, `severity` (optional), `confidence` (optional, 0.0-1.0), `normalized_data` (optional dict, can include `resolved_ips` list for SUBDOMAIN findings so the correlation engine links them to IP_ADDRESS findings).

## 9. Celery Tasks & Workers

**All tasks MUST be imported in `backend/app/workers/celery_app.py`** or they won't register. The `include=["app.workers.scan_tasks"]` in Celery init plus the explicit imports below cover discovery.

### Current task registry (in `celery_app.py`)

```python
celery_app = Celery("osint_worker", broker=REDIS_URL, backend=REDIS_URL, include=["app.workers.scan_tasks"])

import app.workers.scan_tasks          # execute_scan_task
import app.workers.pivot_tasks         # pivot_sweep_task
import app.workers.subdomain_enrich    # subdomain_enrich_task
import app.workers.email_breach        # email_breach_task
import app.workers.deep_pivot          # email_deep_analysis_task
import app.workers.domain_deep_analysis # domain_deep_analysis_task
import app.workers.threat_intel        # threat_intel_task
import app.workers.unified_scan        # execute_unified_scan_task
import app.workers.initial_scan        # execute_initial_scan_task
import app.workers.shodan_enrich       # shodan_enrich_task
import app.workers.censys_enrich       # censys_enrich_task
import app.workers.ai_tasks            # run_ai_dork_task
import app.workers.dnstwist_task       # dnstwist_only_task
import app.workers.telegram_task       # telegram_monitor_task
import collectors.registry             # pre-import for forked children
```

Celery config: `task_serializer=json`, `task_track_started=True`, `broker_connection_retry_on_startup=True`.

### Worker event loop pattern

ALL tasks use the `_run(coro)` pattern: create a fresh `asyncio.new_event_loop()`, run the coroutine, dispose the SQLAlchemy engine inside the same loop, close the loop. **This is mandatory** because:
- SQLAlchemy async engine connections are bound to the loop that created them
- holehe/maigret collectors use `asyncio.get_event_loop()` internally
- `task_utils.run_collector_for_scan()` runs collectors in a thread-local loop via `loop.run_in_executor(None, _run_collector_in_loop, ...)`

### Task details

| Task name | File | Params | What it runs |
|-----------|------|--------|-------------|
| `execute_initial_scan` | `workers/initial_scan.py` | scan_id | Phase 1 pipeline: crtsh -> subfinder -> DNS -> Shodan InternetDB, then correlation, then COMPLETED |
| `execute_unified_scan` | `workers/unified_scan.py` | scan_id | All vectors sequentially |
| `execute_scan_task` | `workers/scan_tasks.py` | scan_id | Legacy monolithic scan |
| `shodan_enrich` | `workers/shodan_enrich.py` | scan_id, ip | Shodan Host API on one IP |
| `censys_enrich` | `workers/censys_enrich.py` | scan_id, ip | Censys Host API on one IP |
| `dnstwist_only` | `workers/dnstwist_task.py` | scan_id, domain | dnstwist lookalikes only (no github_secrets) |
| `telegram_monitor` | `workers/telegram_task.py` | scan_id, keyword | telegram_monitor with keyword |
| `email_breach` | `workers/email_breach.py` | scan_id, emails_list | xposedornot on selected emails |
| `subdomain_enrich` | `workers/subdomain_enrich.py` | scan_id, subdomains_list | hunter + xposedornot |
| `pivot_sweep` | `workers/pivot_tasks.py` | scan_id, email | holehe + maigret + hibp per email |
| `email_deep_analysis` | `workers/deep_pivot.py` | scan_id, identifiers_list | xposedornot + holehe + maigret |
| `domain_deep_analysis` | `workers/domain_deep_analysis.py` | scan_id, domain | hunter + github_secrets + dnstwist in parallel |
| `threat_intel` | `workers/threat_intel.py` | scan_id, domain | github_secrets + dnstwist sequentially |
| `run_ai_dork_task` | `workers/ai_tasks.py` | scan_id, user_prompt | AI dork generation + Serper execution, stores DORK_RESULT findings + AIQuery record |

### The `run_collector_for_scan()` shared helper

`backend/app/workers/task_utils.py:38` is the canonical helper that every per-item task imports. It:
1. Runs the collector in a thread-local event loop (avoids loop-mismatch errors)
2. Dedupes against existing findings (entity_type + entity_value + source_module)
3. Creates `Finding` rows and flushes
4. Returns count of newly persisted findings

Use this whenever adding a new enrichment endpoint. Don't duplicate its logic.

## 10. REST API Routes (all prefixed `/api`)

| Route | Method | Body/Query | Task triggered |
|-------|--------|------------|---------------|
| `/scans/` | POST | `{target_domain, selected_vectors, target_usernames}` | `execute_scan_task` |
| `/scans/simple` | POST | `{target_domain}` | `execute_unified_scan_task` (all vectors) |
| `/scans/initial` | POST | `{target_domain}` | `execute_initial_scan_task` (Phase 1) |
| `/scans/?skip=&limit=` | GET | query | - (list scans with counts) |
| `/scans/{id}` | GET | path | - (scan detail + all findings) |
| `/scans/{id}/pivot` | POST | `{email}` | `pivot_sweep_task` |
| `/scans/{id}/enrich` | POST | `{subdomains: [...]}` | `subdomain_enrich_task` |
| `/scans/{id}/check-breaches` | POST | `{emails: [...]}` | `email_breach_task` |
| `/scans/{id}/deep-pivot` | POST | `{identifier, pivot_type}` | `email_deep_analysis_task` |
| `/scans/{id}/domain-deep-analysis` | POST | `{domain}` | `domain_deep_analysis_task` |
| `/scans/{id}/email-deep-analysis` | POST | `{emails: [...]}` | `email_deep_analysis_task` |
| `/scans/{id}/threat-intel` | POST | `{domain}` | `threat_intel_task` |
| `/scans/{id}/shodan-enrich` | POST | `{ip, provider}` | `shodan_enrich_task` / `censys_enrich_task` (provider=shodan/censys/both) |
| `/scans/{id}/censys-enrich` | POST | `{ip}` | `censys_enrich_task` |
| `/scans/{id}/dnstwist` | POST | `{domain}` | `dnstwist_only_task` |
| `/scans/{id}/telegram-monitor` | POST | `{domain, keyword}` | `telegram_monitor_task` |
| `/scans/{id}/ai-dork` | POST | `{prompt}` | `run_ai_dork_task` |
| `/findings/?scan_id=&vector_type=&entity_type=&severity=&q=&skip=&limit=` | GET | query | - (filtered findings list) |
| `/findings/export?format=csv|json|pdf&...` | GET | query | - (download) |
| `/links/?scan_id=&limit=` | GET | query | - (entity graph edges) |
| `/dashboard/stats` | GET | - | - |
| `/ai/generate-dork` | POST | `{prompt}` | - (returns `{dork}` without executing) |
| `/ai/queries?scan_id=&limit=` | GET | query | - (AIQuery history) |
| `/ai/queries/{id}` | GET | path | - |
| `/health` | GET | - | - |

All POST action endpoints return HTTP 202 with `{task_id}` or `{task_ids: [...]}`.
All GET scan/finding endpoints use `dependencies=[Depends(get_api_key)]`.
The WebSocket router is NOT under `/api` (it's at `/ws/scans/{id}`).

## 11. WebSocket (Live Progress)

`ws://localhost:8000/ws/scans/{scan_id}?api_key=...`

Redis pub/sub channel: `scan:{scan_id}`. Every task publishes JSON events:
```
{ "event": "<event_name>", "scan_id": "...", "timestamp": "ISO", ...payload }
```

**Event types emitted:**
- `scan_started`, `scan_completed`
- `phase_started`, `phase_completed`
- `tool_started`, `tool_completed`, `tool_timeout`, `tool_error`
- `dnstwist_started`, `dnstwist_completed`, `dnstwist_error`
- `telegram_monitor_started`, `telegram_monitor_completed`, `telegram_monitor_error`
- `censys_enrich_started`, `threat_intel_started`, `pivot_started`, `email_deep_analysis_started`, `domain_deep_analysis_started`

**Frontend** consumes this in `frontend/src/pages/ScanWorkspace.tsx` via `openScanWebSocket()` in `frontend/src/api/ws.ts`. It tracks per-tool status and phase state to render live progress bars.

**KNOWN BUG (P2):** `ScanProgressPublisher` uses a module-level Redis client singleton. Multiple worker forks cause "got Future attached to a different loop" errors in publish calls. Events silently drop but the scan itself completes fine. Fix: pass a fresh Redis client per publish OR make the publisher create a new connection in each `async with` block. Non-blocking.

## 12. Configuration

`backend/app/config.py` loads from `backend/.env` (or environment). All collector keys are Optional[float|str] so the platform boots in dev with zero external keys.

| Env var | Used by |
|---------|--------|
| `API_KEY` | Auth (default `osint-local-dev-key-12345` — MUST change in prod) |
| `DATABASE_URL` | `postgresql+asyncpg://postgres:postgres@db:5432/osint_platform` |
| `REDIS_URL` | `redis://redis:6379/0` |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` |
| `APP_ENV` | `development` — set to `production` to enforce required keys |
| `SHODAN_API_KEY` | shodan_host collector |
| `CENSYS_API_SECRET` | censys_host collector (PAT, NOT the old API ID/secret pair) |
| `HUNTER_API_KEY` | hunter_domain collector |
| `HIBP_API_KEY` | hibp_breach collector |
| `GROQ_API_KEY` | AIService (llama-3.3-70b-versatile) |
| `SERPER_API_KEY` | serper_dork_search, serper_search |
| `NVD_API_KEY` | nvd_cve (optional, raises rate limit 5->50/30s) |

**Production validator** (`config.py:validate_required_keys_for_start`): refuses to boot if `API_KEY` is the dev default, or if SHODAN/HUNTER/GROQ/SERPER keys are missing, when `APP_ENV=production`.

## 13. Frontend Structure

```
frontend/src/
  App.tsx                    Routes: /, /scans/new, /scans, /scans/:id, /scans/:id/details, /assistant, /graph
  api/client.ts              axios instance, baseURL=http://localhost:8000/api, X-API-Key header
  api/ws.ts                  openScanWebSocket(scansId, onMessage) with auto-reconnect
  context/ScanWorkspaceContext.tsx   Zustand-like reducer for the workspace state
  pages/
    Dashboard.tsx            KPIs from GET /api/dashboard/stats (recharts graphs)
    NewScan.tsx              POST /api/scans/initial -> redirects to /scans/:id
    ScanHistory.tsx          GET /api/scans/?limit=50 -> click through to workspace
    ScanWorkspace.tsx        Main results page with 5 toolbars + event log, WebSocket consumer
    ScanDetails.tsx          Findings table with filters + CSV/JSON/PDF export
    AIAssistant.tsx          dork preview (POST /ai/generate-dork) + run-dork (POST /scans/:id/ai-dork)
    EntityGraph.tsx          Cytoscape graph from GET /api/links/ + GET /api/findings/
  components/workspace/
    InfrastructureTab.tsx    subdomains, per-IP provider selector (Shodan/Censys/Both), CVE list
    IdentityTab.tsx          emails, breach check, deep dive buttons
    SecretsTab.tsx           LEAKED_SECRET + GITHUB_REPO findings, "Scan GitHub Secrets" button
    ThreatIntelTab.tsx       dnstwist, GitHub secrets, telegram monitor sections
    BrandProtectionTab.tsx   lookalike domains with LIVE/NO DNS badges + re-run button
```

State: `@tanstack/react-query` for server state, `framer-motion` for animations, `lucide-react` for icons, `cytoscape` for entity graph.

## 14. AI Dork Pipeline

1. Frontend calls `POST /api/ai/generate-dork` with `{prompt}` -- synchronous, returns `{dork}`. Uses Groq `llama-3.3-70b-versatile`. Frontend shows this as a "preview" before run.
2. Preview endpoint lives in `backend/app/api/ai.py_dork()` -- calls `AIService.generate_dork()`, no side effects.
3. **Run flow:** Frontend calls `POST /api/scans/{id}/ai-dork` -- enqueues `run_ai_dork_task` Celery task.
4. Task in `backend/app/workers/ai_tasks.py`:
   - Calls `AIService.generate_dork(prompt)` for the dork string
   - If Groq fails, falls back to `site:<last-word>` from prompt
   - Runs the dork via Serper (`serper_dork_search` collector)
   - Persists each result as a `DORK_RESULT` finding
   - Stores an `AIQuery` record (for `/api/queries` history + audit)
   - Returns `{scan_id, dork, results_found}`

`AIService` lives at `backend/app/services/ai_service.py`. Single model: `llama-3.3-70b-versatile`, temperature=0.3, max_tokens=100.

## 15. Correlation Engine

`backend/app/services/correlation.py` — `CorrelationEngine(session, scan_id).run() -> int`.

Called at the end of `initial_scan` pipeline (and unified scan). Iterates every finding in the scan and creates `EntityLink` rows if relationship rules match:

- SUBDOMAIN with `resolved_ips` in normalized_data -> link to IP_ADDRESS with `RESOLVED_TO` (confidence 1.0)
- PORT_SERVICE with `ip` in normalized_data -> link to IP_ADDRESS with `HAS_PORT`
- CVE with `ip` in normalized_data -> link to IP_ADDRESS with `HAS_VULNERABILITY`
- BREACH with `email` in normalized_data -> link to EMAIL finding with `BREACHED_IN`

Dedupes against existing links. Returns count of new links created.

## 16. Censys SDK Integration

`backend/collectors/services/censys_host.py` uses the `censys-platform` SDK (v0.14.4, Speakeasy-generated).

**Auth:** Personal Access Token (PAT), NOT the old API ID + Basic auth. Set via `CENSYS_API_SECRET` env var.

**Pattern:**
```python
from censys_platform import SDK
from censys_platform.models import SDKBaseError

with SDK(personal_access_token=token) as sdk:
    host_data = sdk.global_data.get_host(host_id='8.8.8.8')  # NOTE: host_id, not ip
    data = host_data.model_dump()  # Pydantic model -> dict
```

**Free tier:** 0 credits until 2026-07-20. The SDK works correctly, just returns 422 "insufficient balance" which the collector catches and returns `[]`. No findings until credits reset.

**Graceful fallback:** `CENSYS_AVAILABLE = False` if SDK not installed. Collector returns `[]` silently.

## 17. Docker Setup

`docker-compose.yml` defines 4 services:
- `db` (postgres:16-alpine, port 5432)
- `redis` (redis:7-alpine, port 6379)
- `backend` (python:3.13-slim, port 8000, mounts ./backend:/app)
- `worker` (same image, runs celery worker)

**Backend Dockerfile** (`backend/Dockerfile`):
- Base: `python:3.13-slim`
- Installs: build-essential, libpq-dev, curl, unzip
- Entrypoint: `docker-entrypoint.sh` downloads subfinder v2.6.7 from GitHub releases if not present (handles Docker build network issues)
- Command: `uvicorn app.main:app --host 0.0.0.0 --port 8000`

**IMPORTANT:** `--reload` is intentionally OFF. Uvicorn autoreload triggers a graceful shutdown that hangs while Celery workers hold open asyncpg connections. After code changes: `docker compose restart backend worker`.

**Volume mounts:** `./backend:/app` means code changes are visible without rebuild. But `requirements.txt` changes require `docker compose build` (pip install is cached in image layer).

## 18. Known Issues & TODOs

### P1 — Progress publisher event loop mismatch
`ScanProgressPublisher` uses a module-level Redis client singleton. Multiple worker forks cause "got Future attached to a different loop" errors in publish calls. Events silently drop but the scan itself completes fine. Fix: pass a fresh Redis client per publish OR make the publisher create a new connection in each `async with` block. Non-blocking.

### P1 — Censys free tier has 0 credits until 2026-07-20
The SDK works correctly, just returns 422 "insufficient balance". Collector catches this and returns `[]`. No findings until credits reset. No code fix needed — just wait or add credits.

### P2 — Telegram monitor requires TG_API_ID + TG_API_HASH
Not in `config.py` Settings class. The collector reads them from `os.environ` directly. Returns 0 findings without them. Add to Settings if you want UI configuration.

### P2 — GitHub secrets collector needs GITHUB_TOKEN
Not in `config.py`. Reads from env directly. Add to Settings for consistency.

### P2 — `POST /scans/` (legacy monolithic) still exists
`execute_scan_task` runs the old full scan path. The frontend NewScan page uses `/scans/initial` (Phase 1). The legacy endpoint is kept for API consumers but could be deprecated.

### P2 — `POST /scans/simple` exists but isn't used by frontend
Runs `execute_unified_scan_task` (all vectors sequentially). Kept for P2 — No `updated_at` field on scans
The `Scan` model only has `created_at` and `completed_at`. Some frontend code might expect `updated_at` — check before adding UI that shows "last updated".

### P2 — Alembic migrations exist but aren't run automatically
`backend/alembic/versions/` has 3 migrations. The app uses `Base.metadata.create_all` in the lifespan handler instead Migrations are for production schema evolution.

### P3 — Frontend tab count badges not implemented
The plan file mentions showing counts next to tab names (e.g., "Infrastructure (241)"). Not yet built.

### P3 — InfrastructureTab source_module filter exists but is basic
The dropdown is rendered but filtering logic may need refinement for large scans.

## 19. How to Add a New Collector

1. Create `backend/collectors/<vector>/<name>.py`
2. Subclass `BaseCollector`, set `metadata = CollectorMetadata(name=..., vector=..., ...)`
3. Implement `collect(target) -> List[Dict]` and `normalize(raw) -> Dict`
4. Registry auto-discovers it at import (no manual registration needed)
5. If it needs a new API key, add it to `backend/app/config.py` Settings class
6. If it needs a new Celery task, create `backend/app/workers/<name>_task.py` using the `_run(coro)` pattern and `run_collector_for_scan()` helper, then add `import app.workers.<name>_task` to `celery_app.py`
7. If it needs a new endpoint, add to `backend/app/api/scans.py` and the corresponding request schema to `backend/app/schemas/base.py`

## 20. How to Add a New API Endpoint

1. Add request schema to `backend/app/schemas/base.py`
2. Add route to `backend/app/api/scans.py` (or appropriate router)
3. If it triggers a task, create the task in `backend/app/workers/` and import it in `celery_app.py`
4. Add frontend API call in `frontend/src/api/client.ts` or directly in the component
5. Add UI button/handler in the appropriate workspace tab

## 21. Testing

```bash
# Run smoke tests
./start.sh --test    (runs test_api.sh)

# Manual API test
curl -H "X-API-Key: osint-local-dev-key-12345" http://localhost:8000/health
curl -H "X-API-Key: osint-local-dev-key-12345" http://localhost:8000/api/scans/?limit=5

# Backend unit tests
cd backend && python -m pytest tests/

# Worker logs
docker logs osint_worker -f

# API logs
docker logs osint_api -f
```

## 22. Next Steps (Recommended Priority)

### Immediate (unblock paid features)
1. **Add Censys credits** or wait until 2026-07-20 for free tier reset
2. **Configure GROQ_API_KEY** in `backend/.env` for AI dork generation
3. **Configure SERPER_API_KEY** for dork search execution
4. **Configure SHODAN_API_KEY** for Shodan Host enrichment
5. **Configure HUNTER_API_KEY** for email discovery
6. **Configure TG_API_ID + TG_API_HASH** for Telegram monitoring

### Short-term (reliability)
7. **Fix progress publisher event loop bug** (P1) — pass fresh Redis client per publish
8. **Add `updated_at` field to Scan model** — useful for UI and debugging
9. **Add GITHUB_TOKEN to Settings** — consistency with other keys
10. **Add TG_API_ID/TG_API_HASH to Settings** — same
11. **Add rate limiting to public endpoints** — slowapi or similar
12. **Add proper logging config** — currently uses print() in collectors

### Medium-term (scale)
13. **Implement tab count badges** in ScanWorkspace
14. **Add pagination to findings table** — currently loads all findings into memory
15. **Add scan deletion endpoint** — currently only via direct DB access
16. **Add scan notes/labels** — operator annotations on findings
17. **Add export scheduling** — periodic PDF report generation
18. **Add webhook notifications** — scan completed → Slack/Discord
19. **Add user authentication** — currently single shared API key
20. **Add scan templates** — pre-configured collector sets for common use cases

### Long-term (product)
21. **Add scheduled/recurring scans** — celery-beat integration
22. **Add finding severity override** — operator can adjust severity
23. **Add false-positive marking** — suppress known-good findings
24. **Add multi-tenancy** — separate workspaces per team
25. **Add report generation** — full PDF report with executive summary
26. **Add dark web monitoring** — integrate HaveIBeenPwned, DeHashed, etc.
27. **Add attack surface scoring** — risk score per target
28. **Add historical comparison** — diff between scan runs

## 23. File Map (Quick Reference)

```
automated osint/
├── docker-compose.yml          # 4 services: db, redis, backend, worker
├── start.sh / stop.sh          # One-click launcher
├── test_api.sh                 # Smoke test script
├── backend/
│   ├── Dockerfile              # python:3.13-slim + subfinder entrypoint
│   ├── docker-entrypoint.sh    # Downloads subfinder on first boot
│   ├── requirements.txt        # All Python deps
│   ├── .env                    # API keys (gitignored in prod)
│   ├── alembic/                # DB migrations (3 versions)
│   ├── tests/                  # pytest smoke tests
│   ├── collectors/             # ~20 collectors, auto-discovered
│   │   ├── base.py             # BaseCollector + CollectorMetadata
│   │   ├── registry.py         # Auto-discovery via pkgutil
│   │   ├── infrastructure/     # crtsh, subfinder, dns_resolver, shodan_internetdb
│   │   ├── identity/           # hunter, hibp, holehe, github_secrets, xposedornot
│   │   ├── services/           # shodan_host, censys_host, nvd_cve, cisa_kev
│   │   ├── search/             # dnstwist, serper_dork_search, serper_search, telegram_monitor
│   │   └── username/           # maigret, simple_profiler
│   └── app/
│       ├── main.py             # FastAPI app, lifespan, CORS, /health
│       ├── config.py           # Settings (pydantic-settings)
│       ├── database.py         # Async engine + session
│       ├── api/
│       │   ├── router.py       # Mounts all routers under /api
│       │   ├── scans.py        # All scan endpoints (17 routes)
│       │   ├── findings.py     # Findings CRUD + export
│       │   ├── links.py        # Entity graph edges
│       │   ├── dashboard.py    # KPI stats
│       │   ├── ai.py           # AI dork preview + history
│       │   ├── ws.py           # WebSocket endpoint
│       │   └── _filters.py     # Query builder for findings
│       ├── core/
│       │   ├── security.py     # X-API-Key auth
│       │   ├── ws_security.py  # WebSocket auth (3 channels)
│       │   └── exceptions.py   # Global exception handlers
│       ├── models/             # SQLAlchemy models (5 tables)
│       ├── schemas/
│       │   ├── base.py         # All Pydantic request/response schemas
│       │   └── enums.py        # ALL taxonomy enums
│       ├── services/
│       │   ├── ai_service.py   # Groq Llama 3.3 70B dork generation
│       │   ├── correlation.py  # Entity link engine
│       │   ├── export_service.py # CSV/JSON/PDF export
│       │   ├── progress.py     # Redis pub/sub publisher
│       │   ├── scan_service.py # Legacy scan orchestrator
│       │   ├── streaming.py    # WebSocket streamer
│       │   └── vectors/        # Per-vector scan       └── workers/            # 15 Celery tasks
│           ├── celery_app.py   # Celery config + task imports
│           ├── task_utils.py   # run_collector_for_scan() helper
│           ├── initial_scan.py # Phase 1 pipeline
│           ├── unified_scan.py # All-vectors scan
│           ├── scan_tasks.py   # Legacy monolithic scan
│           ├── shodan_enrich.py
│           ├── censys_enrich.py
│           ├── dnstwist_task.py
│           ├── telegram_task.py
│           ├── email_breach.py
│           ├── subdomain_enrich.py
│           ├── pivot_tasks.py
│           ├── deep_pivot.py
│           ├── domain_deep_analysis.py
│           ├── threat_intel.py
│           └── ai_tasks.py
└── frontend/
    ├── package.json            # React 19, Vite, TanStack Query, Cytoscape
    ├── vite.config.ts
    └── src/
        ├── App.tsx             # Routes + layout
        ├── api/client.ts       # axios instance
        ├── api/ws.ts           # WebSocket client
        ├── context/            # ScanWorkspaceContext
        ├── pages/              # 7 pages
        └── components/
            ├── workspace/      # 5 tab components + shared
            └── (Chip, EventLog, FindingsTable, ProgressBar, PivotDrawer)
```

---

**Last verified:** 2026-06-29. All 23 API endpoints return 200/202. All 15 Celery tasks register and execute. Test scans cleaned up. Censys returns 0 findings (0 credits until 2026-07-20). Telegram returns 0 findings (no TG_API_ID/TG_API_HASH configured).
