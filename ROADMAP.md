# OWL OSINT Platform -- Development Roadmap

> **Working directory:** `C:\Users\user\Documents\automated osint`
> **Tech stack:** Python 3.13 / FastAPI / Celery / React 19 / Vite / Postgres 16 / Redis 7
> **Frontend:** "OWL OSINT" brand, React/Vite on :5173, FastAPI backend on :8000
> **Auth:** Single shared API key (X-API-Key header or query param)
> **Deployment:** Docker Compose (4 services: db, redis, backend, worker)

---

## Phase 0 -- Quick Wins (fixes already applied)

These fixes were completed in the previous session and are already in the working tree:

| Item | Collector | Change |
|------|-----------|--------|
| Holehe parsing | `collectors/identity/holehe.py` | Added `_NON_PLATFORM` regex filter to strip non-platform status/summary lines like "email used", "rate limit" |
| XposedOrNot empty breach | `collectors/identity/xposedornot.py` | Returns `[]` immediately when `breaches_details` is empty, preventing empty BREACH findings |
| Maigret config tweaks | `collectors/username/maigret.py` | Set `SITE_LIMIT=500`, `PER_SITE_TIMEOUT=4`, `MAX_CONNECTIONS=20`, `--no-recursion --no-extracting` for reliable completion |

---

## Phase 0b -- Remaining High-Priority Fixes

These are quick bugs/issues identified but not yet fixed.

### P0.1 -- Fix Progress Publisher Event Loop (P1 Bug)

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | High |
| **Dependencies** | None |
| **File** | `backend/app/services/progress.py` |

**Problem:** `ScanProgressPublisher` uses a module-level `redis.Redis` client singleton. When Celery forks worker processes, the inherited Redis connection raises "got Future attached to a different loop" on any `publish()` call. Events silently drop; the scan itself still completes.

**Approach:** Replace the module-level singleton with a fresh connection per `async with` block:

```python
class ScanProgressPublisher:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id

    @asynccontextmanager
    async def connect(self):
        r = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            yield r
        finally:
            await r.aclose()

    async def publish(self, event: dict):
        async with self.connect() as r:
            await r.publish(f"scan:{self.scan_id}", json.dumps(event))
```

### P0.2 -- Add Missing Env Vars to Settings Class

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Dependencies** | None |
| **File** | `backend/app/config.py`, `backend/collectors/identity/github_secrets.py`, `backend/collectors/search/telegram_monitor.py` |

**Problem:** `GITHUB_TOKEN`, `TG_API_ID`, `TG_API_HASH`, `TG_SESSION_STRING` are read via `os.environ` directly by their collectors rather than through `config.py`. They are listed in `.env.example` but not in `Settings`.

**Approach:**
1. Add `GITHUB_TOKEN`, `TG_API_ID`, `TG_API_HASH`, `TG_SESSION_STRING` fields to `Settings` class in `config.py`.
2. Update collectors to accept the key via dependency injection or `settings` import.
3. Update production validator if Telegram is considered critical.

### P0.3 -- Add Scan Deletion Endpoint

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Dependencies** | None |
| **File** | `backend/app/api/scans.py` |

**Problem:** No way to delete scans through the API. Must access the database directly.

**Approach:** Add `DELETE /api/scans/{scan_id}` endpoint in `scans.py`. Cascade delete will handle findings and entity links via FK relationships.

### P0.4 -- Add Tab Count Badges in Workspace

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Low |
| **Dependencies** | Findings API |
| **File** | `frontend/src/pages/ScanWorkspace.tsx` |

**Approach:** Pass per-vector finding counts to tab labels. The scan detail endpoint already returns all findings with `vector_type`. Compute counts client-side and render as badges.

### P0.5 -- Findings Table Pagination

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Dependencies** | None |
| **File** | `backend/app/api/findings.py`, `frontend/src/components/FindingsTable.tsx` |

**Problem:** `GET /api/findings/` loads all findings matching filters into memory. On a large scan (10k+ findings) this is slow and memory-heavy.

**Approach:** Add `skip`/`limit` to the findings endpoint (already present in the schema but verify implementation). Add server-side pagination with a total count header.

---

## Phase 1 -- API Key Configuration (Highest ROI)

Which keys to configure first and what they unlock.

### Priority Matrix

| Key | Unlocks | Impact | Effort | Priority |
|-----|---------|--------|--------|----------|
| `SHODAN_API_KEY` | shodan_host: detailed port/service/CVE per IP | High | Trivial | **P0** |
| `HUNTER_API_KEY` | hunter_domain: email discovery from domains | High | Trivial | **P0** |
| `SERPER_API_KEY` | serper_search + serper_dork_search: web search + dork execution | High | Trivial | **P0** |
| `GROQ_API_KEY` | AI dork generation via llama-3.3-70b | High | Trivial | **P0** |
| `GITHUB_TOKEN` | github_secrets: scan repos for leaked secrets | High | Trivial | **P0** |
| `CENSYS_API_SECRET` | censys_host: alternative IP intelligence (0 credits until Jul 20) | Medium (future) | Trivial | **P1** |
| `NVD_API_KEY` | nvd_cve: raises rate limit 5->50 req/30s | Medium | Trivial | **P1** |
| `HIBP_API_KEY` | hibp_breach: breach database lookup | Medium | Trivial | **P1** |
| `TG_API_ID/HASH` | telegram_monitor: search Telegram channels | Medium | Small | **P2** |

### Key Impact Summary

- **SHODAN_API_KEY**: Transforms infrastructure tab from "these IPs exist" to "here are open ports, running services, CVEs, and host metadata". This is the single biggest value-add per key.
- **HUNTER_API_KEY**: Enables the entire email discovery pipeline. Without it, the IDENTITY vector only returns breach checks (xposedornot) and platform checks (holehe) -- no emails to check against.
- **SERPER_API_KEY**: Powers both standard web search and Google dork execution. Without it, the SEARCH vector is limited to dnstwist and Ahmia.
- **GROQ_API_KEY**: Enables the AI Assistant page. Without it, AI dork generation falls back to `site:<last-word>` heuristics.

---

## Phase 2 -- New Collectors

### P2.1 -- WHOIS/ASN Lookup

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | High |
| **Vector** | INFRASTRUCTURE |
| **API key?** | No (whois library is free) |
| **Dependencies** | None |

**Rationale:** Currently the platform discovers subdomains and IPs but never answers "who owns this IP/domain?" WHOIS data (registrar, org name, creation date, abuse contact) and ASN data (network range, ISP) are fundamental OSINT data points.

**Approach:**
- Use `whois` Python library (or `ipwhois` for ASN) as a new collector `collectors/infrastructure/whois_lookup.py`.
- Target type: domain or IP.
- Entity types: `DOMAIN_METADATA` (already exists), optionally `ASN` (new entity type).
- Runs as part of INFRASTRUCTURE vector, post-DNS-resolution.

**Implementation sketch:**
```python
import whois
class WhoisCollector(BaseCollector):
    metadata = CollectorMetadata(name="whois_lookup", vector="INFRASTRUCTURE", ...)
    async def collect(self, target: str) -> List[Dict]:
        w = whois.whois(target)
        return [{"domain": target, "registrar": w.registrar, "org": w.org, ...}]
```

### P2.2 -- Extended DNS Records (MX, TXT, NS, SOA)

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Vector** | INFRASTRUCTURE |
| **API key?** | No |
| **Dependencies** | None |

**Rationale:** Current `dns_resolver` only resolves A/AAAA records. MX records reveal email providers (Google Workspace, Office 365, custom mail servers). TXT records reveal SPF, DKIM, DMARC security posture. NS records reveal DNS hosting provider.

**Approach:** Extend `dns_resolver.py` or create `collectors/infrastructure/dns_record_enumerator.py` that queries MX, TXT, NS, SOA, CAA records. Add new entity types or extend `DNS_RECORD`.

### P2.3 -- SSL/TLS Certificate Analysis

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Vector** | INFRASTRUCTURE |
| **API key?** | No |
| **Dependencies** | None |

**Rationale:** crt.sh shows certificates issued for a domain, but doesn't analyze the certificates on the current live servers. Full TLS handshake reveals certificate chain, issuer, validity dates, SANs, cipher suites, and expiration warnings.

**Approach:**
- Use `ssl` + `socket` stdlib or `cryptography` to connect to discovered subdomains on port 443.
- Extract certificate fields (subject, issuer, notBefore, notAfter, SANs, fingerprint).
- Entity type: `TLS_CERT` (already exists in enums).
- Severity: INFO normally, MEDIUM if certificate expires within 30 days, HIGH if expired.

### P2.4 -- EmailRep.io Integration

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Vector** | IDENTITY |
| **API key?** | No (free tier available; key optional) |
| **Dependencies** | Email findings from hunter_domain |

**Rationale:** EmailRep.io provides reputation scoring for email addresses -- suspicious activity, breach associations, known malicious patterns. This adds a trust/risk dimension to discovered emails beyond breach count.

**Approach:**
- New collector `collectors/identity/emailrep.py`.
- Calls `https://emailrep.io/{email}` (no key for limited usage, API key for higher limits).
- Entity type: `EMAIL_PLATFORM` or new `EMAIL_REPUTATION`.
- Severity based on `suspicious` and `details.malicious_activity` flags.

### P2.5 -- Phone Number Intelligence

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | Medium |
| **Vector** | IDENTITY |
| **API key?** | Yes (Numverify, Twilio Lookup, or AbstractAPI) |
| **Dependencies** | None |

**Rationale:** Phone numbers are a common PII finding that the platform currently has no collector for. While not automatically discovered from domains, phone numbers can be entered as targets or discovered via other means.

**Approach:**
- New collector `collectors/identity/phone_lookup.py`.
- Use AbstractAPI Phone Validation or Twilio Lookup (both have free tiers).
- Return carrier, location, line type, validity.
- Add new entity type `PHONE_NUMBER` to `enums.py`.

### P2.6 -- VirusTotal URL/IP Lookup

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | High |
| **Vector** | SEARCH |
| **API key?** | Yes (VirusTotal API key, free tier: 500 req/day) |
| **Dependencies** | IP findings from INFRASTRUCTURE, domain findings |

**Rationale:** VirusTotal aggregates 70+ security scanners. Checking discovered domains/IPs against VT reveals malware associations, phishing detections, and security vendor flags -- critical for threat intelligence.

**Approach:**
- New collector `collectors/search/virustotal.py`.
- Two endpoints: `/api/v3/domains/{domain}` and `/api/v3/ip_addresses/{ip}`.
- Entity types: `DOMAIN_METADATA`, `HOST_METADATA`.
- Generate links to VT web UI.
- Severity based on `last_analysis_stats.malicious` count.

### P2.7 -- URLScan.io Integration

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Vector** | SEARCH |
| **API key?** | No (free API, rate-limited) |
| **Dependencies** | Domain findings |

**Rationale:** URLScan.io provides screenshots, DOM snapshots, HTTP request/response details, and technology fingerprinting for websites. Complements VirusTotal with a different data set.

**Approach:**
- New collector `collectors/search/urlscan.py`.
- Calls `https://urlscan.io/api/v1/search/?q=domain:{domain}`.
- Entity type: `URL` (already exists) or `DOMAIN_METADATA`.
- Technology detection results feed into `TECHNOLOGY` findings.

### P2.8 -- Social Media / Brand Monitoring (Reddit)

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | Medium |
| **Vector** | SEARCH |
| **API key?** | No (Reddit JSON endpoints, no key for read-only) |
| **Dependencies** | None |

**Rationale:** Reddit is a major source of brand mentions, leaked data discussions, and threat actor chatter. Searching Reddit for domain names, email addresses, or brand terms augments Telegram monitoring and dnstwist.

**Approach:**
- New collector `collectors/search/reddit_monitor.py`.
- Uses Pushshift API or Reddit's native JSON (`old.reddit.com/search.json?q=...`).
- Entity type: `DARKWEB_MENTION` or new `SOCIAL_MEDIA_MENTION`.
- Rate-limit friendly (1 req/sec, cache results).

### P2.9 -- Dehashed / IntelX Integration (Paid Dark Web)

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | High |
| **Vector** | IDENTITY |
| **API key?** | Yes (paid subscription) |
| **Dependencies** | API key purchase |

**Rationale:** Dehashed and IntelX are paid breach-aggregation services that cover data not indexed by HIBP or XposedOrNot. They return passwords, hashes, and credentials from both public and dark web breaches.

**Approach:**
- New collector `collectors/identity/dehashed.py`.
- API auth via email + API key, HTTP Basic.
- Entity types: `CREDENTIAL` (already exists), `BREACH`.
- Severity: CRITICAL for password-in-plaintext findings.
- Configuration: `DEHASHED_API_KEY` in `.env`.

### Collector Comparison Grid

| Collector | Vector | Free? | Key Needed | Entity Types | Priority |
|-----------|--------|-------|------------|--------------|----------|
| WHOIS/ASN | INFRASTRUCTURE | Yes | No | DOMAIN_METADATA, ASN (new) | **P0** |
| Extended DNS | INFRASTRUCTURE | Yes | No | DNS_RECORD | **P1** |
| SSL/TLS | INFRASTRUCTURE | Yes | No | TLS_CERT | **P1** |
| EmailRep | IDENTITY | Partial | Optional | EMAIL_PLATFORM | **P1** |
| Phone Lookup | IDENTITY | No | Yes | PHONE_NUMBER (new) | **P2** |
| VirusTotal | SEARCH | Partial | Yes | DOMAIN_METADATA, HOST_METADATA | **P1** |
| URLScan | SEARCH | Yes | No | URL, TECHNOLOGY | **P2** |
| Reddit Monitor | SEARCH | Yes | No | DARKWEB_MENTION | **P1** |
| Dehashed/IntelX | IDENTITY | No | Yes (paid) | CREDENTIAL, BREACH | **P2** |

---

## Phase 3 -- New Features

### P3.1 -- Reports & Export (Enhanced)

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | High |
| **Dependencies** | None |
| **Current state** | CSV/JSON/PDF export exists in `export_service.py` but is basic |

**Current limitations:**
- PDF export is a flat table with truncated values
- No executive summary, no charts, no severity breakdown
- No scheduled report generation
- No per-vector sectioning

**Approach:**
1. Add `GET /api/scans/{id}/report?format=pdf` endpoint using ReportLab for a structured report with:
   - Executive summary (total findings, severity distribution, top risks)
   - Per-vector sections (Infrastructure, Services, Identity, Search, Username)
   - Entity graph summary (key relationships)
   - Timeline of scan events
2. Add `GET /api/scans/{id}/report?format=html` for browser-based report viewing.
3. Add "Export Report" button to ScanWorkspace and ScanDetails pages.
4. Frontend: modal with format selector (PDF/HTML/JSON/CSV) and optional sections checklist.

### P3.2 -- Scan Scheduling (Celery Beat)

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | High |
| **Dependencies** | Database schemas for schedules |
| **Current state** | All scans are manual-once |

**Approach:**
1. Add `schedules` table: `id`, `target_domain`, `selected_vectors`, `cron_expression`, `is_active`, `last_run_at`, `next_run_at`, `created_at`.
2. Add API endpoints: `POST /api/schedules`, `GET /api/schedules`, `DELETE /api/schedules/{id}`, `PATCH /api/schedules/{id}`.
3. Integrate Celery Beat: add `celery-beat` service to `docker-compose.yml`.
4. Frontend: add "Schedule Scan" option in NewScan page, list/view schedules in ScanHistory or a new Schedules page.
5. On each beat tick: create a new Scan + dispatch unified_scan task.
6. Notification on completion (see P3.3).

### P3.3 -- Alerts & Notifications

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | High |
| **Dependencies** | Scan scheduling (P3.2) |
| **Current state** | No notification system |

**Approach:**
1. Add webhook system:
   - `webhooks` table: `id`, `url`, `events` (JSON of event types like `scan.completed`, `finding.critical`), `is_active`, `created_at`.
   - API: `POST /api/webhooks`, `GET /api/webhooks`, `DELETE /api/webhooks/{id}`.
   - When a scan completes (or a critical-severity finding is created), POST a JSON payload to each matching webhook URL.
   - Built-in templates: Slack, Discord, Email (SMTP config).
2. Add `alerts` table for in-app notification history:
   - `id`, `scan_id`, `type`, `title`, `message`, `is_read`, `created_at`.
   - Frontend: bell icon in topbar showing unread count, dropdown with alert list.
3. Frontend: notification toast when WebSocket receives `scan_completed` event.

### P3.4 -- Entity Correlation Views (Enhanced Graph)

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | Medium |
| **Dependencies** | Correlation engine (exists) |
| **Current state** | EntityGraph.tsx renders cytoscape from /api/links/ + /api/findings/ |

**Current limitations:**
- Graph shows all entities without filtering
- No node expansion on click (drill into finding details)
- No layout controls (force-directed only)
- No legend explaining node colors/shapes

**Approach:**
1. Add filter controls to EntityGraph: vector type, entity type, severity minimum.
2. Add node click handler: show finding detail in a side panel or modal.
3. Add layout selector: force-directed, concentric (by severity), hierarchical (by link type).
4. Add visual legend: color by vector, shape by entity type, size by severity.
5. Add "expand node" (lazy-load connected entities not yet in view).
6. Add graph export as PNG/SVG.

### P3.5 -- Timeline View

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | Medium |
| **Dependencies** | Findings have `created_at` (already exists) |
| **Current state** | No chronological visualization |

**Approach:**
1. Add timeline API: `GET /api/scans/{id}/timeline` returning findings grouped by time buckets (hour, day, week).
2. Frontend: new "Timeline" tab in ScanWorkspace (6th tab) or a standalone page.
3. Visualization options:
   - Gantt-like chart showing when each entity type was discovered during the scan.
   - Event strip showing key milestones (scan started, phase completed, enrichment triggered).
   - Highlight density of findings over time.
4. Use `date-fns` for formatting (already in dependencies), `recharts` for chart rendering (already in dependencies).

### P3.6 -- Scan Comparison / Diff

| Field | Value |
|-------|-------|
| **Effort** | Large |
| **Impact** | High |
| **Dependencies** | Scheduled scans (P3.2) |
| **Current state** | Each scan is standalone |

**Approach:**
1. API: `GET /api/scans/compare?ids=id1,id2` returning:
   - New findings (in scan B but not A)
   - Resolved findings (in A but not B)
   - Changed severity findings (same entity, different severity)
   - Summary: +X findings, -Y findings, Z changed
2. Frontend: new "Compare" page with side-by-side or unified diff view.
3. Entities matched by `entity_type + entity_value + source_module`.
4. Useful for: "what changed since last week's scan?"

### P3.7 -- Finding Severity Override & False-Positive Marking

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Dependencies** | None |
| **Current state** | Severity is read-only, no FP mechanism |

**Approach:**
1. Add `overridden_severity` and `is_false_positive` columns to `Finding` model.
2. API: `PATCH /api/findings/{id}` to update these fields.
3. Frontend: inline severity dropdown (override) and "Mark as FP" button in findings table rows.
4. Filter toggles: "Show FPs", "Hide FPs", "All".
5. Filter: "Show only overridden severity".

---

## Phase 4 -- UI/UX Improvements

### P4.1 -- Mobile Responsiveness

| Field | Value |
|-------|-------|
| **Effort** | Large |
| **Impact** | High |
| **Dependencies** | None |
| **Current state** | Desktop-only layout with fixed sidebar |

**Current limitations:**
- Sidebar is 220px fixed, not collapsible.
- ScanWorkspace 5-tab layout is horizontal, wraps poorly on small screens.
- Table views (`FindingsTable`) have no horizontal scroll on mobile.
- No responsive breakpoints in `index.css`.

**Approach:**
1. Collapsible sidebar: hamburger menu on screens < 768px, sidebar becomes a slide-over drawer.
2. Responsive grid: convert fixed widths to `minmax()` and percentage-based.
3. Tab layout: horizontal tabs collapse to a select dropdown on mobile.
4. Tables: add `overflow-x: auto` wrapper, reduce font size on small screens.
5. Touch targets: increase button/input min-height to 44px for touch.
6. Test on: 375px (mobile), 768px (tablet), 1024px (small desktop), 1440px+ (large desktop).

### P4.2 -- Performance Optimization for Large Scans

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | High |
| **Dependencies** | Pagination (P0.5) |
| **Current state** | All findings loaded at once |

**Current limitations:**
- `GET /api/scans/{id}` loads all findings (could be 10k+) in a single response.
- `ScanDetailResponse` includes full `findings` list -- no pagination.
- Frontend renders all rows simultaneously.
- WebSocket events flood during tool execution.

**Approach:**
1. Lazy-load findings per tab: instead of loading all findings with scan detail, fetch per-vector from `GET /api/findings/?scan_id=X&vector_type=INFRASTRUCTURE&limit=50`.
2. Server-side pagination with cursor or offset.
3. Frontend: virtual scrolling for findings table (use `react-window` or `@tanstack/react-virtual`).
4. Batch WebSocket progress events on frontend: debounce rapid events, update UI in ~500ms batches.
5. Lazy-load entity graph: only fetch nodes + edges within viewport, expand on zoom.
6. Add Redis-based caching for frequently-queried scan detail endpoints.

### P4.3 -- Filtering & Sorting Improvements

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Dependencies** | None |
| **Current state** | Basic filter by vector_type, entity_type, severity |

**Current limitations:**
- Filters are in `app/api/filters.py` but limited to exact-match on vector/entity/severity.
- No full-text search on entity_value or raw_data content.
- Frontend FindingTable has no multi-column sort.
- No date range filter.

**Approach:**
1. Backend: add `/api/findings/` query param for `q` (full-text search on `entity_value`), `date_from`/`date_to`, `sort_by`/`sort_order`.
2. Frontend: multi-column sort (click column header to sort, shift-click for secondary sort).
3. Add "Clear all filters" button.
4. Add saved filter presets per user (requires auth -- P5.3).

### P4.4 -- Scan Comparison UI

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | Medium |
| **Dependencies** | Scan Diff API (P3.6) |
| **Current state** | No comparison feature |

**Approach:**
1. Add "Compare with... " button to ScanWorkspace top bar.
2. Opens a modal to select a second scan (from history, filtered by same target_domain).
3. Shows split-view: left = scan A, right = scan B, with diff highlights:
   - Green rows = new findings (only in B)
   - Red rows = missing findings (only in A)
   - Yellow rows = changed severity
4. Summary stats bar: +120 new / -15 gone / 3 severity changes.

---

## Phase 5 -- Infrastructure

### P5.1 -- Frontend Docker Service

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | High |
| **Dependencies** | None |
| **Current state** | Frontend runs via `npm run dev` on host, no container |

**Approach:**
1. Create `frontend/Dockerfile`:
   ```dockerfile
   FROM node:20-alpine AS builder
   WORKDIR /app
   COPY package*.json ./
   RUN npm ci
   COPY . .
   RUN npm run build

   FROM nginx:alpine
   COPY --from=builder /app/dist /usr/share/nginx/html
   COPY nginx.conf /etc/nginx/conf.d/default.conf
   EXPOSE 80
   ```
2. Create `frontend/nginx.conf` with:
   - Serve static files from `/usr/share/nginx/html`
   - Proxy `/api/` and `/ws/` to backend at `http://backend:8000`
   - Add `X-API-Key` automatically from env var or cookie
   - Cache control headers for static assets
3. Update `docker-compose.yml`:
   ```yaml
   frontend:
     build: ./frontend
     ports:
       - "80:80"
     environment:
       VITE_API_URL: /api
       VITE_WS_URL: ""
     depends_on:
       - backend
   ```

### P5.2 -- Reverse Proxy / SSL (Production Gateway)

| Field | Value |
|-------|-------|
| **Effort** | Medium |
| **Impact** | High |
| **Dependencies** | Frontend container (P5.1), domain name |
| **Current state** | Backend and frontend are directly exposed |

**Approach:**
1. Add Caddy (preferred for automatic HTTPS) or Nginx as a reverse proxy.
2. If using Caddy, add a `caddy` service to `docker-compose.yml`:
   ```yaml
   caddy:
     image: caddy:alpine
     ports:
       - "80:80"
       - "443:443"
     volumes:
       - ./Caddyfile:/etc/caddy/Caddyfile
       - caddy_data:/data
     depends_on:
       - frontend
       - backend
   ```
3. `Caddyfile`:
   ```
   osint.example.com {
       reverse_proxy frontend:80
       encode gzip
       log {
           output file /data/logs/access.log
       }
   }
   ```
4. If using Nginx: `nginx.conf` with SSL termination, rate limiting, WAF rules.
5. Rate limiting: 10 req/sec per IP on API routes, 100 req/sec on static assets.
6. Request size limit: 1MB body (prevents abuse of POST endpoints).

### P5.3 -- User Authentication (Beyond Shared API Key)

| Field | Value |
|-------|-------|
| **Effort** | Large |
| **Impact** | High |
| **Dependencies** | None |
| **Current state** | Single shared API key (dev default or env var) |

**Current limitations:**
- Every user/consumer uses the same `X-API-Key`.
- No user isolation: all scans are visible to all key holders.
- No audit trail per user.
- No session expiry or token rotation.

**Approach:**
1. Add `users` table: `id` (UUID), `email`, `hashed_password`, `display_name`, `is_active`, `is_admin`, `created_at`.
2. Add `api_tokens` table: `id`, `user_id` (FK), `token` (hashed), `name`, `last_used_at`, `expires_at`, `is_active`.
3. Authentication flow:
   - `POST /api/auth/login` -- email + password --> JWT access token + refresh token.
   - `POST /api/auth/register` -- create user (admin-only or open registration based on config).
   - `GET /api/auth/me` -- current user info.
   - `POST /api/auth/tokens` -- create API token (for programmatic access).
   - `DELETE /api/auth/tokens/{id}` -- revoke token.
4. Update `get_api_key()` dependency to accept:
   - `Authorization: Bearer <jwt>` for interactive users.
   - `X-API-Key: <token>` for programmatic access (API tokens).
   - Keep legacy single-key support for dev mode (`APP_ENV=development`).
5. Optionally: add role-based access (viewer, analyst, admin).
6. Frontend:
   - Login page (route: `/login`).
   - Auth context provider storing JWT in localStorage (with httpOnly cookie as future upgrade).
   - Auto-refresh token on 401 response.
   - Protected route wrapper redirecting to `/login`.

### P5.4 -- Backup & Restore

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | High |
| **Dependencies** | None |
| **Current state** | No automated backup |

**Approach:**
1. Add `db-backup` service to `docker-compose.yml`:
   ```yaml
   db-backup:
     image: postgres:16-alpine
     entrypoint: |
       sh -c '
       while true; do
         PGPASSWORD=$POSTGRES_PASSWORD pg_dump -h db -U $POSTGRES_USER $POSTGRES_DB \
           | gzip > /backups/osint_$(date +%Y%m%d_%H%M%S).sql.gz
         find /backups -name "*.sql.gz" -mtime +30 -delete
         sleep 86400
       done
       '
     volumes:
       - ./backups:/backups
     environment:
       POSTGRES_USER: postgres
       POSTGRES_PASSWORD: postgres
       POSTGRES_DB: osint_platform
     depends_on:
       - db
   ```
2. Document restore procedure:
   ```bash
   gunzip -c backups/osint_20260701_120000.sql.gz | docker exec -i osint_db psql -U postgres osint_platform
   ```
3. Add optional S3/GCS backup target using `awscli` or `rclone`.
4. Backup also: `.env` file (encrypted), frontend build artifacts (optional).

### P5.5 -- Celery Beat Service (for Scheduling)

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | High |
| **Dependencies** | Scan scheduling feature (P3.2) |
| **Current state** | Celery worker exists, no beat scheduler |

**Approach:**
1. Add `beat` service to `docker-compose.yml`:
   ```yaml
   beat:
     build: ./backend
     container_name: osint_beat
     env_file: ./backend/.env
     depends_on:
       - db
       - redis
     command: ["celery", "-A", "app.workers.celery_app:celery_app", "beat", "--loglevel=INFO", "--pidfile=/tmp/celerybeat.pid"]
   ```
2. Schedule store: Celery Beat supports database-backed schedule entries via Django model, or a simple custom scheduler using Redis.
3. For a FastAPI app without Django, use Redis as the schedule backend via `celery-redbeat` or implement a lightweight custom scheduler that reads from the `schedules` table.
4. Recommended: Use `celery-redbeat` (Redis-based persistent schedule store).

### P5.6 -- Logging & Monitoring

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Dependencies** | None |
| **Current state** | `print()` statements in collectors, no structured logging |

**Current limitations:**
- Collectors use `print()` for status messages -- not logged, no levels, no timestamps.
- API FastAPI logs go to stdout but at default level.
- Worker logs are mixed with Celery's own output.
- No centralized log aggregation.

**Approach:**
1. Replace `print()` in all collectors with `logging.getLogger(__name__)` calls:
   - `logger.info()` for normal collector lifecycle.
   - `logger.warning()` for non-fatal issues (rate limits, partial results).
   - `logger.error()` for failures.
2. Configure structured JSON logging in `app/main.py`:
   ```python
   import structlog
   structlog.configure(processors=[...])
   ```
   Alternatively, use standard `logging` with JSON formatter for simpler setup.
3. Add request-id middleware to trace requests across API + Celery task.
4. Add health check endpoint improvements: report per-collector status (available/misconfigured/errored).
5. Optional: add Loki + Grafana for log aggregation (infrastructure expansion).

### P5.7 -- API Rate Limiting

| Field | Value |
|-------|-------|
| **Effort** | Small |
| **Impact** | Medium |
| **Dependencies** | Auth system (P5.3) or IP-based |
| **Current state** | No rate limiting on API endpoints |

**Approach:**
1. Add `slowapi` or custom middleware for rate limiting:
   ```python
   from slowapi import Limiter, _rate_limit_exceeded_handler
   from slowapi.util import get_remote_address
   limiter = Limiter(key_func=get_remote_address)
   app.state.limiter = limiter
   app.add_exception_handler(429, _rate_limit_exceeded_handler)
   ```
2. Rate limits:
   - `/api/scans/` POST: 10/hour per IP (prevent abuse).
   - `/api/findings/` GET: 60/minute per IP.
   - `/api/dashboard/` GET: 30/minute per IP.
   - WebSocket connections: 5 concurrent per IP.
3. For authenticated users: higher limits tied to user tier.

---

## Dependency Graph Between Phases

```
Phase 0b (Quick Fixes) ─── no deps ───► can start immediately
       │
       ▼
Phase 1 (API Keys) ─────── no deps ───► can start immediately
       │
       ▼
Phase 2 (New Collectors) ── no deps ───► can start immediately
                                        (each collector is independent)
       │
       ▼
Phase 3.1 (Reports) ─────── no deps ───► can start immediately
Phase 3.2 (Scheduling) ──── no deps ───► can start immediately
Phase 3.3 (Alerts) ───────── blocked by 3.2 (scheduling)
Phase 3.4 (Entity Views) ─── no deps ───► can start immediately
Phase 3.5 (Timeline) ─────── no deps ───► can start immediately
Phase 3.6 (Diff) ─────────── blocked by 3.2 (scheduling, for meaningful use)
Phase 3.7 (Override/FP) ──── no deps ───► can start immediately
       │
       ▼
Phase 4 (UI/UX) ──────────── no deps ───► can start in parallel
                                        (responsive and perf are independent)
       │
       ▼
Phase 5.1 (Frontend Docker) ─── no deps
Phase 5.2 (Reverse Proxy) ───── blocked by 5.1
Phase 5.3 (Auth) ────────────── no deps
Phase 5.4 (Backup) ──────────── no deps
Phase 5.5 (Celery Beat) ─────── blocked by 3.2
Phase 5.6 (Logging) ─────────── no deps
Phase 5.7 (Rate Limit) ──────── no deps
```

---

## Effort Summary by Phase

| Phase | Items | Small | Medium | Large | Total Est. |
|-------|-------|-------|--------|-------|------------|
| Phase 0b -- Quick Fixes | 5 | 5 | 0 | 0 | 3-5 days |
| Phase 1 -- API Keys | -- | -- | -- | -- | Hours (configuration only) |
| Phase 2 -- New Collectors | 9 | 6 | 3 | 0 | 3-4 weeks |
| Phase 3 -- New Features | 7 | 1 | 5 | 1 | 5-7 weeks |
| Phase 4 -- UI/UX | 4 | 1 | 2 | 1 | 4-6 weeks |
| Phase 5 -- Infrastructure | 7 | 4 | 2 | 1 | 4-5 weeks |

**Total estimated effort (all phases):** ~16-22 weeks for a single developer.

---

## Recommended Sprint Prioritization

### Sprint 1 (Week 1, Highest ROI)
- P0.1 -- Fix progress publisher event loop bug (1 day)
- P0.2 -- Add missing env vars to Settings (0.5 day)
- P0.3 -- Scan deletion endpoint (0.5 day)
- P0.4 -- Tab count badges (1 day)
- Phase 1 -- Configure all available API keys (hours)
- P2.1 -- WHOIS/ASN collector (2 days)

### Sprint 2 (Week 2)
- P2.4 -- EmailRep.io collector (1 day)
- P2.6 -- VirusTotal collector (2 days)
- P2.8 -- Reddit monitor collector (2 days)
- P3.1 -- Enhanced report/export (2 days)

### Sprint 3 (Week 3)
- P2.2 -- Extended DNS records (1 day)
- P2.3 -- SSL/TLS analysis (1 day)
- P3.2 -- Scan scheduling (3 days)
- P0.5 -- Findings pagination (1 day)

### Sprint 4 (Week 4)
- P3.3 -- Alerts/notifications (3 days)
- P3.4 -- Enhanced entity graph (2 days)
- P3.5 -- Timeline view (2 days)

### Sprint 5 (Week 5)
- P3.7 -- Severity override / FP marking (1 day)
- P4.2 -- Large scan performance (3 days)
- P4.3 -- Filtering/sorting improvements (1 day)

### Sprint 6 (Week 6)
- P4.1 -- Mobile responsiveness (3-5 days, ongoing)
- P5.1 -- Frontend Docker service (2 days)
- P5.4 -- Backup/restore (0.5 day)
- P5.6 -- Logging improvements (1 day)

### Sprint 7 (Week 7)
- P5.2 -- Reverse proxy/SSL (2 days)
- P5.5 -- Celery Beat (1 day)
- P5.7 -- Rate limiting (1 day)

### Sprint 8+ (Weeks 8-10)
- P2.5 -- Phone lookup (2 days)
- P2.7 -- URLScan collector (1 day)
- P2.9 -- Dehashed/IntelX (2 days)
- P3.6 -- Scan comparison/diff (3-5 days)
- P4.4 -- Comparison UI (2 days)
- P5.3 -- Auth system (5-7 days)

---

## Detailed File Map for New Collector Implementation

For each new collector, follow this checklist:

1. **Create collector class:** `backend/collectors/<vector>/<name>.py`
   - Extend `BaseCollector`, define `CollectorMetadata`
   - Implement `async collect(target)` and `normalize(raw)`
2. **Register new entity types (if needed):** `backend/app/schemas/enums.py` -- add to `EntityType` enum
3. **Register new API key (if needed):** `backend/app/config.py` -- add field to `Settings` class
4. **Create Celery task (if standalone endpoint needed):** `backend/app/workers/<name>_task.py`
   - Import in `backend/app/workers/celery_app.py`
5. **Create API endpoint (if standalone endpoint needed):** `backend/app/api/scans.py`
   - Add request schema to `backend/app/schemas/base.py`
6. **Wire into unified scan pipeline (optional):** `backend/app/workers/unified_scan.py`
7. **Add frontend tab/display (if needed):** `frontend/src/components/workspace/` -- add section to relevant tab
8. **Add WebSocket event constants (optional):** `backend/app/services/progress.py`
