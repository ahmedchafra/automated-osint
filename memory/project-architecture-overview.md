---
name: project-architecture-overview
description: Complete architecture, pipeline flow, collector inventory, and known gaps for the OSINT platform
metadata:
  type: project
---

# Automated OSINT Platform — Architecture Overview

## Stack
- **Backend**: Python 3.11+, FastAPI, Celery, SQLAlchemy async, Redis, PostgreSQL
- **Frontend**: React 18, TypeScript, Vite, TanStack React Query, Framer Motion
- **Infrastructure**: Docker, Celery worker with Redis broker

## Two Parallel Pipeline Flows

The project has **two distinct scan execution paths** that should eventually converge:

1. **Unified Pipeline** (`backend/app/workers/unified_scan.py`) — called by `POST /scans/simple`: 4 phases (INFRASTRUCTURE→SERVICES→IDENTITY→SEARCH). Includes theHarvester. No Holehe/Telegram/USERNAME.
2. **Legacy Orchestrator** (`backend/app/services/vectors/*.py`) — called by `POST /scans/`: per-vector strategy modules. More comprehensive (includes Telegram, Holehe, maigret, USERNAME). No theHarvester.

**Frontend uses**: `POST /scans/initial` → `initial_scan.py` (Phase 1 only: crtsh→subfinder→DNS→Shodan InternetDB). On-demand tasks available post-scan.

## Collector Inventory (22 total)

See [[collectors-theharvester-h8mail-final]] for theHarvester/h8mail details.

### INFRASTRUCTURE (Phase 1)
- `crtsh` — Certificate Transparency log subdomain enumeration (free, no key)
- `subfinder` — Passive subdomain enumeration via 40+ sources (binary on PATH)
- `dns_resolver` — DNS A/AAAA/MX/TXT/CNAME resolution via dnspython
- `shodan_internetdb` — Shodan InternetDB for IP enrichment (free, no key)
- `theharvester` — Email/subdomain/IP harvest from search engines (vector=IDENTITY but runs here)

### SERVICES (Phase 2)
- `shodan_host` — Shodan Host API (SHODAN_API_KEY)
- `censys_host` — Censys Platform v3 host (CENSYS_API_SECRET)
- `nvd_cve` — NVD CVE matching from CPE strings (NVD_API_KEY optional)
- `cisa_kev` — CISA Known Exploited Vulnerabilities catalog (free)

### IDENTITY (Phase 3)
- `hunter_domain` — Hunter.io domain email discovery (HUNTER_API_KEY)
- `xposedornot_breach` — XposedOrNot breach & paste lookup (free, 2 req/s)
- `h8mail` — h8mail email OSINT breach/reputation (free + optional API keys)
- `holehe` — Email-to-platform registration checker (free, on-demand only)
- `hibp_breach` — HaveIBeenPwned breach lookup (HIBP_API_KEY, on-demand only)

### SEARCH (Phase 4)
- `dnstwist` — Lookalike domain detection via permutation + DNS
- `github_secrets` — GitHub public repo leaked secrets scanner (GITHUB_TOKEN opt)
- `serper_search` — Serper.dev Google SERP dorking (SERPER_API_KEY)
- `serper_dork_search` — Arbitrary dork query execution (SERPER_API_KEY, on-demand only)
- `telegram_monitor` — Telegram channel/group mention monitor (TG_API_ID/HASH/SESSION, on-demand)
- `ahmia` — Ahmia.fi .onion dark web search (free, on-demand)

### USERNAME (on-demand only)
- `maigret` — Username OSINT across 3000+ sites (free)
- `simple_profiler` — Lightweight username checks on 4 sites (free)

## Entity Types enum → Tab Mapping
Infrastructure tab: SUBDOMAIN, IP_ADDRESS, PORT_SERVICE, CVE, HOST_METADATA, DNS_RECORD, TLS_CERT
Identity tab: EMAIL, DOMAIN_METADATA, BREACH, EMAIL_PLATFORM, PROFILE
Secrets tab: LEAKED_SECRET, GITHUB_REPO, CREDENTIAL
Threat Intel tab: TELEGRAM_MESSAGE, TELEGRAM_CHANNEL, ONION_SITE, DARKWEB_MENTION
Brand Protection tab: LOOKALIKE_DOMAIN, PHISHING_SITE, CLOUD_BUCKET, EXPOSED_FILE, DORK_RESULT

## Known Gaps

### Entity types in enum, never produced: TECHNOLOGY, OPEN_PORT, URL
### Entity types expected by frontend, never produced: PHISHING_SITE, CLOUD_BUCKET, EXPOSED_FILE (Brand Protection tab shows COMING SOON)
### Collectors not in unified pipeline: holehe, hibp_breach, telegram_monitor, maigret, simple_profiler, ahmia (all on-demand only)
### Duplicated code: `_run_tool()`, `_persist_findings()` in both unified_scan.py and initial_scan.py
### Vector misclassification: theHarvester (IDENTITY flag, runs in INFRASTRUCTURE), github_secrets (IDENTITY flag, runs in SEARCH)

## AI Dork System
Groq Llama 3.3 70B generates Google Dorks from natural language. Preview via `POST /ai/generate-dork`, execute via `POST /scans/{id}/ai-dork` → `serper_dork_search` collector. Results stored as DORK_RESULT findings + AIQuery audit records.

## API Keys (38 total)
- 4 required for production: SHODAN_API_KEY, HUNTER_API_KEY, GROQ_API_KEY, SERPER_API_KEY
- 4 optional for specific collectors: CENSYS_API_SECRET, HIBP_API_KEY, NVD_API_KEY, GITHUB_TOKEN
- 3 optional for Telegram: TG_API_ID, TG_API_HASH, TG_SESSION_STRING
- ~25 theHarvester-specific optional keys
- 2 h8mail-specific optional keys: EMAILREP_API_KEY, SNUSBASE_API_KEY

## Correlation Engine
Creates EntityLinks after scan completion:
- SUBDOMAIN → IP_ADDRESS (RESOLVES_TO)
- IP_ADDRESS → PORT_SERVICE (HAS_PORT)
- IP_ADDRESS → CVE (HAS_VULNERABILITY)
- EMAIL → BREACH (BREACHED_IN)
