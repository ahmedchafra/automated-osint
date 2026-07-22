---
name: collectors-theharvester-h8mail-final
description: Working sources, findings counts, pipeline integration, API key config for theHarvester and h8mail
metadata:
  type: reference
---

## theHarvester v4.11.1 — Final State

**Free sources (12, always included, no key needed):**
thc, rapiddns, certspotter, robtex, crtsh, duckduckgo, yahoo, baidu, threatcrowd, threatminer, subdomaincenter, subdomainfinderc99

**Excluded free sources that TIMEOUT:** waybackarchive, commoncrawl, otx (otx is API-key now)

**API-key sources (auto-detected when key present in ~/.theHarvester/api-keys.yaml):**
shodan, censys, hackertarget, bufferoverun, virustotal, urlscan, otx, leakix, netlas, securitytrails, fullhunt, bevigil, tomba, brave, dymo, criminalip, hunterhow, mojeek, windvane, venacus, zoomeye, builtwith, intelx, onyphe, fofa, sherlockeye, pentesttools, projectdiscovery, rocketreach, securityscorecard, whoisxml, dehashed, haveibeenpwned, leaklookup

**Explicitly excluded API sources:**
- hunter — dedicated hunter_domain collector exists, would double-burn 50-free/month
- github-code — v4.11.1 throws key-format parsing bug even with valid GITHUB_TOKEN

**Pipeline integration:** Runs in INFRASTRUCTURE phase of unified_scan.py, despite being classified as `vector="IDENTITY"` in its metadata. `_run_tool("theharvester", scan.target_domain, ...)` with `scan_id` and `publisher` for progress events.

**Timeout:** 180s (enforced via asyncio.wait_for inside collect() — the subprocess itself)

**Dynamic key detection:** `sources()` property reads `~/.theHarvester/api-keys.yaml` at runtime via `_read_configured_api_keys()`, returns set of configured key names. API_SOURCE_KEYS dict maps source name → YAML key name.

**Webhook subprocess:** theHarvester runs as `asyncio.create_subprocess_exec(theHarvester, -d domain, -b sources, -l 500, ...)` and output is parsed with regex from stdout text.

## h8mail v2.5.6 — Final State

**Free sources (no key):** scylla.so, hunter.io public, emailrep.io free tier

**API-key sources (conditional on env var):** hunterio, hibp, emailrep, snusbase, leaklookup, dehashed, intelx

**Pipeline integration:** Runs in IDENTITY phase of unified_scan.py, once per email discovered. Output: BREACH, CREDENTIAL, PROFILE entity types. In the legacy vector orchestrator (vectors/identity.py) h8mail also runs. In the unified pipeline, only Hunter/XposedOrNot/h8mail run (no holehe, no maigret in the auto-pipeline).

**Timeout:** 120s

## API Key Configuration Files

All keys go in `backend/.env` (local dev) or Docker env vars. The `docker-entrypoint.sh` helper function `_write_key` writes non-empty env vars to `~/.theHarvester/api-keys.yaml`. h8mail keys are passed via `-k` flag at runtime — the collector reads `settings.*_API_KEY` directly and appends to the flag when non-empty.

## .env Structure

- Lines 1-23: Original platform config (SHODAN, CENSYS, HUNTER, HIBP, GROQ, SERPER, NVD, DB, Redis, GITHUB_TOKEN)
- Lines 25-64: theHarvester API keys — 21 free-tier + 12 paid, all empty for user to fill
- Lines 66-73: h8mail-specific keys (SNUSBASE, EMAILREP)

## Known Discrepancies

- theHarvester is classified as `vector="IDENTITY"` but runs in the INFRASTRUCTURE phase of the unified pipeline (unified_scan.py) alongside crtsh/subfinder/dns. This is because it returns subdomains and IPs that feed DNS resolution.
- The unified pipeline does NOT run Holehe, maigret, or Telegram monitoring automatically — those are only available via the legacy orchestrator or on-demand tasks.
- Two parallel pipeline flows exist: unified_scan.py (used by "simple" scans) and vectors/*.py (used by legacy "full" scans). They overlap significantly but are not identical.
