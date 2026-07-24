# OSINT Platform — Setup & Usage Guide

> **Version:** 1.0 | **Updated:** July 2026  
> **Stack:** FastAPI (Python), React (TypeScript), PostgreSQL, Redis, Celery, Docker

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Installation & Setup](#3-installation--setup)
   - [Clone or Copy the Project](#31-clone-or-copy-the-project)
   - [Configure API Keys](#32-configure-api-keys)
   - [Start the Application](#33-start-the-application)
   - [Verify It's Running](#34-verify-its-running)
   - [Stop the Application](#35-stop-the-application)
   - [Update the Application](#36-update-the-application)
4. [Architecture (How It Works)](#4-architecture-how-it-works)
5. [Using the Application](#5-using-the-application)
   - [Registration & Login](#51-registration--login)
   - [Creating a Scan](#52-creating-a-scan)
   - [The Scan Workspace](#53-the-scan-workspace)
   - [Tabs Explained](#54-tabs-explained)
     - [Dashboard Tab](#541-dashboard-tab)
     - [Infrastructure Tab](#542-infrastructure-tab)
     - [Identity Tab](#543-identity-tab)
     - [Secrets Tab](#544-secrets-tab)
     - [Brand Protection Tab](#545-brand-protection-tab)
     - [Threat Intel Tab](#546-threat-intel-tab)
     - [Web OSINT Tab](#547-web-osint-tab)
     - [Entity Graph Tab](#548-entity-graph-tab)
   - [Findings Table](#55-findings-table)
   - [Pivot Actions](#56-pivot-actions)
6. [API Keys — Which Ones You Need](#6-api-keys--which-ones-you-need)
7. [Troubleshooting](#7-troubleshooting)
8. [Sharing with Someone Else](#8-sharing-with-someone-else)

---

## 1. Overview

This is a **dockerized OSINT (Open Source Intelligence) platform** that automates reconnaissance against domains, IP addresses, and organizations. It runs 30+ collectors across multiple vectors — infrastructure, identity, secrets, brand protection, and threat intelligence — and presents results in a web dashboard.

**What it can do:**
- Scan a domain for subdomains, IPs, DNS records, and SSL certificates
- Discover email addresses associated with a domain
- Find leaked credentials, secrets, and exposed configuration files on GitHub
- Detect lookalike domains (typosquatting)
- Profile web technologies (server, frameworks, libraries) and cross-reference CVEs
- Monitor Telegram for brand mentions
- Generate Google dorks via AI
- Visualize the relationship graph between findings
- Export reports as PDF

---

## 2. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Docker** | 24+ | [Get Docker](https://docs.docker.com/get-docker/) |
| **Docker Compose** | v2 (included with Docker Desktop) | Comes with Docker Desktop |
| **Git** (optional) | Any | Needed to clone the repo |
| **RAM** | 4 GB minimum, 8 GB+ recommended | The system runs 4 containers |
| **Disk** | 10 GB free | Docker images + database storage |
| **OS** | Windows, macOS, or Linux | Docker Desktop on Windows/Mac; Docker Engine on Linux |
| **Node.js** | 18+ | [nodejs.org](https://nodejs.org/) — needed for the frontend dev server |

> **Windows users:** Install Docker Desktop (WSL2 backend recommended).  
> **Linux users:** Install Docker Engine + Docker Compose plugin.

---

## 3. Installation & Setup

### 3.1 Clone or Copy the Project

**Option A — Git (recommended):**

```bash
git clone <repository-url> osint-platform
cd osint-platform
```

**Option B — Zip file:**

Unzip the project archive, then open a terminal in the project root directory:

```bash
cd osint-platform
```

### 3.2 Configure API Keys

The application comes with API keys pre-configured for demo use. You should replace them with your own keys for production use.

1. **Copy the example env file:**

```bash
cp backend/.env.example backend/.env
```

2. **Edit `backend/.env`** and fill in the API keys you have. At minimum, set:

```env
API_KEY=your-secret-api-key-here        # Change this!
JWT_SECRET=your-random-jwt-secret       # Change this!
```

The most important collectors and their API keys:

| Collector | What it does | API Key Needed? | Free Tier? |
|---|---|---|---|
| Shodan | IP/port/service enumeration | `SHODAN_API_KEY` | Paid (cheap) |
| Censys | SSL certificate / IP intelligence | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Free tier |
| Hunter.io | Domain email discovery | `HUNTER_API_KEY` | 50 free req/month |
| GitHub | Secret scanning | `GITHUB_TOKEN` | Free |
| BuiltWith | Web technology profiler | `BUILTWITH_API_KEY` | 50 free queries ever |
| theHarvester (29+ sources) | Email/host/subdomain harvest | Any of the keys below | Most have free tiers |

The **theHarvester** collector is special — it reads **29+ separate API keys** from your `.env` and feeds them into its YAML config. Each key enables a different source (VirusTotal, URLScan, FullHunt, Shodan, Censys, etc.). You don't need all of them — theHarvester works with whatever keys you have and does more with more keys. Most have free tiers:

| theHarvester Source | Env Variable | Free Tier Limit |
|---|---|---|
| VirusTotal | `VT_API_KEY` | 500 lookups/day |
| URLScan | `URLSCAN_API_KEY` | Free rate-limited |
| FullHunt | `FULLHUNT_API_KEY` | 50 queries |
| Shodan | `SHODAN_API_KEY` | Paid |
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | 250 free credits |
| SecurityTrails | `SECURITYTRAILS_KEY` | 50 queries/month |
| AlienVault OTX | `OTX_API_KEY` | Free registration |
| DNSDumpster | `DNSDUMPSTER_API_KEY` | 50 queries/day |
| BeVigil | `BEVIGIL_API_KEY` | 50 queries/month |
| ... and 20 more | See `backend/.env.example` | See notes |

Collectors that work **without any API key**: holehe, maigret, xposedornot, crt.sh, DNS resolver, subdomain discovery, dnstwist (lookalike domains), Wayback Machine, http_headers, version_detector.

**theHarvester API keys:** If you set any of the 30+ theHarvester API keys in your `.env`, the "Auto" mode will use full theHarvester with all sources. Without them, it uses free sources only (still powerful).

> **Important:** The `.env` file contains secrets. Never commit it to Git! It's in `.gitignore` already.

3. **Configure the frontend** — edit `frontend/.env` if needed:

```env
VITE_API_URL=http://localhost:8000/api
VITE_API_KEY=osint-local-dev-key-12345    # Must match backend .env API_KEY
VITE_WS_URL=ws://localhost:8000
```

### 3.3 Start the Application

**Step 1 — Start the backend services (Docker):**

```bash
docker-compose up -d
```

This starts 4 containers:

| Container | Purpose | Port |
|---|---|---|
| `osint_db` | PostgreSQL database | 5432 |
| `osint_redis` | Redis (message broker + cache) | 6379 |
| `osint_api` | FastAPI backend | 8000 |
| `osint_worker` | Celery worker (runs collectors) | — |

**Step 2 — Start the frontend (Node.js outside Docker):**

In a **separate terminal**, run:

```bash
cd frontend
npm install   # only first time, or after pulling updates
npm run dev
```

The frontend runs via Vite's dev server (hot-reload) on http://localhost:5173. It is **not** inside Docker — you run it with Node.js directly.

> If you don't have Node.js installed, download it from [nodejs.org](https://nodejs.org/) (v18+). The frontend needs this to compile React/TypeScript.

**First-time build** (takes 3–10 minutes depending on internet):

```bash
docker-compose up -d --build
```

The `--build` flag rebuilds the Docker images from source. You only need it the first time or after code changes.

### 3.4 Verify It's Running

**Check Docker containers:**

```bash
docker-compose ps
```

All 4 containers should show `Up` status. If the frontend terminal shows any errors, make sure `frontend/.env` has the correct `VITE_API_URL`.

**View logs:**

```bash
docker-compose logs -f       # All containers
docker-compose logs -f api   # Just the backend API
docker-compose logs -f worker   # Just the worker
```

**Open the app:**

- **Frontend:** http://localhost:5173
- **API docs (Swagger):** http://localhost:8000/docs

When you open the frontend, you'll see a login/register page.

### 3.5 Stop the Application

Stop the frontend by pressing **Ctrl+C** in its terminal, then stop Docker:

```bash
docker-compose down         # Stop all containers
docker-compose down -v      # Stop + delete all data (database reset!)
```

### 3.6 Update the Application

```bash
# Pull latest code (if using Git)
git pull

# Rebuild images and restart
docker-compose up -d --build
```

---

## 4. Architecture (How It Works)

```
┌──────────────────────────────────────────────────┐
│           Frontend (React) — runs outside Docker   │
│              http://localhost:5173                  │
│         Start with: cd frontend && npm run dev      │
└─────────────────────┬────────────────────────────┘
                      │ HTTP / WebSocket
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Docker Containers                          │
│                                                             │
│  ┌─────────────────────┐     ┌─────────────────────────┐    │
│  │  FastAPI Backend    │◄───►│     Celery Worker        │    │
│  │  :8000              │ REDIS│  (runs collectors)       │    │
│  │  ┌───────────────┐  │QUEUE │  ┌───────────────────┐  │    │
│  │  │ REST API      │  │      │  │ Hunter.io         │  │    │
│  │  │ WebSocket     │──┤      │  │ Shodan / Censys   │  │    │
│  │  │ Auth (JWT)    │  │      │  │ theHarvester      │  │    │
│  │  └───────────────┘  │      │  │ GitHub Secrets    │  │    │
│  └──────────┬──────────┘      │  │ dnstwist          │  │    │
│             │                 │  │ BuiltWith         │  │    │
│             ▼                 │  │ Wayback Machine   │  │    │
│  ┌─────────────────────┐     │  │ + 25 more...      │  │    │
│  │    PostgreSQL        │     │  └───────────────────┘  │    │
│  │    (structured data) │     └─────────────────────────┘    │
│  └─────────────────────┘                                     │
└─────────────────────────────────────────────────────────────┘
```

**Flow for a scan:**

1. **User** creates a scan via the frontend (enters a domain, IP, or org name)
2. **Backend API** creates a scan record in PostgreSQL, then dispatches a **Celery task** to the Redis queue
3. **Worker** picks up the task, runs the appropriate collectors concurrently
4. Each collector produces **Findings** (email addresses, subdomains, IPs, secrets, etc.)
5. Progress is streamed to the frontend **live** via WebSocket
6. **User** sees results appear in real-time, can trigger further actions (deep analysis, pivots, enrichment)
7. **Correlation engine** links related findings together (e.g., email → domain → IP)

---

## 5. Using the Application

### 5.1 Registration & Login

1. Open http://localhost:5173
2. Click **Register** — create an account with email + password
3. Log in with your credentials
4. The first user to register is automatically an **Admin**

**Admin features** (top-right menu → Admin):
- View all users
- Promote/demote users (Admin/Viewer/User roles)
- Delete users
- Reset other users' passwords

### 5.2 Creating a Scan

1. From the Dashboard, click **"New Scan"**
2. Choose the target type:

   | Target Type | What It Does | Example |
   |---|---|---|
   | **Domain** | Full pipeline: subdomains, DNS, emails, SSL, secrets, tech profiling, lookalike domains | `example.com` |
   | **IP Address** | IP-focused: Shodan, Censys, ASN lookup, reverse DNS | `8.8.8.8` |
   | **Organization** | Domain discovery first, then full pipeline on each found domain | `Acme Inc` |

3. Select **reconnaissance vectors** (what collectors to run):

   | Vector | Collectors |
   |---|---|
   | Infrastructure | Subdomains, DNS, SSL, HTTP headers, BuiltWith, Shodan, Censys |
   | Identity | Hunter.io (emails), holehe, maigret, social media profiles |
   | Secrets | GitHub secret scanning |
   | Username | Cross-platform username search |

   > The default is just Infrastructure — fast, no API keys needed.

4. (Optional) Add **usernames** to scan across platforms
5. Click **"Start Scan"**

The scan appears on your Dashboard with a progress bar and live status updates.

### 5.3 The Scan Workspace

Click any scan card on the Dashboard to open the **Scan Workspace** — a detailed view with multiple tabs. Progress is shown in real-time at the top.

### 5.4 Tabs Explained

#### 5.4.1 Dashboard Tab

Shows a summary of the scan:
- **Status** (Running / Completed / Failed)
- **Finding counts** broken down by severity (Critical, High, Medium, Low, Info)
- **Timeline** of when the scan ran
- Quick links to findings by severity

#### 5.4.2 Infrastructure Tab

**What you see:** Subdomains discovered, IP addresses, DNS records, web technologies, and HTTP headers.

**Columns:**
- **Subdomain** — e.g., `www.example.com`, `mail.example.com`
- **IP Address** — resolved IP
- **Technologies** — web server, frameworks, libraries detected
- **HTTP Status** — response code when fetched
- **Actions** — buttons for each subdomain

**Actions available per subdomain:**

| Button | What It Does |
|---|---|
| **Deep Analysis** | Runs 8 collectors against this subdomain: Hunter (emails), theHarvester, GitHub secrets, dnstwist, BuiltWith, HTTP headers, Wayback Machine, version detection. Then cross-references technologies against CVE database. This is the most powerful action. |
| **Enrich** | Runs Hunter + XposedOrNot breach check on this specific subdomain (lighter than deep analysis). |
| **Shodan/Censys** | Looks up the IP in Shodan or Censys for open ports and services. |

**Deep Analysis Modes:**

When you click "Deep Analysis", a picker asks which theHarvester mode:

| Mode | What It Does | Duration |
|---|---|---|
| **Auto (Recommended)** | Uses full theHarvester if API keys are configured, otherwise uses quick/free mode | 30s–15min |
| **Quick** | Free sources only (24 sources) — no API keys needed | ~30s |
| **Full** | All 55 sources with all configured API keys | ~15min |

> After deep analysis completes, look for CVEs in the findings — technologies are matched against the NVD database with version-range filtering.

#### 5.4.3 Identity Tab

**What you see:** Email addresses discovered for the target domain.

**Columns:**
- Email address
- Source (Hunter.io, theHarvester, etc.)
- Confidence score
- Breach status (checked via XposedOrNot)

**Actions:**

| Button | What It Does |
|---|---|
| **Deep Analysis** | Runs holehe (account existence check) + maigret (social media footprint) + breach database check on this email |
| **Check Breaches** | Queries XposedOrNot for known breaches containing this email |
| **Pivot** | Runs holehe + maigret + HIBP deep sweep on the email |

#### 5.4.4 Secrets Tab

**What you see:** Potential secrets, keys, and credentials leaked on GitHub mentioning the target domain.

**Columns:**
- Secret type (API key, password, token, private key, etc.)
- File path (GitHub URL)
- Repository name
- Severity

**Actions:**

| Button | What It Does |
|---|---|
| **Scan GitHub Secrets** | Re-runs the GitHub secret search |
| Click any row | Opens the GitHub file containing the secret |

#### 5.4.5 Brand Protection Tab

**What you see:** Lookalike domains generated by dnstwist, Telegram mentions, and config monitoring.

- **Lookalike domains** — permutations of your target domain that could be used for phishing (e.g., `examp1e.com`, `example.co`)
- **Telegram monitor** — set up keyword monitoring for Telegram channels mentioning your brand

**Actions:**

| Button | What It Does |
|---|---|
| **Run dnstwist** | Generate lookalike permutations for any domain |
| **Monitor Telegram** | Start monitoring a keyword/phrase on Telegram for brand mentions |

#### 5.4.6 Threat Intel Tab

**What you see:** Combined threat intelligence — GitHub secret scan + dnstwist lookalike domains.

**Actions:**

| Button | What It Does |
|---|---|
| **Run Threat Intel** | Runs GitHub secrets + dnstwist together on a domain |

#### 5.4.7 Web OSINT Tab

**What you see:** Results from deep analysis organized by collector:
- **Emails found** — via Hunter.io
- **Web technologies** — server, frameworks, CMS, analytics detected
- **CVE matches** — known vulnerabilities matching detected versions
- **Wayback URLs** — historical URLs from archive.org
- **HTTP headers** — response headers from the target
- **Version info** — specific version numbers for detected technologies

This tab is the richest source of intelligence after running Deep Analysis.

#### 5.4.8 Entity Graph Tab

An interactive **graph visualization** of all findings and their connections:
- **Nodes** = entities (emails, domains, IPs, secrets, people)
- **Edges** = relationships (email@domain, IP hosts domain, secret contains domain)
- **Drag** to rearrange
- **Click** a node to see details
- **Zoom** with scroll wheel

Use the graph to discover relationships you wouldn't see in a table — e.g., an email reused across multiple platforms, or a secret that mentions a different domain.

### 5.5 Findings Table

Every tab has a **Findings Table** at the bottom showing ALL findings for the scan, filterable by:
- **Vector** (Infrastructure, Identity, Secrets, etc.)
- **Entity type** (Email, Domain, IP, Technology, CVE, etc.)
- **Severity** (Critical, High, Medium, Low, Info)
- **Source module** (which collector found it)
- **Search** — free text search across all findings

**Columns:**
- Entity (the value discovered)
- Type (email, domain, IP, etc.)
- Severity (color-coded)
- Source (which collector)
- Timestamp
- Actions (view raw data, view normalized data)

### 5.6 Pivot Actions

Pivoting is how you **go deeper** from one finding to discover more:

- **Email → Deep Pivot:** From an email address, run holehe (checks if the email has accounts on 100+ sites) + maigret (social media profile discovery) + breach database check
- **Username → Deep Pivot:** From a username, search across platforms for matching profiles
- **Subdomain → Deep Analysis:** Full multi-collector analysis on a single subdomain
- **Email → Breach Check:** Check if an email was in known data breaches
- **Domain → Threat Intel:** Run GitHub secrets + dnstwist

Pivot results appear as new findings in the same scan, linked back to the source finding.

---

## 6. API Keys — Which Ones You Need

Collectors are organized into tiers. The platform works without any API keys (using free collectors), but you get richer results with API keys.

### Tier 1: No Keys Needed (Always Works)

These collectors require zero configuration:

| Collector | What It Finds |
|---|---|
| DNS Resolver | A, AAAA, MX, NS, TXT records |
| crt.sh | SSL certificate transparency logs |
| Subfinder | Subdomain discovery |
| xposedornot | Email breach database check |
| holehe | Email account existence on 100+ sites |
| maigret | Social media profile discovery |
| dnstwist | Lookalike/typosquatting domains |
| Wayback Machine | Historical URLs from archive.org |
| HTTP Headers | Response headers + redirect chain |
| Version Detector | Technology version detection |
| Simple Username Profiler | Cross-platform username search |

### Tier 2: Free API Keys (Recommended)

These have generous free tiers — sign up for an account and get a key:

| Service | What to Get | Where to Sign Up |
|---|---|---|
| **Hunter.io** | `HUNTER_API_KEY` | hunter.io → API → Free plan (50 req/month) |
| **Censys** | `CENSYS_API_ID` + `CENSYS_API_SECRET` | censys.io → Register → Free (250 credits) |
| **VirusTotal** | `VT_API_KEY` | virustotal.com → API → Free (500 lookups/day) |
| **URLScan** | `URLSCAN_API_KEY` | urlscan.io → API → Free rate-limited |
| **FullHunt** | `FULLHUNT_API_KEY` | fullhunt.io → Free (50 queries) |
| **GitHub** | `GITHUB_TOKEN` | github.com → Settings → Developer settings → Fine-grained tokens (Free) |
| **BuiltWith** | `BUILTWITH_API_KEY` | builtwith.com → API → Free (50 queries total) |

### Tier 3: Paid API Keys (Optional for Power Users)

These unlock more data but require payment:

| Service | Key | Estimated Cost |
|---|---|---|
| Shodan | `SHODAN_API_KEY` | ~$49/year |
| Whoxy | `WHOXY_API_KEY` | ~$10/month |
| IntelX | `INTELX_API_KEY` | ~$30/month |

### How to Add API Keys

Once you have a key:

1. Open `backend/.env`
2. Find the matching variable name
3. Replace `your_key_here` with your actual key
4. Rebuild the backend and worker:
   ```bash
   docker-compose up -d --build
   ```

> **Don't have a key?** The scanner will still work — it just won't use that particular collector.

---

## 7. Troubleshooting

### "Port is already in use"

```bash
# Check what's using the port
netstat -ano | findstr :8000   # Windows
lsof -i :8000                  # macOS/Linux

# Or change the port in docker-compose.yml
```

### Containers won't start

```bash
# Check logs for errors
docker-compose logs -f

# Most common cause: missing .env file
# Fix: cp backend/.env.example backend/.env
```

### "Database connection refused"

The database takes a few seconds to initialize on first run. The backend will retry automatically. Wait 10 seconds and check again:

```bash
docker-compose restart backend worker
```

### Worker is running but findings are empty

Some collectors depend on API keys. If you have no keys configured, many collectors will return 0 results. Try running with at least:

- Hunter.io (free tier) — for email discovery
- GitHub token — for secret scanning

Or use the collectors that work without keys: DNS, crt.sh, subfinder, holehe, maigret, dnstwist, Wayback Machine.

### Deep analysis returns 0 CVEs

CVE matching requires the version detection phase to complete first. If no web technologies were detected (e.g., the target is a parked domain with no HTTP server), there's nothing to match against CVEs.

### Frontend shows blank page

```bash
# Check browser console (F12) for errors
# Common fix: clear browser cache, reload
# Check that API key in frontend/.env matches backend/.env
```

### "422 Unprocessable Content"

The API rejected the request because the data didn't match the expected format. This usually means a field value is wrong. Check:
- Was the domain valid (no protocol prefix like `https://`)?
- Was the IP address properly formatted?

### "409 Conflict — Already running"

This means a deep analysis or enrichment is already running for that target. Wait for it to complete or check the worker logs:

```bash
docker-compose logs -f worker
```

### Redis warning in logs

```
WARNING: The TCP backlog setting of 511 cannot be enforced
```

This is harmless — just a kernel tuning warning. Ignore it.

### Reset everything

```bash
docker-compose down -v   # Stops everything AND deletes all data
docker-compose up -d     # Fresh start
```

---

## 8. Sharing with Someone Else

There are several ways to share this project. Here they are from most recommended to least:

### Method 1: Git Repository ★ RECOMMENDED

**This is the simplest and most maintainable way.**

1. Push the source code (excluding `.env`) to a private Git repository:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin <your-git-url>
   git push -u origin main
   ```

2. The recipient clones and runs:
   ```bash
   git clone <your-git-url> osint-platform
   cd osint-platform
   cp backend/.env.example backend/.env
   # Edit backend/.env with their own API keys
   docker-compose up -d --build

   # In a separate terminal, start the frontend
   cd frontend
   npm install
   npm run dev
   ```

**Note:** The recipient also needs **Node.js 18+** installed on their machine for the frontend.

**Pros:** Recipient gets the cleanest setup, they build their own Docker images (no trust issues), easy to share updates.

**Cons:** They need Git installed (free, 2-minute install).

> **GitHub tip:** Create a free private repo at github.com/new. Push the code there, add the recipient as a collaborator (Settings → Collaborators).

### Method 2: Zip File (Second Best)

1. Create a `.gitignore` that already excludes `node_modules`, `.venv`, `.env`, and other runtime files
2. Zip the project folder, then send the zip:

```bash
# Windows (PowerShell)
Compress-Archive -Path "C:\path\to\osint-platform" -DestinationPath "osint-platform.zip"
```

**The recipient then:**
1. Unzips the file
2. Creates `backend/.env` from `backend/.env.example`
3. Runs `docker-compose up -d --build`
4. Opens a **second terminal**, runs `cd frontend && npm install && npm run dev`

**What to exclude from the zip:**
- `backend/.venv/` (virtual env)
- `backend/.env` (your API keys!)
- `frontend/node_modules/` (the recipient will run `npm install`)
- `backend/collectors/__pycache__/` (cache files)
- `.git/` (Git history — optional)

**Pros:** No Git needed, simple.

**Cons:** Large file (especially the first `docker-compose up --build` downloads 1-2 GB of base images anyway), no easy update path.

### Method 3: Docker Images (If They Have No Internet)

Use this if the recipient has no internet access to download base images.

1. Build the images:
   ```bash
   docker-compose build
   ```

2. Export the images:
   ```bash
   docker save automatedosint-backend:latest automatedosint-worker:latest -o osint-images.tar
   ```

3. Zip the images + source code together

4. The recipient:
   ```bash
   # Load the Docker images
   docker load -i osint-images.tar
   
   # Start the backend
   docker-compose up -d

   # In a separate terminal, start the frontend
   cd frontend
   npm install
   npm run dev
   ```

**Pros:** No internet needed on the target machine (after initial download).

**Cons:** Large file (~2 GB), images are specific to your CPU architecture (won't work if the recipient has ARM while you have x86, or vice versa).

### What NOT to Include

**Never share these files** — they contain API keys and secrets:

- ❌ `backend/.env` — all your API keys
- ❌ `frontend/.env` — frontend API key
- ❌ `backend/collectors/**/api_keys.py` — any hardcoded keys
- ❌ `.git/` — unless it's a clean push

The safest approach: **share the Git repo** with `backend/.env` in `.gitignore`. The recipient gets a fresh `.env.example` and fills in their own keys.

### What the Recipient Must Configure

Regardless of how you share it, the recipient MUST:

1. **Create `backend/.env`** from the template
2. **Set their own API keys** (or the collectors that need keys won't work)
3. **Have Docker installed** on their machine
4. **Run `docker-compose up -d --build`** for the first time

> **Minimum viable config without any API keys:** They can copy `backend/.env.example` to `backend/.env`, change `API_KEY` and `JWT_SECRET`, and the platform will still work — just using free collectors only.

---

## Appendix: Quick Reference

```bash
# Start the backend
docker-compose up -d

# Start the app (rebuild from source)
docker-compose up -d --build

# Start the frontend (separate terminal)
cd frontend && npm run dev

# View logs
docker-compose logs -f
docker-compose logs -f worker   # Just the worker

# Stop the frontend
# Press Ctrl+C in the frontend terminal, then:
docker-compose down

# Stop + delete all data (factory reset)
docker-compose down -v

# Restart backend + worker (after changing .env)
docker-compose restart backend worker

# Check disk usage of Docker
docker system df

# Clean up unused Docker resources
docker system prune -a
```

**URLs:**
- Frontend: http://localhost:5173
- API docs: http://localhost:8000/docs
- Database (PostgreSQL): `localhost:5432` (user: `postgres`, password: `postgres`)
- Redis: `localhost:6379`
