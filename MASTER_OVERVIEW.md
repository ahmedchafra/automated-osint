# OWL OSINT — Master Overview Document

**Project:** Automated OSINT & Attack Surface Management Platform  
**Version:** 2.0  
**Date:** 2026-07-20  
**Audience:** Someone completely new to coding and web development  

---

> This document breaks down the entire project — every technology, every part of the architecture, every folder and file — as if you have never coded before. Each section explains not just *what* something is, but *why* it exists and *how it fits* into the bigger picture.

---

# Part 1: Technology Stack & Dependencies

Think of this section as an inventory of every ingredient in a recipe. Each ingredient has a job, and they must work together to produce the final product.

## 1.1 Programming Languages

| Language | Where It's Used | What It Does |
|---|---|---|
| **Python 3.13** | All backend code (`backend/` folder) | The "brain" of the platform. Reads data from the internet, processes it, stores it in a database, and serves it up when requested. Python is chosen because there are many ready-made tools for OSINT (Open Source Intelligence) work. |
| **TypeScript 6.0** | All frontend code (`frontend/` folder) | A stricter version of JavaScript. Builds the web pages you see in your browser — the dashboard, scan results, buttons, charts, everything visual and interactive. TypeScript adds safety checks that prevent many bugs before the code even runs. |
| **CSS 3** | `frontend/src/index.css` | The design language. Controls colors, fonts, spacing, animations — everything that makes the platform look polished and cyber-themed (dark backgrounds, cyan accents, glass effects). |
| **HTML** | `frontend/index.html` | The skeleton of the web page. Tells the browser: "load this React app here, use these fonts, include this graph library from the internet." |

## 1.2 Backend Frameworks & Libraries (Python)

### Core Web Framework

| Technology | Purpose | Why It's Here |
|---|---|---|
| **FastAPI** (`fastapi`) | The web server framework | FastAPI handles all incoming HTTP requests from the frontend (like when you click "New Scan"). It's one of the fastest Python web frameworks, has automatic API documentation, and works naturally with async operations (doing many things at once without waiting). |
| **Uvicorn** (`uvicorn`) | The ASGI server | The engine that actually runs the FastAPI application. It's what "listens" at `http://localhost:8000` for requests and feeds them into FastAPI. |

### Database & Data Layer

| Technology | Purpose | Why It's Here |
|---|---|---|
| **PostgreSQL 16** (`postgres:16-alpine`) | The database | Stores all scan results, user accounts, findings, and relationships between findings. Think of it as a super-organized filing cabinet where everything has a specific drawer and label. |
| **SQLAlchemy** (`sqlalchemy[asyncio]`) | The database translator | Instead of writing raw SQL (database language), SQLAlchemy lets the Python code talk to the database using Python objects. The `[asyncio]` variant means it can do this without blocking other operations. |
| **asyncpg** (`asyncpg`) | The database driver | The specific "translator" that converts Python database commands into PostgreSQL's native protocol. It's the fastest option for talking to PostgreSQL from Python. |
| **Alembic** (`alembic`) | Database version control | When the database structure needs to change (like adding a new column), Alembic creates and tracks those changes as "migrations." It ensures every copy of the database stays in sync. |

### Background Task Processing

| Technology | Purpose | Why It's Here |
|---|---|---|
| **Celery** (`celery`) | Background task queue | OSINT scans take a long time (minutes to hours). Celery lets the platform say "start this scan" and immediately return control to the user, while the scan runs in the background. It's like ordering food at a restaurant — you place the order and chat while the kitchen cooks. |
| **Redis** (`redis:7-alpine`) | Message broker + cache | Acts as the "order counter" between the web server and Celery. When the server says "start a scan," the message goes into Redis, and Celery picks it up. Redis is also used for live progress updates (pub/sub) and is incredibly fast because it keeps everything in memory (RAM). |

### Async HTTP & Networking

| Technology | Purpose | Why It's Here |
|---|---|---|
| **httpx** (`httpx`) | Modern HTTP client for Python | Makes requests to external APIs (like Shodan, Hunter.io, Serper.dev). Supports async, timeouts, retries — critical when talking to 30+ different internet services. |
| **aiohttp** (`aiohttp`) | Another async HTTP client | Used specifically by the theHarvester tool internally (the aiohttp version is patched to work on Windows with Python 3.13). |
| **dnspython** (`dnspython`) | DNS queries | Looks up domain name system records — the phonebook of the internet. When the platform resolves "example.com" to an IP address like "93.184.216.34," dnspython does the lookup. |

### Authentication & Security

| Technology | Purpose | Why It's Here |
|---|---|---|
| **python-jose** (`python-jose[cryptography]`) | JWT token handling | Generates and verifies JSON Web Tokens — the "digital ID cards" users receive when they log in. Every subsequent request includes this token to prove their identity. |
| **passlib** (`passlib[bcrypt]`) | Password hashing | Never stores passwords in plain text. When you create a password, it gets scrambled into a meaningless string (hash) using the bcrypt algorithm. Even if the database is stolen, passwords can't be recovered. |
| **bcrypt** (`bcrypt`) | Password hashing algorithm | The specific mathematical algorithm used for scrambling passwords. It's deliberately slow — this makes brute-force guessing impractical. |
| **PySocks** (`PySocks`) | SOCKS proxy support | Routes traffic through the Tor network for the Ahmia dark-web collector. Adds anonymity when searching `.onion` sites. |

### OSINT Tool Libraries

| Technology | Purpose | Why It's Here |
|---|---|---|
| **theHarvester** (GitHub `laramies/theHarvester`) | Email/subdomain/ASN harvesting | A famous OSINT tool that searches 50+ public sources (search engines, PGP servers, certificate logs, etc.) to find emails, subdomains, IPs, ASNs, and virtual hosts associated with a domain. The platform wraps it as a subprocess. |
| **holehe** (`holehe`) | Email platform check | Checks if an email is registered on ~120 websites (Twitter, Instagram, Amazon, etc.). Useful for determining which services a target person uses. |
| **maigret** (`maigret`) | Username profiling | Checks ~3000 websites for a given username. If your username is "john_doe," maigret finds every site where that name is registered. |
| **h8mail** (`h8mail`) | Email breach lookup | Checks if an email appears in known data breaches, using sources like emailrep.io and scylla.so. |
| **dnstwist** (`dnstwist`) | Domain typo-squatting detection | Generates lookalike domain names ("g00gle.com," "googie.com") and checks if they exist. Used for brand protection against phishing/impersonation. |
| **PyGithub** (`PyGithub`) | GitHub API client | Searches GitHub for leaked secrets, credentials, or sensitive mentions of a domain. |
| **Telethon** (`Telethon`) | Telegram API client | Monitors Telegram channels and groups for mentions of keywords. Requires Telegram API credentials. |
| **censys-platform** | Censys API client | Queries Censys for internet-wide scan data — open ports, running services, SSL certificates for IP addresses. |

### AI / ML

| Technology | Purpose | Why It's Here |
|---|---|---|
| **Groq SDK** (`groq`) | AI inference API | Talks to Groq's ultra-fast LLM API (Llama 3.3 70B) to generate Google dork queries from natural language. Example: user types "find admin panels" → AI generates `intitle:"admin" inurl:admin`. |
| **Groq** (hardware) | AI chip company | Their LPU (Language Processing Unit) is extraordinarily fast for LLM inference — milliseconds per query rather than seconds. |

### Reporting & Export

| Technology | Purpose | Why It's Here |
|---|---|---|
| **ReportLab** (`reportlab`) | PDF generation | Creates downloadable PDF reports from scan findings. Converts all the data into a nicely formatted document. |

## 1.3 Frontend Libraries (TypeScript/JavaScript)

### UI Framework & Tools

| Technology | Purpose | Why It's Here |
|---|---|---|
| **React 19** | UI framework | The core frontend library. Builds the interface as a tree of "components" (reusable pieces like buttons, tables, cards). React efficiently updates only what changed on screen, making the app feel snappy. |
| **react-router-dom v7** | Page routing | Determines which page to show based on the URL. `/scans/new` shows the New Scan form. `/dashboard` shows the dashboard. Handles navigation without full page reloads. |
| **Vite 8** | Build tool & dev server | During development, Vite instantly reflects code changes in the browser. For production, it bundles and optimizes all the code into efficient files. Vite 8 uses Rolldown (a Rust-based bundler) — very fast. |
| **TypeScript 6.0** | Types for JavaScript | Catches errors during development: "you can't multiply a string by a number." Prevents many runtime crashes before the code is ever deployed. |

### State Management & Data Fetching

| Technology | Purpose | Why It's Here |
|---|---|---|
| **@tanstack/react-query v5** | Server data management | Handles all API calls — fetching scan lists, submitting forms, refreshing data. Provides caching (don't re-fetch if data is fresh), automatic retries on failure, and background refresh. |
| **React Context API** (built into React) | Global app state | Three built-in "contexts" share data across all pages: authentication state (is user logged in?), notifications (popup messages), and scan workspace state (active filters, real-time findings). |

### UI Components & Visuals

| Technology | Purpose | Why It's Here |
|---|---|---|
| **framer-motion** | Animations | Powers page transitions (smooth slide effects), spring-animated notification toasts, loading spinners, and subtle hover effects. Makes the UI feel polished and responsive. |
| **lucide-react** | Icons | Clean, consistent icon set. Every icon in the sidebar (Dashboard, New Scan, etc.) and every action button (Download, Delete, Filter) comes from Lucide. |
| **recharts** | Charts | Renders the dashboard's donut chart (findings by severity) and bar chart (findings by type). Built on React components so they fit naturally. |
| **cytoscape** | Graph visualization | Renders the entity relationship graph — a visual web showing how subdomains connect to IPs, which connect to port services, which connect to CVEs. |
| **react-cytoscapejs** | React wrapper for Cytoscape | Lets Cytoscape be used as a React component. |

### Utilities

| Technology | Purpose | Why It's Here |
|---|---|---|
| **axios** | HTTP client | Makes API calls from the browser to the backend. Handles attaching auth tokens automatically, intercepts 401 (unauthorized) responses to redirect to login. |
| **date-fns** | Date formatting | Shows human-friendly dates like "2 hours ago" or "Jan 15, 2026." Lighter alternative to the massive Moment.js library. |

## 1.4 Infrastructure & DevOps

| Technology | Purpose | Why It's Here |
|---|---|---|
| **Docker** | Containerization | Packages each service (PostgreSQL, Redis, Backend API, Celery Worker) into isolated "containers" — lightweight virtual machines. Ensures the app runs identically on any computer. |
| **Docker Compose** | Multi-container orchestration | A single `docker compose up` command starts all four services together, wired to talk to each other. Defines environment variables, port mappings, and storage volumes. |
| **PostgreSQL 16 Alpine** | Database container | The smallest possible PostgreSQL image (~200MB). Stores all persistent data on a named Docker volume so it survives container restarts. |

## 1.5 External APIs & Services (Data Sources)

These are the third-party services the platform talks to over the internet to gather intelligence:

### Infrastructure / Network
| API | What It Provides | Free Tier |
|---|---|---|
| **crt.sh** | Certificate Transparency log — reveals subdomains from SSL certificates | Unlimited, free |
| **Shodan InternetDB** | Basic IP info (open ports, technologies) for any internet-facing IP | Unlimited, free |
| **Shodan Host** | Deep IP scan results (services, CVEs, banners, org info) | API key, 1M results/mo |
| **Censys Host** | Internet-wide scan data — ports, protocols, certificates, vulnerabilities | API ID + Secret, limited free |
| **WhoIS (rdap)** | Domain registration info (registrar, dates, name servers) | Free |
| **DNS** (built-in) | Resolves domain names to IPs, finds mail servers, etc. | Free |

### Identity / Email
| API | What It Provides | Free Tier |
|---|---|---|
| **Hunter.io** | Finds email addresses associated with a domain | 25 queries/mo free |
| **HaveIBeenPwned** | Checks if emails appear in known breaches | 100 queries/day free |
| **XposedOrNot** | Breach data lookup | Free |
| **emailrep.io** | Email reputation and breach info | Rate-limited free |
| **Hibp** (theHarvester) | Email harvesting from public sources | Free |

### Search & Discovery
| API | What It Provides | Free Tier |
|---|---|---|
| **Serper.dev** | Google search API (for dorking) | 2,500 queries/mo free |
| **GitHub** (via token) | Searches repos for secrets/mentions | Free with token |
| **Brave Search** | Alternative search engine API | Free tier |
| **WHOXY** | Reverse Whois lookup — find domains owned by a person/org | 100 queries/mo |

### Threat Intelligence
| API | What It Provides | Free Tier |
|---|---|---|
| **NVD** (NIST) | National Vulnerability Database — CVE details | 5 req/30s free, 50 with key |
| **CISA KEV** | Known Exploited Vulnerabilities catalog | Free |
| **VirusTotal** | File/URL/domain reputation | 500 lookups/day free |
| **AlienVault OTX** | Open Threat Exchange — threat intelligence | Free |
| **URLScan.io** | Website screenshot and analysis | Rate-limited free |
| **Ahmia.fi** | Dark web (.onion) search | Free (via Tor) |

### theHarvester Sources (50+ total, 24 free without API keys)
Free sources include: baidu, bing, bingapi, certspotter, crtsh, dnsdumpster, dogpile, duckduckgo, google, hackertarget, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securitytrails, subdomaincenter, subdomainfinderc99, threatminer, urlscan, virustotal, yahoo, yandex.

API-key sources include: shodan, hunter, github, intelx, fullhunt, criminalip, brave, zoomEye, builtwith, fofa, and more.

---

# Part 2: Architecture & Design Patterns

## 2.1 Overall Architecture: Monolith + Microservice Hybrid

This platform uses a **dual architecture pattern**:

### Frontend-Backend Split (Client-Server Architecture)

```
┌─────────────────────────┐      ┌──────────────────────────────────┐
│      YOUR BROWSER       │      │           DOCKER COMPOSE         │
│                         │      │                                  │
│   React 19 Frontend     │◄────►│  ┌──────────────────────────┐   │
│   (TypeScript)          │ HTTP │  │  FastAPI Backend          │   │
│                         │  /   │  │  (Python, Port 8000)      │   │
│   Port 5173 (dev)       │  WS  │  └────────┬─────────┬───────┘   │
│   Port 80 (prod)        │      │           │         │           │
└─────────────────────────┘      │     ┌─────▼──┐ ┌───▼────────┐  │
                                  │     │ Redis  │ │ PostgreSQL │  │
                                  │     │ Broker │ │ Database   │  │
                                  │     └────┬───┘ └────────────┘  │
                                  │          │                      │
                                  │     ┌────▼──────────┐          │
                                  │     │ Celery Worker  │          │
                                  │     │ (Background)    │          │
                                  │     └────────────────┘          │
                                  └──────────────────────────────────┘
```

**Key Principle:** The frontend (what you see) and backend (what processes data) are completely separate. They communicate only through well-defined API calls over HTTP or WebSocket connections. This means either part could be replaced independently — you could build a mobile app using the same backend, or swap the frontend to a different framework.

### Why not Microservices?

A true microservices architecture would split the backend into dozens of tiny services, each running in its own container. This project deliberately keeps a **monolithic backend** because:

- **OSINT workflows are sequential and interconnected** — Phase 1 infra findings feed into Phase 2 services, which feed into CVE lookups. Splitting this across services adds complexity without benefit.
- **Database transactions are simpler** — One transaction can insert findings from the infrastructure scan and immediately read them for the services scan.
- **Deployment is simpler** — One Docker container for the API, one for the worker. No service mesh, no API gateway.

### But it also uses a Worker Pattern (Microservice-like)

Celery workers run as a **separate Docker container**, sharing the same codebase. This is a microservice-style separation: the API server handles quick request/response (milliseconds), while workers handle long-running scans (minutes). They communicate through Redis.

## 2.2 Communication Between Components

### Frontend ↔ Backend: REST API

```
Frontend                    Backend
   │     POST /api/scans/initial     │
   │    { target: "example.com" }    │
   │────────────────────────────────►│
   │                                  │
   │    202 { scan_id: "abc123" }    │
   │◄────────────────────────────────│
   │                                  │
   │     GET /api/scans/abc123        │
   │────────────────────────────────►│
   │     { status: "RUNNING", ... }   │
   │◄────────────────────────────────│
```

**REST (Representational State Transfer)** is a style where you use standard HTTP methods (GET=read, POST=create, PATCH=update, DELETE=remove) to interact with resources (scans, findings, users).

### Frontend ↔ Backend: WebSocket (Live Updates)

```
Frontend                    Backend
   │     ws://localhost:8000/ws/scans/abc123   │
   │═══════════════════════════════════════════►│
   │                                           │
   │    { event: "tool_completed",             │
   │      tool: "crtsh", findings: 142 }       │
   │◄═══════════════════════════════════════════│
   │                                           │
   │    { event: "phase_completed",            │
   │      phase: "INFRASTRUCTURE" }            │
   │◄═══════════════════════════════════════════│
```

**WebSocket** is a persistent two-way connection. Unlike REST (where the frontend must ask for updates), the server can push events as they happen. This is how the pipeline progress page animates in real-time.

### Backend ↔ Worker: Celery + Redis (Task Queue)

```
Backend API                  Redis                    Celery Worker
   │                          │                          │
   │── celery.send_task() ──► │                          │
   │   "execute_scan"         │── message queue ────────►│
   │                          │                          │── run_task()
   │                          │                          │── crtsh.execute()
   │                          │                          │── subfinder.execute()
   │                          │                          │── ...
   │                          │◄──── progress event ─────│
   │◄── Redis pub/sub ────────│                          │
   │                          │                          │
   │── WebSocket push ───────►│                          │
   │   to frontend            │                          │
```

The API server places a "task" message in Redis. The Celery worker (running in a separate container) picks it up, executes it, and publishes progress events back through Redis. The API server subscribes to those events and forwards them to the frontend via WebSocket.

### Worker ↔ Collectors: Direct Python Calls

```
Celery Worker
    │
    ├──► CollectorRegistry.get("crtsh")
    │       └──► crtsh.CrtShCollector.execute("example.com")
    │              └──► httpx.get("https://crt.sh/?q=example.com")
    │
    ├──► CollectorRegistry.get("subfinder")
    │       └──► subfinder.SubfinderCollector.execute("example.com")
    │              └──► subprocess.run(["subfinder", "-d", "example.com"])
    │
    ├──► run_collector_for_scan()  ← auto-discovery + dedup + persist
    └──► persist_findings()
            └──► db.session.add_all(findings)
```

## 2.3 Design Patterns Used

### 1. Registry Pattern (Collector Discovery)

```python
# collectors/registry.py
class CollectorRegistry:
    def __init__(self):
        self._collectors = {}
    
    def auto_discover(self):
        # Scans all Python files under collectors/ directory
        # Finds every class that extends BaseCollector
        # Registers them by metadata.name
```

**Why:** New collectors can be added by simply creating a new Python file in the right folder. The system automatically discovers and registers it — no configuration file needs to be updated.

### 2. Strategy Pattern (5 Vectors)

```python
# services/vectors/__init__.py
STRATEGIES = {
    VectorType.INFRASTRUCTURE: run_infrastructure,
    VectorType.SERVICES: run_services,
    VectorType.IDENTITY: run_identity,
    VectorType.SEARCH: run_search,
    VectorType.USERNAME: run_username,
}
```

Each vector (dimension of reconnaissance) is a self-contained "strategy." The `ScanOrchestrator` selects which strategies to run based on what the user requested, and runs them sequentially. Each strategy can be developed and tested independently.

### 3. Repository Pattern (Database Access)

SQLAlchemy itself implements this pattern. Instead of writing raw SQL statements scattered throughout the code, all database operations go through typed Python objects:

```python
# Instead of:  SELECT * FROM findings WHERE scan_id = 'abc'
# You write:
session.execute(select(Finding).where(Finding.scan_id == scan_id))
```

### 4. Factory Pattern (Findings Creation)

The `normalize()` method on each collector acts as a factory — it takes raw data from an external source and creates structured `Finding` objects with proper entity types, severity levels, and confidence scores.

### 5. Pub/Sub Pattern (Progress Updates)

Redis pub/sub (publish/subscribe) decouples the workers that produce progress events from the API server that consumes them:

- Workers **publish** events to a Redis channel
- API server **subscribes** to that channel
- Neither knows about the other directly

### 6. Singleton Pattern (Settings & Registry)

The `Settings` class and `CollectorRegistry` are effectively singletons — they are created once at application startup and shared everywhere:

```python
settings = Settings()          # Single instance, imported everywhere
registry = CollectorRegistry() # Auto-discovers all collectors once
```

### 7. Adapter Pattern (Collector Base Class)

```python
class BaseCollector(ABC):
    @abstractmethod
    async def collect(self, target: str) -> list[dict]:
        """Fetch raw data from the source."""
    
    @abstractmethod
    def normalize(self, raw: list[dict], target: str) -> list[dict]:
        """Convert raw data into standardized findings."""
    
    async def execute(self, target: str) -> list[dict]:
        """Template method: collect → normalize, with retry logic."""
```

Every collector follows the same interface regardless of whether it calls an API (Shodan), runs a CLI tool (theHarvester), queries a database (WhoIS), or scrapes a website (crt.sh). The `BaseCollector.execute()` wraps everything with retry logic and error handling.

### 8. Template Method Pattern (Collector Execution)

`BaseCollector.execute()` defines the skeleton of the operation:
1. Retry up to 5 times with exponential backoff (wait 2s, then 4s, then 8s...)
2. Call the concrete `collect()` method
3. Call the concrete `normalize()` method
4. Return standardized findings
5. On failure, log and return empty list

Individual collectors only override `collect()` and `normalize()` — they inherit retry logic, error handling, and timeout behavior automatically.

---

# Part 3: Data Flow & Core Processes

## 3.1 The Full User Journey: Starting a Scan

Let's trace what happens when you type a domain and click "Launch Reconnaissance."

### Step 1: User Interface

```
[New Scan Page]
    │
    ├── You type: "example.com"
    ├── Frontend auto-detects it's a domain (regex check)
    ├── Shows: "Domain Reconnaissance" 
    │         - Certificate Transparency (crt.sh)
    │         - Subdomain Enumeration (subfinder)
    │         - DNS Resolution
    │         - Shodan InternetDB
    │
    └── You click: "Launch Reconnaissance"
```

**What happens in the code:**
1. `frontend/src/pages/NewScan.tsx` captures the form submission
2. `React Query` mutation sends `POST /api/scans/initial`
3. Body: `{ "target_domain": "example.com", "target_type": "domain" }`

### Step 2: API Server Receives Request

```
backend/app/api/scans.py (line ~120)
    │
    ├── Authenticates user (checks JWT token in header)
    ├── Validates domain format
    ├── Creates Scan record in database
    │     status = "PENDING"
    │     target_domain = "example.com"
    │     target_type = "domain"
    │     owner_id = <current user>
    │
    ├── Dispatches Celery task:
    │     celery_app.send_task("execute_initial_scan", args=[scan_id])
    │
    └── Returns HTTP 202:
        { "scan_id": "abc-123-def", "status": "PENDING" }
```

**What happens in the code:**
1. `POST /api/scans/initial` in `backend/app/api/scans.py`
2. Validates input using Pydantic schemas (`backend/app/schemas/base.py`)
3. Creates Scan model instance (`backend/app/models/scan.py`)
4. Calls `celery_app.send_task("execute_initial_scan", args=[scan_id])`
5. Returns `{"scan_id": "abc-123-def", "status": "PENDING"}`

### Step 3: Frontend Redirects to Workspace

```
Browser URL changes to: /scans/abc-123-def
    │
    ├── Opens WebSocket connection:
    │     ws://localhost:8000/ws/scans/abc-123-def
    │
    ├── Shows "Pipeline Progress" view:
    │     - INFRASTRUCTURE phase: [pending] [pending] [pending]
    │     - SERVICES phase: [locked] [locked] [locked]
    │     - IDENTITY phase: [locked] [locked]
    │     - SEARCH phase: [locked] [locked]
    │
    └── Waits for events on WebSocket...
```

### Step 4: Celery Worker Executes the Scan

```
Celery Worker picks up the task
    │
    ├── backend/app/workers/initial_scan.py
    │
    ├── Phase 1: INFRASTRUCTURE
    │   ├── 1. crt.sh ▸ Searches certificate logs → finds subdomains
    │   │     Publishes: { tool: "crtsh", collected: 142 }
    │   │
    │   ├── 2. subfinder ▸ 40+ passive sources → more subdomains  
    │   │     Publishes: { tool: "subfinder", collected: 89 }
    │   │
    │   ├── 3. DNS Resolution ▸ Resolves each subdomain to IP addresses
    │   │     Publishes: { tool: "dns_resolver", collected: 231 }
    │   │
    │   ├── 4. Shodan InternetDB ▸ Gets port/service info for each IP
    │   │     Publishes: { tool: "shodan_internetdb", collected: 405 }
    │   │
    │   └── 5. WhoIS Lookup ▸ Domain registration info
    │         Publishes: { tool: "whois_lookup", collected: 1 }
    │
    ├── Publishes: { event: "phase_completed", phase: "INFRASTRUCTURE" }
    │
    ├── Phase 2: SERVICES (runs on each discovered IP)
    │   ├── Shodan Host → port services, CVEs, banners, technologies
    │   └── Censys Host → internet scan data
    │
    ├── Phase 3: IDENTITY (email discovery)
    │   ├── Hunter.io → find emails
    │   └── XposedOrNot → check if emails breached
    │
    ├── Phase 4: SEARCH
    │   ├── GitHub secrets scan
    │   └── Serper Google dorking
    │
    ├── Runs Correlation Engine:
    │   - Links subdomains → IPs (RESOLVES_TO)
    │   - Links IPs → port services (HAS_PORT)
    │   - Links IPs → CVEs (HAS_VULNERABILITY)
    │   - Links emails → breaches (BREACHED_IN)
    │
    ├── Publishes: { event: "scan_completed", total_findings: 1567 }
    │
    └── Updates Scan model: status = "COMPLETED"
```

**What happens inside each collector:**
```
crt.sh collector:
    │
    ├── execute("example.com")
    │     │
    │     ├── collect("example.com"):
    │     │     GET https://crt.sh/?q=example.com&output=json
    │     │     Returns: [{"name_value": "www.example.com", ...}, ...]
    │     │
    │     └── normalize(raw, "example.com"):
    │           For each entry:
    │             entity_type = "SUBDOMAIN"
    │             entity_value = "www.example.com"
    │             severity = "INFO"
    │             confidence = 0.8
    │             source_module = "crtsh"
```

### Step 5: Live Progress Flows to Frontend

```
[Celery Worker]                 [Redis]                 [FastAPI]               [Browser]
    │                            │                        │                       │
    │── publish(progress) ─────►│                        │                       │
    │                            │── (pub/sub) ──────────►│                       │
    │                            │                        │── ws.send(json) ─────►│
    │                            │                        │                       │
    │                            │                        │                       │── update progress bars
    │                            │                        │                       │── animate transitions
    │                            │                        │                       │── show findings count
```

Each time a collector finishes, the worker publishes a progress event → Redis pub/sub delivers it → the API server's event streamer sends it over WebSocket → the frontend's scan workspace updates the UI.

### Step 6: Results Become Interactive

Once the scan completes (or even while it's running), the user can:

1. **View Raw Findings** — The `InfrastructureTab` shows all subdomains, IPs, DNS records, certificates, and Whois data in sortable tables.

2. **Trigger Deep Analysis** — Clicking "Deep Analysis" on a subdomain dispatches a new Celery task that runs 7 collectors in parallel (Hunter.io, theHarvester full mode, GitHub secrets, dnstwist, BuiltWith, HTTP headers, Wayback Machine).

3. **View Entity Graph** — The `EntityGraph` page uses Cytoscape to render an interactive graph showing how everything connects.

4. **Export** — Download findings as CSV, JSON, or PDF report.

5. **AI Dorking** — In `AIAssistant`, describe what you're looking for in natural language, and the platform generates Google dork queries and runs them via Serper.

## 3.2 The Database Schema (Data Model)

This is how data is organized in PostgreSQL:

```
┌─────────────────────────────────────────────────────┐
│                      users                           │
├─────────────────────────────────────────────────────┤
│ id (UUID)          ← Primary key                     │
│ username (text)    ← Unique, used for login          │
│ email (text)       ← Unique                          │
│ hashed_password    ← bcrypt hash, never plaintext    │
│ role (text)        ← "admin" or "user"               │
│ is_active (bool)   ← Account approval status         │
│ created_at         ← Timestamp                       │
└───────────────────────────┬─────────────────────────┘
                            │ 1
                            │
                            │ * (owner)
                            ▼
┌─────────────────────────────────────────────────────┐
│                      scans                            │
├─────────────────────────────────────────────────────┤
│ id (UUID)          ← Primary key                     │
│ target_domain      ← "example.com"                   │
│ target_type        ← "domain" | "ip" | "organization"│
│ status             ← "PENDING" | "RUNNING" | ...     │
│ selected_vectors   ← JSON array of vectors to run    │
│ target_usernames   ← JSON array                      │
│ owner_id (FK)      ← users.id                        │
│ created_at         ← Timestamp                       │
│ completed_at       ← Timestamp (nullable)            │
│ updated_at         ← Timestamp                       │
└───────────────────────────┬─────────────────────────┘
                            │ 1
                            │
                            │ * (on delete CASCADE)
                            ▼
┌─────────────────────────────────────────────────────┐
│                     findings                          │
├─────────────────────────────────────────────────────┤
│ id (UUID)          ← Primary key                     │
│ scan_id (FK)       ← scans.id                        │
│ vector_type        ← "INFRASTRUCTURE" | "IDENTITY"   │
│ entity_type        ← "SUBDOMAIN" | "EMAIL" | "CVE"   │
│ entity_value       ← "www.example.com"               │
│ severity           ← "INFO" | "LOW" | "MEDIUM" | ...│
│ confidence         ← float 0.0-1.0                   │
│ source_module      ← "crtsh" | "subfinder"           │
│ raw_data (JSON)    ← Original API response           │
│ normalized_data    ← Structured data hash            │
│ tags (JSON)        ← Arbitrary labels                │
│ search_vector      ← Full-text search index          │
│ created_at         ← Timestamp                       │
│                                                       │
│ UNIQUE: (scan_id, entity_type, entity_value,          │
│         source_module)  ← Prevents duplicates         │
└──────────┬──────────────────────────────────────────┘
           │ *                   │ *
           │                     │
           ▼                     ▼
┌──────────────────────────────────────────────────────┐
│                    entity_links                        │
├──────────────────────────────────────────────────────┤
│ id (UUID)          ← Primary key                      │
│ scan_id (FK)       ← scans.id                         │
│ source_finding_id  ← findings.id (from)               │
│ target_finding_id  ← findings.id (to)                 │
│ link_type          ← "RESOLVES_TO" | "HAS_PORT"       │
│ confidence         ← float 0.0-1.0                    │
│ created_at         ← Timestamp                        │
└──────────────────────────────────────────────────────┘
```

### Understanding Entity Types

The `entity_type` field tells you *what kind of thing* was found. There are 34 entity types across 6 categories:

**Infrastructure:** SUBDOMAIN, IP_ADDRESS, DNS_RECORD, TLS_CERT, ASN_INFO, PORT_SERVICE, HOST_METADATA, DOMAIN_METADATA  
**Web:** TECHNOLOGY, HTTP_HEADER, HISTORICAL_URL, WAYBACK_SNAPSHOT  
**Identity:** EMAIL, BREACH, EMAIL_PLATFORM, PROFILE  
**Secrets:** LEAKED_SECRET, GITHUB_REPO  
**Threat:** CVE, LOOKALIKE_DOMAIN, PHISHING_SITE, CLOUD_BUCKET, ONION_SITE, TELEGRAM_MESSAGE, TELEGRAM_CHANNEL, DARKWEB_MENTION, EXPOSED_FILE, DORK_RESULT, CREDENTIAL, MALICIOUS_IP, MALWARE, EXPLOIT_KIT, ATTACK_PATTERN

### Understanding Severity Levels

| Level | Color | Meaning | Example |
|---|---|---|---|
| **CRITICAL** | Rose/Red | Immediate action needed | Active CVE exploit, leaked credential |
| **HIGH** | Amber | Significant risk | Open database, exposed admin panel |
| **MEDIUM** | Yellow | Moderate concern | Information disclosure |
| **LOW** | Emerald | Minor finding | Version disclosure |
| **INFO** | Blue | For reference only | Subdomain, DNS record |

## 3.3 Authentication Flow

```
[Browser]                        [Backend]
    │                                │
    │  POST /api/auth/register       │
    │  { username, email, password } │
    │───────────────────────────────►│
    │                                │── Hash password (bcrypt)
    │                                │── Create user (is_active=false)
    │                                │── Return 201
    │◄───────────────────────────────│
    │                                │
    │  (User must be approved by     │
    │   admin before they can login) │
    │                                │
    │  POST /api/auth/login          │
    │  { username, password }        │
    │───────────────────────────────►│
    │                                │── Verify password hash
    │                                │── Check is_active
    │                                │── Generate JWT token
    │                                │── Return { token, user }
    │◄───────────────────────────────│
    │                                │
    │  Store token in localStorage   │
    │  ("owl_osint_token")           │
    │                                │
    │  GET /api/auth/me              │
    │  Authorization: Bearer <token> │
    │───────────────────────────────►│
    │                                │── Validate JWT signature
    │                                │── Return user profile
    │◄───────────────────────────────│
```

The JWT token is a signed "digital passport" containing the user's ID and role. It expires after 24 hours (configurable). Every subsequent API request includes this token in the Authorization header.

---

# Part 4: Directory Structure

Here is the complete project tree with explanations of each folder's responsibility.

## 4.1 Root Level

```
C:\Users\user\Documents\automated osint\
│
├── docker-compose.yml          ← Defines all 4 Docker containers,
│                                   how they're networked, where data
│                                   is stored, and what environment
│                                   variables they need.
│
├── backend/                    ← ALL server-side code (Python)
├── frontend/                   ← ALL browser-side code (TypeScript)
├── docs/                       ← Additional documentation
├── tests/                      ← Test files
├── memory/                     ← Persistent memory for Claude Code
│
├── start.bat                   ← Windows one-click startup script
├── start.sh                    ← Linux/Mac startup script
├── stop.bat                    ← Windows shutdown script
├── stop.sh                     ← Linux/Mac shutdown script
├── run_tests.bat               ← Windows test runner
│
├── HANDOVER.md                 ← Project handover documentation
├── DEPLOYMENT.md               ← Production deployment guide
├── ROADMAP.md                  ← Future development roadmap
├── PLAN_FILE.md                ← Implementation plan
├── implementation_plan.md      ← Detailed implementation planning
├── MASTER_OVERVIEW.md          ← This document
│
├── package.json / .claude/     ← Claude Code configuration
└── *.bat / *.sh                ← Helper scripts
```

## 4.2 Backend Directory (`backend/`)

```
backend/
│
├── Dockerfile                  ← Instructions to build the backend
│                                   container image (Python 3.13, all
│                                   dependencies installed)
│
├── docker-entrypoint.sh        ← Script that runs INSIDE the container
│                                   when it starts:
│                                   - Installs subfinder binary
│                                   - Installs theHarvester from GitHub
│                                   - Generates API key YAML files
│                                   - Starts Tor daemon for dark web
│                                   - Then runs the main command
│
├── requirements.txt            ← All Python package dependencies
│                                   (pip install -r requirements.txt)
│
├── .env                        ← API keys and secrets (NOT committed
│                                   to git)
├── .env.example                ← Template showing which keys to set
├── .dockerignore               ← Files to exclude from Docker build
│
├── alembic.ini                 ← Alembic database migration config
├── alembic/                    ← Migration files (5 versions exist):
│   └── versions/                   - Initial schema creation
│       ├── 5441414d9d07_...        - Add target_usernames column
│       ├── 20260618_0002_...       - Add full-text search to findings
│       ├── 20260620_0003_...       - Add updated_at to scans
│       ├── 20260629_0004_...       - Add uniqueness constraint
│       └── 20260630_0005_...
│
├── app/                        ← THE MAIN APPLICATION (43 files)
│   │
│   ├── main.py                 ← FastAPI entry point:
│   │                              - Creates the app
│   │                              - Configures CORS (allows cross-origin
│   │                                requests from the frontend)
│   │                              - Mounts all API routes
│   │                              - Health check endpoint
│   │                              - Global error handlers
│   │
│   ├── config.py               ← Settings class (Pydantic):
│   │                              Reads from .env file + environment
│   │                              All ~40+ API keys defined here
│   │                              Production validation
│   │
│   ├── database.py             ← Database engine setup:
│   │                              Creates async connection pool
│   │                              Session factory for database access
│   │
│   ├── models/                 ← Database table definitions (7 models):
│   │   ├── base.py                 - UUID + timestamp mixin
│   │   ├── user.py                 - User accounts
│   │   ├── scan.py                 - Scan sessions
│   │   ├── finding.py              - Individual findings
│   │   ├── entity_link.py          - Relationships between findings
│   │   ├── ai_query.py             - AI dork query history
│   │   └── scan_collaborator.py    - Shared scan permissions
│   │
│   ├── schemas/                ← Data validation & API contracts:
│   │   ├── enums.py                - All 34 entity types, severities,
│   │   │                             scan statuses, etc.
│   │   ├── base.py                 - Request/response schemas for scans,
│   │   │                             findings, enrichment triggers
│   │   └── auth.py                 - Login/register/change-password
│   │
│   ├── api/                    ← REST API endpoints (10 files):
│   │   ├── router.py               - Aggregates all routes
│   │   ├── auth.py                 - POST /register, /login, /me
│   │   ├── scans.py                - POST /scans/* (17+ endpoints)
│   │   ├── findings.py             - GET /findings (filter + export)
│   │   ├── links.py                - GET /links (entity graph edges)
│   │   ├── dashboard.py            - GET /stats, /queue
│   │   ├── admin.py                - User management (admin only)
│   │   ├── users.py                - User search
│   │   ├── ai.py                   - AI dork generation
│   │   ├── ws.py                   - WebSocket upgrade endpoint
│   │   └── _filters.py             - Shared query filter builder
│   │
│   ├── core/                   ← Cross-cutting concerns:
│   │   ├── auth.py                 - JWT creation/verification
│   │   ├── security.py             - API key validation
│   │   ├── ws_security.py          - WebSocket auth (key, query, header)
│   │   └── exceptions.py           - Global error handlers
│   │
│   ├── services/               ← Business logic:
│   │   ├── scan_service.py         - Scan orchestrator
│   │   ├── streaming.py            - Redis→WebSocket event relay
│   │   ├── progress.py             - Redis progress publisher
│   │   ├── correlation.py          - Creates entity links
│   │   ├── ai_service.py           - Calls Groq LLM for dork gen
│   │   ├── export_service.py       - CSV/JSON/PDF report generation
│   │   └── vectors/                - 5 reconnaissance strategies:
│   │       ├── infrastructure.py       - crt.sh → subfinder → DNS
│   │       ├── services.py             - Shodan → Censys → CVE → KEV
│   │       ├── identity.py             - Hunter → XposedOrNot → h8mail
│   │       ├── search.py               - Serper → dnstwist → Telegram
│   │       └── context.py              - Shared state across vectors
│   │
│   └── workers/                ← Background task definitions (17 files):
│       ├── celery_app.py             - Celery configuration
│       ├── task_utils.py             - run_collector_for_scan, persist
│       ├── initial_scan.py           - Phase 1 infrastructure scan
│       ├── ip_scan.py                - IP reconnaissance
│       ├── org_scan.py               - Organization scan
│       ├── domain_deep_analysis.py   - All 7 collectors in parallel
│       ├── deep_pivot.py             - Email deep analysis
│       ├── pivot_tasks.py            - Per-email pivot sweep
│       ├── email_breach.py           - XposedOrNot breach check
│       ├── shodan_enrich.py          - IP→Shodan Host enrichment
│       ├── censys_enrich.py          - IP→Censys enrichment
│       ├── dnstwist_task.py          - Standalone dnstwist
│       ├── telegram_task.py          - Telegram monitoring
│       ├── ahmia_task.py             - Dark web search
│       ├── threat_intel.py           - GitHub + dnstwist
│       ├── ai_tasks.py               - AI dork execution
│       ├── subdomain_enrich.py       - Per-subdomain enrichment
│       ├── scan_tasks.py             - Legacy task (deprecated)
│       └── unified_scan.py           - Legacy pipeline (disabled)
│
├── collectors/                 ← PLUGGABLE DATA SOURCES (20 collectors)
│   │
│   ├── base.py                 ← BaseCollector ABC:
│   │                              - Defines the interface every
│   │                                collector must follow
│   │                              - Automatic retry (5 attempts,
│   │                                exponential backoff + jitter)
│   │                              - Error handling
│   │
│   ├── registry.py             ← Auto-discovery:
│   │                              - Scans all collector directories
│   │                              - Registers every BaseCollector
│   │                                subclass found
│   │                              - Used by workers to find collectors
│   │                                by name
│   │
│   ├── infrastructure/         ← 6 collectors:
│   │   ├── crtsh.py                - Certificate transparency logs
│   │   ├── subfinder.py            - Passive subdomain enumeration
│   │   ├── dns_resolver.py         - DNS record resolution
│   │   ├── whois_lookup.py         - Domain registration info
│   │   ├── reverse_dns.py          - PTR record lookups
│   │   ├── shodan_internetdb.py    - Free Shodan IP data
│   │   ├── org_domain_discovery.py - Find domains for organization
│   │   └── reverse_whois_whoxy.py  - Whoxy API reverse lookup
│   │
│   ├── services/               ← 7 collectors:
│   │   ├── shodan_host.py          - Shodan paid API
│   │   ├── censys_host.py          - Censys internet scan data
│   │   ├── nvd_cve.py              - CVE lookups from CPEs
│   │   ├── cisa_kev.py             - Known exploited vulns
│   │   ├── http_headers_collector.py - HTTP response headers
│   │   ├── builtwith_collector.py  - Tech fingerprinting
│   │   └── technology_cve.py       - Tech name→CVE cross-ref
│   │
│   ├── identity/               ← 7 collectors:
│   │   ├── theharvester.py         - CLI wrapper (50+ sources)
│   │   ├── hunter_domain.py        - Hunter.io API
│   │   ├── h8mail.py               - Email breach checking
│   │   ├── hibp_breach.py          - HaveIBeenPwned API
│   │   ├── holehe.py               - Platform registration check
│   │   ├── xposedornot.py          - Breach data
│   │   └── github_secrets.py       - GitHub secret scanning
│   │
│   ├── search/                 ← 7 collectors:
│   │   ├── serper_search.py        - Google search API
│   │   ├── serper_dork_search.py   - Custom dork execution
│   │   ├── dnstwist.py             - Domain permutations
│   │   ├── telegram_monitor.py     - Channel monitoring
│   │   ├── ahmia.py                - Dark web search
│   │   ├── wayback_machine.py      - Archive.org historical URLs
│   │   └── cloud_bucket.py         - Cloud storage discovery
│   │
│   └── username/               ← 2 collectors:
│       ├── maigret.py              - Username profiling (3000+ sites)
│       └── simple_profiler.py      - Lightweight platform check
│
├── scripts/                    ← Standalone utility scripts:
│   ├── seed_admin.py               - Create admin user
│   ├── cleanup_stuck_scans.py      - Mark hung scans as failed
│   └── theharvester_runner.py      - Patched theHarvester runner
│
└── theharvester_output.json / .xml  ← Debug output files
```

## 4.3 Frontend Directory (`frontend/`)

```
frontend/
│
├── index.html                  ← HTML entry point:
│                                  - Loads cytoscape from CDN
│                                  - Mounts React app at <div id="root">
│
├── vite.config.ts              ← Vite build configuration
├── tsconfig.json               ← TypeScript configuration
├── tsconfig.app.json           ← App-specific TS settings
├── tsconfig.node.json          ← Node-specific TS settings
├── eslint.config.js            ← Code quality rules
│
├── package.json                ← All frontend dependencies (18 packages)
│
├── src/                        ← ALL application code (31 files)
│   │
│   ├── main.tsx                ← React entry point:
│   │                              Creates root, wraps in StrictMode
│   │
│   ├── App.tsx                 ← Application shell:
│   │                              - BrowserRouter for routing
│   │                              - AuthProvider + NotificationProvider
│   │                              - Sidebar (OWL OSINT branding)
│   │                              - Topbar with breadcrumbs
│   │                              - 11 route definitions
│   │
│   ├── index.css               ← Complete design system (1627 lines):
│   │                              - CSS custom properties (tokens)
│   │                              - All component styles
│   │                              - Dark theme with glass effects
│   │                              - Animations
│   │
│   ├── api/                    ← Backend communication:
│   │   ├── client.ts               - Axios HTTP client
│   │   │                             JWT interceptor
│   │   └── ws.ts                   - WebSocket client
│   │                                 Exponential backoff reconnect
│   │
│   ├── context/                ← Global state management:
│   │   ├── AuthContext.tsx          - Login/logout/user state
│   │   ├── NotificationContext.tsx  - Toast notifications
│   │   └── ScanWorkspaceContext.tsx - Scan state (23 action types)
│   │
│   ├── types/                  ← TypeScript type definitions:
│   │   └── cytoscape.d.ts          - Types for graph library
│   │
│   ├── components/             ← Reusable UI parts:
│   │   ├── ProtectedRoute.tsx      - Auth guard component
│   │   ├── AdminRoute.tsx          - Admin-only guard
│   │   ├── ProgressBar.tsx         - Loading bar (0-100%)
│   │   ├── Chip.tsx                - Toggle filter chip
│   │   ├── EventLog.tsx            - Activity log display
│   │   ├── FindingsTable.tsx       - Sortable data table
│   │   └── NotificationToast.tsx   - Popup notifications
│   │   │
│   │   └── workspace/          ← Scan workspace components:
│   │       ├── MetricCards.tsx         - KPI cards
│   │       ├── PivotDrawer.tsx         - Email pivot slide-in
│   │       ├── PipelineProgress.tsx    - Phase/tool progress
│   │       ├── DeepAnalysisProgress.tsx - Analysis tracking
│   │       ├── CollaboratorModal.tsx   - Share scan modal
│   │       ├── InfrastructureTab.tsx   - Subdomains/IP/DNS/CVE
│   │       ├── IdentityTab.tsx         - Emails/breaches
│   │       ├── SecretsTab.tsx          - GitHub secrets
│   │       ├── ThreatIntelTab.tsx      - Dark web/Telegram
│   │       └── BrandProtectionTab.tsx  - Typosquatting
│   │
│   └── pages/                  ← Full page views (11 pages):
│       ├── Dashboard.tsx            - Command center homepage
│       ├── NewScan.tsx              - Launch reconnaissance form
│       ├── ScanHistory.tsx          - Paginated scan list
│       ├── ScanWorkspace.tsx        - 3-view scan results
│       ├── ScanDetails.tsx          - Detailed findings view
│       ├── Settings.tsx             - User account settings
│       ├── EntityGraph.tsx          - Interactive graph viz
│       ├── AIAssistant.tsx          - AI dork generator
│       ├── Login.tsx                - Login form
│       ├── Register.tsx             - Registration form
│       └── AdminUsers.tsx           - Admin user management
│
└── dist/                       ← Built output (what goes to production)
    └── assets/
        ├── index-BSaSp9hq.js       - Bundled JavaScript
        └── index-BUnFiDfr.css      - Bundled CSS
```

---

# Part 5: Key Concepts Explained Simply

## What is a REST API?

Imagine a restaurant menu. Each item on the menu (a URL like `/api/scans`) has specific actions you can take:
- **GET** = "What's on the menu?" (read data)
- **POST** = "I'd like to order this." (create new data)
- **PATCH** = "Can you modify my order?" (update data)
- **DELETE** = "Cancel my order." (remove data)

Every action returns a status code:
- **200** = "Here you go." (success)
- **201** = "Created successfully."
- **202** = "Accepted, processing in background."
- **400** = "You made a bad request." (client error)
- **401** = "You're not logged in." (unauthorized)
- **404** = "Not found."
- **500** = "Something broke on the server." (server error)

## What is a Celery Worker?

Think of it like a kitchen in a restaurant:
- **The Frontend** = The dining area (what customers see)
- **The API Server** = The waiter (takes orders, brings results)
- **Redis** = The order ticket rail (where orders wait)
- **Celery Worker** = The kitchen (cooks the food)
- **PostgreSQL** = The pantry (stores ingredients)

The waiter doesn't cook — they take your order, put it on the rail (Redis), and the kitchen (Celery) picks it up and cooks it. While cooking, the kitchen might call out "order up!" (publish progress), and the waiter delivers it to your table (WebSocket push).

## What is JWT?

A JSON Web Token is a digital ID card. When you log in:
1. The server checks your password
2. If correct, it creates a signed card containing your user ID and role
3. The card is encrypted so it can't be tampered with
4. You send this card with every request to prove who you are
5. The card expires (24 hours), so you need to log in again

## Why Async?

"Async" means doing multiple things without waiting for each to finish. Instead of:
```
1. Ask crt.sh for subdomains → wait 2 seconds → get result
2. Ask subfinder for subdomains → wait 5 seconds → get result
3. Ask DNS for resolution → wait 3 seconds → get result
```
(= 10 seconds total, sequential)

Async lets it do:
```
1. Ask ALL sources at once → 
2. Each result arrives whenever it's ready →
```
(= 5 seconds total, parallel, limited by the slowest source)

Python achieves this with `async`/`await` keywords and `asyncio`. The deep analysis phase takes this further — all 7 collectors run in parallel threads.

## What is the Correlation Engine?

After scans collect findings, the Correlation Engine draws lines between them:

```
subdomain "mail.example.com" ──RESOLVES_TO──► IP "93.184.216.34"
                                                     │
                                                     ├──HAS_PORT──► "SMTP (port 25)"
                                                     │
                                                     └──HAS_VULNERABILITY──► CVE-2024-1234

email "admin@example.com" ──BREACHED_IN──► BREACH "Collection #1"
```

This creates a navigable graph — you can click from a subdomain to its IP, see what ports are open, and check if any of those services have known vulnerabilities.

---

# Quick Reference: Where Things Are

| You Want To... | File/Folder |
|---|---|
| Add a new data source | `backend/collectors/<category>/` |
| Add a new API endpoint | `backend/app/api/scans.py` |
| Add a new page | `frontend/src/pages/` |
| Change the database schema | `backend/app/models/` + run alembic |
| Add a new Celery task | `backend/app/workers/` |
| Change how data is displayed | `frontend/src/components/workspace/` |
| Add API keys | `backend/.env` |
| Change backend settings | `backend/app/config.py` |
| Change Docker setup | `docker-compose.yml` |
| Understand entity types | `backend/app/schemas/enums.py` |
| See all API routes | `backend/app/api/router.py` |
| See the CSS design system | `frontend/src/index.css` |
| Configure frontend URLs | `frontend/.env` |

---

*Generated: 2026-07-20 | Total project: ~60,000+ lines of code across ~100+ files*
