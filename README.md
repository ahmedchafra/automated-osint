<p align="center">
  <img src="frontend/src/assets/hero.png" alt="OSINT Platform" width="600"/>
</p>

<h1 align="center">🔍 OSINT Reconnaissance Platform</h1>

<p align="center">
  <b>Automated open-source intelligence — domains, IPs, emails, secrets, and brand threats</b><br>
  <i>Dockerized • 30+ collectors • Real-time WebSocket updates</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/backend-FastAPI-009688?logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/frontend-React-61DAFB?logo=react&logoColor=white" alt="React"/>
  <img src="https://img.shields.io/badge/worker-Celery-37814A?logo=celery&logoColor=white" alt="Celery"/>
  <img src="https://img.shields.io/badge/database-PostgreSQL-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/cache-Redis-DC382D?logo=redis&logoColor=white" alt="Redis"/>
  <img src="https://img.shields.io/badge/container-Docker-2496ED?logo=docker&logoColor=white" alt="Docker"/>
</p>

---

## ✨ What It Does

Run a full reconnaissance pipeline against any domain, IP address, or organization — automatically. The platform discovers subdomains, finds email addresses, scans for leaked secrets, profiles web technologies, detects lookalike domains, monitors brand mentions, and visualizes the relationship graph.

**One command to start. One click to scan. Real-time results.**

| Capability | Example Output |
|---|---|
| 🏗️ **Infrastructure** | Subdomains, IPs, DNS records, SSL certs, HTTP headers |
| 📧 **Identity** | Emails (Hunter.io), account existence (holehe), social profiles (maigret) |
| 🔑 **Secrets** | Leaked API keys, passwords, tokens on GitHub |
| 🌐 **Web OSINT** | Tech stack (BuiltWith), CVEs by version, Wayback Machine history |
| 🎭 **Brand Protection** | Lookalike domains (dnstwist), Telegram monitoring |
| 🧠 **AI Assistant** | Generate Google dorks from natural language (Groq-powered) |
| 🔗 **Entity Graph** | Interactive visualization of all connections |
| 📊 **Reports** | Export findings as PDF |

---

## 🚀 Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) 24+ and Docker Compose v2
- 4 GB RAM minimum, 8 GB+ recommended

### Setup

```bash
# Clone the repo
git clone https://github.com/ahmedchafra/automated-osint.git
cd automated-osint

# Configure API keys (optional — works without them too)
cp backend/.env.example backend/.env
# Edit backend/.env with your API keys (see below)

# Start the backend (PostgreSQL, Redis, API, worker)
docker-compose up -d --build

# In a separate terminal, start the frontend (requires Node.js 18+)
cd frontend
npm install
npm run dev
```

### Open the App

| URL | What |
|---|---|
| http://localhost:5173 | 🖥️ Frontend — register an account, start scanning |
| http://localhost:8000/docs | 📚 API docs (Swagger) |

---

## 🔧 Configuring API Keys

Collectors are organized in tiers. The platform works **without any API keys** using free collectors (DNS, crt.sh, subfinder, holehe, maigret, dnstwist, Wayback Machine, etc.). For richer data, configure these keys:

| Key | Service | What You Get | Sign Up |
|---|---|---|---|
| `HUNTER_API_KEY` | Hunter.io | Domain email discovery (50 req/month free) | [hunter.io](https://hunter.io) |
| `GITHUB_TOKEN` | GitHub | Secret scanning | [GitHub tokens](https://github.com/settings/tokens) |
| `BUILTWITH_API_KEY` | BuiltWith | Web technology profiling (50 free) | [builtwith.com](https://builtwith.com) |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | Censys | SSL/IP intelligence (250 free credits) | [censys.io](https://censys.io) |

The **theHarvester** collector is different — it uses 29+ API keys (VirusTotal, URLScan, FullHunt, Shodan, and many more). Each key you add enables another source. Most have free tiers:

| theHarvester Source | Env Variable | Free Limit |
|---|---|---|
| VirusTotal | `VT_API_KEY` | 500 lookups/day |
| URLScan | `URLSCAN_API_KEY` | Free rate-limited |
| FullHunt | `FULLHUNT_API_KEY` | 50 queries |
| SecurityTrails | `SECURITYTRAILS_KEY` | 50 queries/month |
| OTX (AlienVault) | `OTX_API_KEY` | Free registration |
| DNSDumpster | `DNSDUMPSTER_API_KEY` | 50 queries/day |
| BeVigil | `BEVIGIL_API_KEY` | 50 queries/month |
| + 20+ more | See `.env.example` | |

Edit `backend/.env` with your keys, then restart:

```bash
docker-compose restart backend worker
```

> 🔑 **Full documentation** on every API key and collector is in [DOCUMENTATION.md](DOCUMENTATION.md#6-api-keys--which-ones-you-need).

---

## 🧭 How to Use

### 1. Register & Log In

Open the frontend, create an account, and log in. The first user is an admin.

### 2. Start a Scan

Click **"New Scan"**, choose a target type:

```
🌐 example.com  →  Full domain pipeline
📡 8.8.8.8      →  IP-focused pipeline (Shodan/Censys/ASN)
🏢 Acme Inc     →  Org discovery → domain pipeline
```

### 3. Explore Results

The scan workspace has tabbed views:

| Tab | What You'll Find |
|---|---|
| **Dashboard** | Status, severity breakdown, timeline |
| **Infrastructure** | Subdomains, IPs, tech stack, deep analysis |
| **Identity** | Emails, breach status, social profiles |
| **Secrets** | GitHub leaks, exposed credentials |
| **Brand Protection** | Lookalike domains, Telegram brand mentions |
| **Threat Intel** | Combined secret scan + lookalike detection |
| **Web OSINT** | Deep analysis: technologies, CVEs, versions, Wayback URLs |
| **Entity Graph** | Interactive relationship graph of all findings |

### 4. Go Deeper

Click **"Deep Analysis"** on any subdomain to fire 8 collectors + CVE cross-referencing. Pivot from emails to breach checks. Monitor Telegram for brand mentions. Generate AI dorks.

---

## 🏗️ Architecture

```
┌───────────┐    ┌──────────────┐    ┌────────────────┐
│  React    │◄──►│  FastAPI     │◄──►│  Celery Worker │
│  Frontend │ WS │  Backend     │RQ  │  (collectors)  │
├───────────┤    ├──────────────┤    ├────────────────┤
│ :5173     │    │ :8000        │    │ Hunter         │
│           │    │ JWT Auth     │    │ Shodan/Censys  │
│           │    │ REST API     │    │ theHarvester   │
│           │    │ WebSocket    │    │ GitHub Secrets │
│           │    │              │    │ dnstwist       │
│           │    │              │    │ + 25 more...   │
└───────────┘    └──────┬───────┘    └────────────────┘
                        │
                   ┌────▼───────┐
                   │ PostgreSQL │
                   └────────────┘
```

---

## 📦 Project Structure

```
├── docker-compose.yml       # All services defined here
├── backend/
│   ├── Dockerfile           # Python 3.13 container
│   ├── .env.example         # API key template
│   ├── requirements.txt
│   ├── app/
│   │   ├── api/             # FastAPI routes
│   │   ├── workers/         # Celery tasks (scan orchestration)
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Pydantic request/response schemas
│   │   ├── services/        # Business logic, collectors orchestration
│   │   └── core/            # Auth, security, config
│   └── collectors/          # Individual reconnaissance collectors
│       ├── infrastructure/  # DNS, subfinder, http_headers, builtwith...
│       ├── identity/        # hunter_domain, holehe, maigret...
│       └── secrets/         # github_secrets
└── frontend/
    ├── .env                 # VITE_API_URL, VITE_API_KEY
    ├── src/
    │   ├── components/      # React components
    │   ├── pages/           # Route pages
    │   ├── context/         # React context providers
    │   └── api/             # API client + WebSocket
    └── package.json
```

---

## 🛠️ Commands Quick Reference

```bash
docker-compose up -d                 # Start backend services
docker-compose up -d --build         # Rebuild & start (after code changes)
cd frontend && npm run dev           # Start frontend (separate terminal)
docker-compose logs -f               # View all logs
docker-compose logs -f worker        # View worker logs only
docker-compose down                  # Stop all containers
docker-compose down -v               # Factory reset (deletes all data)
docker-compose restart backend worker  # Restart API + worker (after .env changes)
```

---

## 📖 Full Documentation

For a complete walkthrough covering every feature, button, API key, and troubleshooting step, see:

➡️ **[DOCUMENTATION.md](DOCUMENTATION.md)**

Includes:
- Step-by-step usage of every workspace tab
- All API keys with free-tier limits and sign-up links
- Detailed troubleshooting guide
- How to share the app with someone else
- Quick reference cheat sheet

---

## 🧪 How It Looks

| View | Description |
|---|---|
| Dashboard | Scan cards with live progress, severity breakdowns |
| Workspace | Tabbed deep-dive into findings per vector |
| Entity Graph | Interactive Cytoscape graph of connections |
| Pipeline Progress | Real-time WebSocket progress per collector |
| AI Assistant | Natural language → Google dork generation |

---

## 🔒 Security

- JWT-based authentication with role-based access control (Admin / User / Viewer)
- API keys are stored in server-side `.env` only — never exposed to the frontend
- Collaborator system lets you share scans without sharing credentials
- Docker container isolation

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

This project is for authorized security testing, educational purposes, and CTF challenges only. Ensure you have proper authorization before scanning any domain or system.
