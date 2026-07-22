# Deployment Guide

## Production stack

- **Postgres 16** — primary store for scans, findings, entity links, AI queries.
- **Redis 7** — Celery broker + result backend + pub/sub for live progress events.
- **FastAPI (uvicorn)** — HTTP API + WebSocket endpoint. Run behind a reverse proxy (nginx, Caddy, Traefik) for TLS.
- **Celery worker** — runs scans asynchronously. Scale horizontally by adding more worker replicas; the platform is stateless.
- **Frontend** — static SPA, served by any static host (nginx, Caddy, Vercel, Netlify, S3 + CloudFront).

`docker-compose.yml` ships a working local arrangement of all four. For production we recommend:

1. Managed Postgres (RDS, Cloud SQL, Supabase) — enables point-in-time recovery.
2. Managed Redis (ElastiCache, Memorystore) — keeps the pub/sub channel outside the worker fleet.
3. Two stateless services behind a load balancer: `backend` (uvicorn) and `worker` (Celery). Scale independently.
4. A separate static host for the frontend so you can invalidate the SPA independently of the API.

## Environment setup

1. Generate a strong API key:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. Provision API keys for the data sources you intend to use (see README table). Each can be rotated independently.

3. Set `APP_ENV=production` in the backend environment so the startup validator refuses to run with missing keys or the dev default API key.

## Migrations

In development the backend auto-creates tables via `Base.metadata.create_all` on startup. In production you **must** run migrations explicitly so schema changes are auditable and reproducible:

```bash
# Inside the backend container
docker compose exec backend alembic upgrade head

# To roll back one revision
docker compose exec backend alembic downgrade -1

# To generate a new migration after a model change
docker compose exec backend alembic revision --autogenerate -m "describe the change"
```

The current migration set:

- `20260618_0002_add_target_usernames` — adds `target_usernames` to scans.
- `20260620_0003_add_tsvector_to_findings` — adds the GIN-indexed `tsvector` column for full-text search.

## Running the stack

```bash
# Production build, secrets from .env / secrets manager
docker compose -f docker-compose.yml up -d

# Verify
docker compose ps                 # all services healthy
curl -s http://localhost:8000/health
# {"status":"ok","database":"ok","redis":"ok"}

# Tail the worker
docker compose logs -f worker
```

## Reverse proxy

Nginx example (TLS termination + WebSocket upgrade):

```nginx
upstream backend {
    server backend:8000;
}

server {
    listen 443 ssl http2;
    server_name osint.example.com;

    ssl_certificate     /etc/letsencrypt/live/osint.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/osint.example.com/privkey.pem;

    location / {
        proxy_pass         http://backend;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }

    # WebSocket upgrade headers
    location /ws/ {
        proxy_pass         http://backend;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade           $http_upgrade;
        proxy_set_header   Connection        "upgrade";
        proxy_set_header   Host              $host;
        proxy_read_timeout 86400;  # long-lived connection
    }
}
```

## Key rotation

The single static API key is acceptable for a single-user tool, but rotating it should not require a code change.

1. Add the new key as an alias (future work: accept multiple keys in `Settings`).
2. Update clients / `.env`.
3. Remove the old key.

For production multi-user setups, replace `app/core/security.py` with a JWT-based auth flow before exposing the platform publicly.

## Observability

- **Logs** — every log line is JSON-formatted with a `request_id` correlation header. Pipe stdout to your log collector (Loki, CloudWatch, Datadog).
- **Health** — `GET /health` reports DB and Redis status. Wire into your uptime monitor.
- **Worker health** — `celery -A app.workers.celery_app inspect ping` reports live workers.

## Backups

- **Postgres** — enable automated daily snapshots. The `findings` table is the largest; back-restore time is dominated by its size.
- **Redis** — pub/sub channels are ephemeral and do not need persistence. The Celery result backend keys can be allowed to expire normally.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `API key ... is still set to the development default` on boot | Set `APP_ENV` to anything other than `production`, or change `API_KEY` to a strong value. |
| `Missing required API keys: ...` | Add the listed keys to `.env` or unset `APP_ENV=production`. |
| Worker stays idle, scans queue but never run | `docker compose logs worker` for the actual error. Usually a missing API key for a collector. |
| Frontend shows "401 Unauthorized" on export | The export endpoint now uses `apiClient` (X-API-Key preserved). Confirm `VITE_API_KEY` is set in `frontend/.env`. |
| WebSocket won't connect with 1008 | API key missing or wrong. Pass `?api_key=...` in the URL or use the `Sec-WebSocket-Protocol: api-key.<value>` header. |

## Scaling notes

- **CPU-bound** scans (subfinder, dns resolver) — add worker replicas.
- **API-bound** scans (Shodan, Censys, Hunter) — workers are already async; scale by replica count.
- **Database** — `findings` is append-only and indexed by `(scan_id, vector_type, entity_type, severity)`. Add a covering index if your dashboard filters slow down.
- **Redis** — pub/sub is fan-out; a single Redis instance handles thousands of subscribers comfortably. Move to a managed Redis cluster when scan counts climb.