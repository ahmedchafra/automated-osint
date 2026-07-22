# GitHub Token Setup for Secrets Scanner

## How to create a Personal Access Token (PAT)

1. Go to https://github.com/settings/tokens
2. Click **Generate new token** (classic) — **NOT** fine-grained
3. Set **Expiration** to your preference (90 days recommended)
4. Select scopes — you need:
   - **repo** (Full control of private repositories) — this is the ONLY required scope
   - That's it. The scanner searches public code, but GitHub requires a repo scope to access the code search API

## Why classic (not fine-grained)?

- Fine-grained tokens have restricted repository access (you'd need to add every repo you want to scan)
- Classic PATs with `repo` scope work for both public and private repo searches
- Fine-grained tokens also don't support the legacy code search API we use

## Add to .env

```
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Rate limits

- Authenticated: 30 requests/minute
- Unauthenticated: 5 requests/minute (current, why you see 421 errors)
