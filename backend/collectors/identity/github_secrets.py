"""GitHub leaked secrets collector.

Uses PyGithub to search public repositories for leaked secrets belonging
to the target organization. Searches for API keys, tokens, passwords, and
other sensitive data patterns.

GitHub Token: https://github.com/settings/tokens (free, read-only public repos)
Docs: https://docs.github.com/en/rest/search#search-code
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from collectors.base import BaseCollector, CollectorConfigurationError, CollectorMetadata
from app.config import settings


class GitHubSecretsCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="github_secrets",
        vector="IDENTITY",
        description="GitHub public repo leaked secrets scanner (PyGithub)",
        passive=True,
        requires_api_key=True,
        api_key_env="GITHUB_TOKEN",
    )

    # Patterns that indicate leaked secrets
    SECRET_PATTERNS = [
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "API_KEY"),
        (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "SECRET_KEY"),
        (r'(?:access[_-]?token|accesstoken)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "ACCESS_TOKEN"),
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?', "PASSWORD"),
        (r'(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', "AWS_ACCESS_KEY"),
        (r'(?:aws[_-]?secret[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', "AWS_SECRET_KEY"),
        (r'(?:slack[_-]?token)\s*[:=]\s*["\']?(xox[bprs]-[a-zA-Z0-9-]+)["\']?', "SLACK_TOKEN"),
        (r'(?:private[_-]?key|privatekey)\s*[:=]\s*["\']?-----BEGIN', "PRIVATE_KEY"),
        (r'(?:database[_-]?url|db[_-]?url)\s*[:=]\s*["\']?(\w+://[^"\'\s]+)["\']?', "DATABASE_URL"),
        (r'(?:connection[_-]?string)\s*[:=]\s*["\']?([^"\'\s;]{20,})["\']?', "CONNECTION_STRING"),
        (r'(?:client[_-]?secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "CLIENT_SECRET"),
        (r'(?:jwt[_-]?secret|jwtsecret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "JWT_SECRET"),
        (r'(?:encryption[_-]?key|encryptionkey)\s*[:=]\s*["\']?([A-Za-z0-9_\-/+=]{16,})["\']?', "ENCRYPTION_KEY"),
        (r'(?:signing[_-]?key|signingkey)\s*[:=]\s*["\']?([A-Za-z0-9_\-/+=]{16,})["\']?', "SIGNING_KEY"),
        (r'(?:oauth[_-]?token|oauthtoken)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "OAUTH_TOKEN"),
        (r'(?:refresh[_-]?token|refreshtoken)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "REFRESH_TOKEN"),
        (r'(?:bearer[_-]?token|bearer)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{16,})["\']?', "BEARER_TOKEN"),
        (r'(?:auth[_-]?token|authtoken)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "AUTH_TOKEN"),
        (r'(?:api[_-]?secret|apisecret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "API_SECRET"),
        (r'(?:consumer[_-]?key|consumerkey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "CONSUMER_KEY"),
        (r'(?:consumer[_-]?secret|consumersecret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', "CONSUMER_SECRET"),
        (r'(?:github[_-]?token|github_token)\s*[:=]\s*["\']?(ghp_[A-Za-z0-9]{36,})["\']?', "GITHUB_TOKEN"),
        (r'(?:stripe[_-]?secret|stripe_secret)\s*[:=]\s*["\']?(sk_(?:live|test)_[A-Za-z0-9]{24,})["\']?', "STRIPE_SECRET"),
        (r'(?:mailgun[_-]?api[_-]?key)\s*[:=]\s*["\']?(key-[A-Za-z0-9]{32,})["\']?', "MAILGUN_KEY"),
        (r'(?:twilio[_-]?auth[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9]{32,})["\']?', "TWILIO_TOKEN"),
        (r'(?:sendgrid[_-]?api[_-]?key)\s*[:=]\s*["\']?(SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,})["\']?', "SENDGRID_KEY"),
        (r'(?:heroku[_-]?api[_-]?key)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{36})["\']?', "HEROKU_KEY"),
        (r'(?:digitalocean[_-]?token|do[_-]?token)\s*[:=]\s*["\']?(dop_v1_[A-Za-z0-9]{64})["\']?', "DO_TOKEN"),
        (r'(?:npm[_-]?token|npm_token)\s*[:=]\s*["\']?(npm_[A-Za-z0-9]{36})["\']?', "NPM_TOKEN"),
        (r'(?:pypi[_-]?token|pypi_token)\s*[:=]\s*["\']?(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})["\']?', "PYPI_TOKEN"),
        (r'(?:ssh[_-]?rsa|rsa[_-]?private)\s*[:=]\s*["\']?-----BEGIN', "SSH_PRIVATE_KEY"),
        (r'(?:BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY)', "PRIVATE_KEY"),
    ]

    # Comprehensive credential keyword list — used for the proximity check
    # (Option C). A real secret almost always has one of these words near it.
    CREDENTIAL_KEYWORDS = [
        # Generic credential words
        "api_key", "apikey", "api-key",
        "api_secret", "apisecret", "api-secret",
        "secret", "secret_key", "secretkey",
        "password", "passwd", "pwd",
        "token", "access_token", "auth_token", "bearer", "bearer_token",
        "client_secret", "clientsecret", "client-secret",
        "private_key", "privatekey", "private-key",
        "encryption_key", "signing_key", "jwt_secret",
        "oauth", "refresh_token",
        "credential", "credentials",
        # Cloud provider prefixes
        "akia",            # AWS access key
        "aws_access", "aws_secret",
        "ghp_",            # GitHub PAT
        "sk_live", "sk_test",  # Stripe
        "sg.",             # SendGrid
        "xoxb-", "xoxp-",  # Slack
        # DB / connection strings
        "database_url", "db_url", "dburl",
        "connection_string", "conn_str",
        "mongodb://", "mongodb+srv://",
        "postgres://", "postgresql://",
        "mysql://", "redis://",
        "mongodb", "mysql", "postgres", "postgresql",
        # Provider-specific
        "slack_token", "github_token",
        "mailgun", "twilio", "sendgrid", "heroku", "digitalocean",
        "stripe", "npm_token", "pypi_token",
        "consumer_key", "consumer_secret",
        # File markers
        "begin private key", "begin rsa", "begin openssh",
        "-----begin",       # PEM headers
        "passphrase",
        # Auth headers / patterns
        "authorization:", "x-api-key",
    ]

    # File extensions that are UNLIKELY to contain real source code with secrets
    # (binary data, scientific data, images). Used by Option A — we skip
    # these UNLESS the content contains a credential keyword.
    NON_CODE_EXTENSIONS = {
        # Scientific / sequence data
        ".fasta", ".fa", ".fna", ".ffa", ".frn",
        ".fastq", ".fq",
        ".faa", ".ffn",
        ".gb", ".gbk", ".gff", ".gtf", ".bed",
        # Generic data
        ".csv", ".tsv",
        ".parquet", ".arrow", ".orc", ".avro",
        ".hdf5", ".h5", ".hdf",
        # Binary / archives
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".o", ".a",
        ".class", ".jar", ".war",
        # Compiled / object
        ".pyc", ".pyo", ".pyd",
        # Media
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac", ".ogg",
    }

    # Publisher/committer indicators that suggest auto-generated content
    # (low-signal — typically GitHub Actions commits, not human leaks)
    AUTO_GENERATED_AUTHORS = {
        "noreply@github.com",
        "github-actions[bot]@users.noreply.github.com",
        "dependabot[bot]@users.noreply.github.com",
        "renovate[bot]@users.noreply.github.com",
    }

    REPO_LIMIT = 50       # Max repos to collect
    CODE_LIMIT = 100      # Max code matches per query (fetching decoded_content is slow)
    PER_PAGE = 100        # Max per-page (GitHub API cap is 100)

    # Max seconds to spend on a single query's pagination loop before moving on
    QUERY_TIMEOUT = 60

    # Proximity window in lines — credential keyword must be within this many
    # lines of the target domain/brand mention to count as "near".
    NEAR_WINDOW_LINES = 5

    def __init__(self):
        super().__init__()
        self._github = None

    def _get_github(self):
        """Lazy-initialize PyGithub client.

        Uses a custom retry policy that does NOT retry on 403 — GitHub code
        search returns 403 for content-restricted queries that will *never*
        succeed (e.g. ``"domain" AKIA``).  The default GithubRetry retries 10
        times on 403, wasting minutes per query.  We retry only on server
        errors (5xx) and true rate limits (429).
        """
        if self._github is not None:
            return self._github
        try:
            from github import Github, GithubRetry
            token = (settings.GITHUB_TOKEN or "").strip()
            if not token:
                raise CollectorConfigurationError(
                    "GitHub secret search is unavailable: configure GITHUB_TOKEN"
                )
            retry = GithubRetry(total=3, status_forcelist=[429, 500, 502, 503, 504])
            self._github = Github(token, per_page=self.PER_PAGE, retry=retry)
        except ImportError:
            raise CollectorConfigurationError(
                "GitHub secret search is unavailable: PyGithub is not installed"
            )
        return self._github

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Search GitHub for leaked secrets related to the target domain."""
        g = self._get_github()
        if g is None:
            return []

        # Extract org/brand name from domain
        # e.g., "utm.tn" → "utm", "example.com" → "example"
        brand = target.split(".")[0].lower()
        domain_clean = target.lower()  # GitHub search doesn't support escaped dots

        results: List[Dict[str, Any]] = []

        # Run the blocking PyGithub calls in a thread pool
        import asyncio
        loop = asyncio.get_running_loop()

        try:
            # 1. Search for repos belonging to the organization
            repos = await loop.run_in_executor(
                None, self._search_repos, g, brand, domain_clean
            )
            for repo in repos:
                results.append({
                    "type": "repo_found",
                    "repo_name": repo.full_name,
                    "repo_url": repo.html_url,
                    "description": repo.description or "",
                    "language": repo.language or "",
                    "stars": repo.stargazers_count,
                    "target_brand": brand,
                })

            # 2. Search code for secrets mentioning the domain
            code_matches = await loop.run_in_executor(
                None, self._search_code, g, domain_clean, brand
            )
            for match in code_matches:
                results.append(match)

        except CollectorConfigurationError:
            raise
        except Exception as e:
            print(f"[github_secrets] error: {e}")
            return []

        return results

    def _search_repos(self, g, brand: str, domain: str):
        """Search repositories containing the exact target domain.

        Brand-only README searches are too broad for short names such as
        ``utm``. Repository context is therefore anchored to the domain.
        """
        from github import GithubException
        result: list = []
        try:
            repos = g.search_repositories(
                query=f'"{domain}" in:description,readme',
                sort="stars",
                order="desc",
            )
            page = 0
            while len(result) < self.REPO_LIMIT:
                try:
                    items = repos.get_page(page)
                except GithubException as exc:
                    if exc.status == 401:
                        raise CollectorConfigurationError(
                            "GitHub authentication failed: check GITHUB_TOKEN"
                        ) from exc
                    if exc.status == 403:
                        print(f"[github_secrets] repo search 403/rate-limited, returning {len(result)} repos so far")
                    else:
                        print(f"[github_secrets] repo search GitHub error {exc.status}, returning {len(result)} repos so far")
                    break
                except Exception:
                    break
                if not items:
                    break
                for repo in items:
                    result.append(repo)
                    if len(result) >= self.REPO_LIMIT:
                        break
                page += 1
            return result
        except GithubException as exc:
            if exc.status == 401:
                raise CollectorConfigurationError(
                    "GitHub authentication failed: check GITHUB_TOKEN"
                ) from exc
            if exc.status == 403:
                print(f"[github_secrets] repo search 403/rate-limited, returning {len(result)} repos so far")
                return result
            print(f"[github_secrets] repo search error: {exc}")
            return []
        except Exception as e:
            print(f"[github_secrets] repo search error: {e}")
            return []

    def _search_code(self, g, domain_clean: str, brand: str):
        """Search code for secrets mentioning the target domain, paginating up to CODE_LIMIT.

        Each code result's ``decoded_content`` triggers a separate API call to
        download the file contents. To avoid hanging the pipeline for 20+ minutes
        on queries that return thousands of results, we:
          - Limit to CODE_LIMIT (100) per query.
          - Enforce a QUERY_TIMEOUT (60s) deadline per query pagination loop.
          - Wrap decoded_content in a try/except so one slow fetch doesn't block
            the remaining items.

        Filtering (in order):
          - Option A: Skip non-code file extensions (data/binary files) UNLESS
            the content contains a credential keyword.
          - Option C: Drop files entirely if no credential keyword is found
            anywhere in the content. Among files with keywords, record whether
            the keyword is within NEAR_WINDOW_LINES of the domain/brand mention.
        """
        from github import GithubException

        results = []

        # Build search queries for different secret types
        search_queries = [
            f'"{domain_clean}" api_key',
            f'"{domain_clean}" secret',
            f'"{domain_clean}" token',
            f'"{domain_clean}" password',
            f'"{domain_clean}" DATABASE_URL',
            f'"{brand}" AKIA',
        ]

        seen_urls = set()
        skipped_no_keyword = 0
        skipped_non_code = 0
        kept_near = 0
        kept_far = 0

        for query in search_queries:
            try:
                code_results = g.search_code(query=query)
            except GithubException as exc:
                if exc.status == 401:
                    raise CollectorConfigurationError(
                        "GitHub authentication failed: check GITHUB_TOKEN"
                    ) from exc
                if exc.status == 403:
                    print(f"[github_secrets] code search 403 on '{query[:40]}...', skipping")
                else:
                    print(f"[github_secrets] code search error {exc.status} on '{query[:40]}...', skipping")
                continue
            except Exception as e:
                print(f"[github_secrets] code search error for '{query[:40]}...': {e}")
                continue

            query_count = 0
            page = 0
            deadline = time.monotonic() + self.QUERY_TIMEOUT
            while query_count < self.CODE_LIMIT and time.monotonic() < deadline:
                try:
                    items = code_results.get_page(page)
                except GithubException as exc:
                    if exc.status == 401:
                        raise CollectorConfigurationError(
                            "GitHub authentication failed: check GITHUB_TOKEN"
                        ) from exc
                    if exc.status == 403:
                        print(f"[github_secrets] code search 403 on '{query[:40]}...', stopping")
                    else:
                        print(f"[github_secrets] code search error {exc.status} on '{query[:40]}...', stopping")
                    break
                except Exception:
                    break
                if not items:
                    break
                for item in items:
                    if item.html_url in seen_urls:
                        continue
                    seen_urls.add(item.html_url)
                    query_count += 1
                    if query_count > self.CODE_LIMIT:
                        break
                    if time.monotonic() >= deadline:
                        break

                    file_path = item.path or ""

                    # ── Option A: skip non-code extensions unless we have a
                    #    strong reason to look at them ─────────────────────
                    ext = self._get_extension(file_path)
                    is_non_code = ext in self.NON_CODE_EXTENSIONS

                    # Fetch file content — wrap so one slow/unavailable file
                    # doesn't block the rest of the query's items.
                    try:
                        raw = item.decoded_content
                        content = raw.decode("utf-8", errors="ignore") if raw else ""
                    except Exception:
                        content = ""

                    has_keyword = self._has_credential_keyword(content)

                    if is_non_code and not has_keyword:
                        skipped_non_code += 1
                        continue

                    # ── Option C: drop files with NO credential keyword ──
                    if not has_keyword:
                        skipped_no_keyword += 1
                        continue

                    # Classify specific secret type via regex patterns
                    secret_type = self._classify_secret(content)

                    # Measure proximity: keyword within N lines of domain/brand
                    proximity = self._measure_proximity(
                        content, domain_clean, brand
                    )

                    if proximity == "near":
                        kept_near += 1
                    else:
                        kept_far += 1

                    # Publisher email check (low-signal auto-generated content)
                    publisher_email = self._get_publisher_email(item)
                    is_auto_generated = publisher_email in self.AUTO_GENERATED_AUTHORS

                    results.append({
                        "type": "code_match",
                        "repo_name": item.repository.full_name,
                        "repo_url": item.repository.html_url,
                        "file_path": file_path,
                        "file_url": item.html_url,
                        "secret_type": secret_type,
                        "target_brand": brand,
                        "target_domain": domain_clean,
                        "domain_proximity": proximity,
                        "publisher_email": publisher_email,
                        "auto_generated": is_auto_generated,
                    })
                page += 1

                # If we hit the deadline mid-page, log it once
                if time.monotonic() >= deadline:
                    print(f"[github_secrets] query '{query[:40]}...' timed out after "
                          f"{self.QUERY_TIMEOUT}s with {query_count} items, moving on")

            if time.monotonic() >= deadline and query_count == 0:
                print(f"[github_secrets] query '{query[:40]}...' timed out before "
                      f"fetching any results")

        # Summary log so we can tune filters later
        if results or skipped_no_keyword or skipped_non_code:
            print(f"[github_secrets] filter summary: "
                  f"kept_near={kept_near} kept_far={kept_far} "
                  f"skipped_no_keyword={skipped_no_keyword} "
                  f"skipped_non_code={skipped_non_code}")

        return results

    def _get_extension(self, file_path: str) -> str:
        """Get the lowercase file extension including the dot, or '' if none."""
        import os
        _, ext = os.path.splitext(file_path.lower())
        return ext

    def _has_credential_keyword(self, content: str) -> bool:
        """Return True if any credential keyword appears in the content.

        Case-insensitive substring search across the full content. We do NOT
        require proximity at this stage — proximity is measured separately.
        """
        if not content:
            return False
        content_lower = content.lower()
        for kw in self.CREDENTIAL_KEYWORDS:
            if kw in content_lower:
                return True
        return False

    def _measure_proximity(self, content: str, domain: str, brand: str) -> str:
        """Measure how close a credential keyword is to a domain/brand mention.

        Returns:
            "near"   — keyword within NEAR_WINDOW_LINES of domain or brand
            "far"    — keyword present but no nearby domain/brand
            "domain_only" — domain present but no keyword at all
        """
        if not content:
            return "far"

        lines = content.splitlines()
        if not lines:
            return "far"

        # Domain matches are literal. Brand matches must be standalone tokens;
        # substring checks make short brands match unrelated identifiers.
        domain_lower = domain.lower()
        brand_pattern = re.compile(
            rf"(?<![a-z0-9]){re.escape(brand.lower())}(?![a-z0-9])"
        ) if brand else None

        # Find lines containing the domain or a standalone brand token.
        target_lines = []
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if domain_lower in line_lower or (
                brand_pattern is not None and brand_pattern.search(line_lower)
            ):
                target_lines.append(i)

        # Find lines containing any credential keyword
        keyword_lines = []
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(kw in line_lower for kw in self.CREDENTIAL_KEYWORDS):
                keyword_lines.append(i)

        if not keyword_lines:
            return "domain_only"

        if not target_lines:
            return "far"

        window = self.NEAR_WINDOW_LINES
        for tl in target_lines:
            for kl in keyword_lines:
                if abs(tl - kl) <= window:
                    return "near"
        return "far"

    def _get_publisher_email(self, item) -> str:
        """Get the last commit's author email for a code search result.

        NOTE: We do NOT call get_commits() here because it adds a full API
        call per code match item, making the scan ~5x slower. The proximity
        + secret_type signals already provide accurate severity tuning.
        This method is kept as a hook for future use with cheaper signals
        (e.g. the repo's primary language or default branch metadata).
        """
        return ""

    def _classify_secret(self, content: str) -> str:
        """Classify the type of secret found in code content."""
        for pattern, secret_type in self.SECRET_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                return secret_type
        return "UNKNOWN_SECRET"

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize GitHub secrets data into standard Finding format.

        For code matches, severity and confidence are tuned by the proximity
        and publisher signals captured during collect():
          - Specific secret type (AWS_*, PRIVATE_KEY, DATABASE_URL, etc.) +
            near proximity + human publisher  → HIGH / 0.95
          - Specific secret type + far proximity + human publisher → MEDIUM / 0.55
          - Specific secret type + far proximity + auto publisher → LOW / 0.4
          - UNKNOWN_SECRET (no specific pattern) + near + human  → MEDIUM / 0.6
          - UNKNOWN_SECRET + far / auto  → LOW / 0.3
        """
        raw_type = raw.get("type", "")

        if raw_type == "repo_found":
            return {
                "entity_type": "GITHUB_REPO",
                "entity_value": raw["repo_url"],
                "severity": "INFO",
                "confidence": 0.7,
                "tags": ["github", "repository-search-match", "search-strategy:exact-domain-v2"],
                "normalized_data": {
                    "repo_name": raw["repo_name"],
                    "repo_url": raw["repo_url"],
                    "description": raw.get("description", ""),
                    "language": raw.get("language", ""),
                    "stars": raw.get("stars", 0),
                    "target_brand": raw.get("target_brand", ""),
                    "search_strategy": "exact_domain_v2",
                    "source": "github_secrets",
                },
            }

        # code_match
        secret_type = raw.get("secret_type", "UNKNOWN")
        proximity = raw.get("domain_proximity", "far")
        auto_generated = bool(raw.get("auto_generated"))

        # Any successful regex classification is more specific than the broad
        # keyword-only fallback. Keeping this rule derived from the classifier
        # prevents newly added patterns from silently receiving UNKNOWN scores.
        specific = secret_type not in ("UNKNOWN", "UNKNOWN_SECRET")

        # ── Severity logic ──
        if specific and proximity == "near" and not auto_generated:
            severity = "HIGH"
            confidence = 0.95
        elif specific and proximity == "near" and auto_generated:
            severity = "MEDIUM"
            confidence = 0.7
        elif specific and proximity == "far" and not auto_generated:
            severity = "MEDIUM"
            confidence = 0.55
        elif specific and proximity == "far" and auto_generated:
            severity = "LOW"
            confidence = 0.4
        elif not specific and proximity == "near" and not auto_generated:
            # UNKNOWN_SECRET but keyword IS near the domain — likely real
            severity = "MEDIUM"
            confidence = 0.6
        elif not specific and proximity == "near" and auto_generated:
            severity = "LOW"
            confidence = 0.4
        else:
            # UNKNOWN_SECRET + far / no proximity
            severity = "LOW"
            confidence = 0.3

        return {
            "entity_type": "LEAKED_SECRET",
            "entity_value": f"{raw['repo_url']}::{raw['file_path']}",
            "severity": severity,
            "confidence": confidence,
            "tags": [
                "github",
                "potential-secret",
                secret_type.lower(),
                f"proximity:{proximity}",
                "classifier:v2",
            ],
            "normalized_data": {
                "repo_name": raw["repo_name"],
                "repo_url": raw["repo_url"],
                "file_path": raw["file_path"],
                "file_url": raw["file_url"],
                "secret_type": secret_type,
                "target_brand": raw.get("target_brand", ""),
                "target_domain": raw.get("target_domain", ""),
                "domain_proximity": proximity,
                "publisher_email": raw.get("publisher_email", ""),
                "auto_generated": auto_generated,
                "classifier_version": 2,
                "source": "github_secrets",
            },
        }
