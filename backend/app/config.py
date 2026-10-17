from typing import Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # API Security
    API_KEY: str = "osint-local-dev-key-12345"

    # Database / Broker
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/osint_platform"
    REDIS_URL: str = "redis://localhost:6379/0"
    AUTO_CREATE_DB: bool = True

    # Runtime
    APP_ENV: str = "development"
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    # JWT Auth
    JWT_SECRET_KEY: str = "osint-jwt-secret-change-in-production-12345"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # Optional one-time bootstrap. When all three are present and no admin
    # exists, the API creates the first administrator during startup.
    INITIAL_ADMIN_USERNAME: Optional[str] = None
    INITIAL_ADMIN_EMAIL: Optional[str] = None
    INITIAL_ADMIN_PASSWORD: Optional[str] = None

    # Collector API keys — all optional so the platform boots in dev
    # even when only a subset of collectors will be exercised.
    SHODAN_API_KEY: Optional[str] = None
    CENSYS_API_ID: Optional[str] = None
    CENSYS_API_SECRET: Optional[str] = None
    HUNTER_API_KEY: Optional[str] = None
    HIBP_API_KEY: Optional[str] = None
    GROQ_API_KEY: Optional[str] = None
    SERPER_API_KEY: Optional[str] = None
    NVD_API_KEY: Optional[str] = None  # rate-limits NVD from 5 to 50 req / 30s
    GITHUB_TOKEN: Optional[str] = None  # PyGithub token for github_secrets collector
    TG_API_ID: Optional[str] = None     # Telegram API ID (my.telegram.org)
    TG_API_HASH: Optional[str] = None   # Telegram API hash (my.telegram.org)
    TG_SESSION_STRING: Optional[str] = None  # Telethon session string for auth
    AHMIA_DEEP_SCRAPE: bool = False            # deep-scrape .onion pages via Tor SOCKS5

    # ── theHarvester API keys (all optional) ─────────────────────────────
    # These are read by docker-entrypoint.sh and written to
    # ~/.theHarvester/api-keys.yaml. The collector auto-detects sources.
    # Free-tier keys:
    HACKERTARGET_API_KEY: Optional[str] = None    # 50 req/month
    BUFFEROVERUN_API_KEY: Optional[str] = None    # 100 free/month
    VT_API_KEY: Optional[str] = None              # 500 lookups/day
    URLSCAN_API_KEY: Optional[str] = None         # free rate-limited
    OTX_API_KEY: Optional[str] = None             # free registration
    LEAKIX_API_KEY: Optional[str] = None          # 3000 req/month
    DNSDUMPSTER_API_KEY: Optional[str] = None     # 50 queries/day
    SECURITYTRAILS_KEY: Optional[str] = None      # 50 queries/month
    FULLHUNT_API_KEY: Optional[str] = None        # 50 queries
    BEVIGIL_API_KEY: Optional[str] = None         # 50 queries/month
    TOMBA_API_KEY: Optional[str] = None           # 25 searches/month
    BRAVE_API_KEY: Optional[str] = None           # free plan
    DYMO_API_KEY: Optional[str] = None            # free tier
    NETLAS_API_KEY: Optional[str] = None          # 50 requests/day
    CRIMINALIP_API_KEY: Optional[str] = None      # 100 free
    HUNTERHOW_API_KEY: Optional[str] = None       # 10k free/30d
    MOJEEK_API_KEY: Optional[str] = None          # 5000 free credits
    WINDVANE_API_KEY: Optional[str] = None        # 100 free queries
    VENACUS_API_KEY: Optional[str] = None         # 1 free search/day
    ZOOMEYE_API_KEY: Optional[str] = None         # 5 free results/day
    WHOXY_API_KEY: Optional[str] = None           # Whoxy reverse whois API
    BUILTWITH_API_KEY: Optional[str] = None       # 50 free queries ever
    # Paid / limited free trial:
    INTELX_API_KEY: Optional[str] = None          # paid
    ONYPHE_API_KEY: Optional[str] = None          # paid
    FOFA_API_KEY: Optional[str] = None            # paid
    SHERLOCKEYE_API_KEY: Optional[str] = None     # paid
    PENTESTTOOLS_API_KEY: Optional[str] = None    # paid
    PROJECTDISCOVERY_KEY: Optional[str] = None    # paid
    ROCKETREACH_API_KEY: Optional[str] = None     # paid
    SECURITYSCORECARD_KEY: Optional[str] = None   # paid
    WHOISXML_API_KEY: Optional[str] = None        # paid
    DEHASHED_API_KEY: Optional[str] = None        # paid
    LEAKLOOKUP_API_KEY: Optional[str] = None      # paid

    # ── h8mail API keys (optional) ───────────────────────────────────────
    EMAILREP_API_KEY: Optional[str] = None        # emailrep.io full access
    SNUSBASE_API_KEY: Optional[str] = None        # snusbase breach data

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() in {"production", "prod"}

    @model_validator(mode="after")
    def validate_required_keys_for_production(self) -> "Settings":
        """Fail fast in production when critical secrets are missing.

        Development tolerates missing integrations. Production requires strong
        platform secrets, explicit migrations, restricted CORS, and non-default
        database credentials. Collector keys remain intentionally optional.
        """
        if not self.is_production:
            return self

        if self.API_KEY == "osint-local-dev-key-12345" or len(self.API_KEY) < 32:
            raise ValueError(
                "API_KEY must be a non-default random value of at least 32 characters."
            )

        if (
            self.JWT_SECRET_KEY == "osint-jwt-secret-change-in-production-12345"
            or len(self.JWT_SECRET_KEY) < 32
        ):
            raise ValueError(
                "JWT_SECRET_KEY must be a non-default random value of at least 32 characters."
            )

        if self.AUTO_CREATE_DB:
            raise ValueError(
                "AUTO_CREATE_DB must be false in production; use Alembic migrations."
            )

        if "*" in self.cors_origins_list:
            raise ValueError("Wildcard CORS origins are forbidden in production.")

        if "postgres:postgres@" in self.DATABASE_URL:
            raise ValueError("Default PostgreSQL credentials are forbidden in production.")

        bootstrap_values = (
            self.INITIAL_ADMIN_USERNAME,
            self.INITIAL_ADMIN_EMAIL,
            self.INITIAL_ADMIN_PASSWORD,
        )
        if any(bootstrap_values) and not all(bootstrap_values):
            raise ValueError(
                "INITIAL_ADMIN_USERNAME, INITIAL_ADMIN_EMAIL, and "
                "INITIAL_ADMIN_PASSWORD must be provided together."
            )
        if self.INITIAL_ADMIN_PASSWORD and len(self.INITIAL_ADMIN_PASSWORD) < 12:
            raise ValueError("INITIAL_ADMIN_PASSWORD must be at least 12 characters.")

        return self


settings = Settings()
