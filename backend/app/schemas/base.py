"""Pydantic schemas for API request and response bodies.

All taxonomies are imported from `app.schemas.enums` so request validation
matches what the database accepts and what the correlation engine emits.
"""
from __future__ import annotations

import re
import ipaddress
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.enums import (
    EntityType,
    LinkType,
    ScanStatus,
    Severity,
    TargetType,
    VectorType,
)

# Reasonable upper bound to keep a single scan's payload bounded.
_MAX_USERNAME_LENGTH = 64
_MAX_DOMAIN_LENGTH = 253  # RFC 1035 total length
_USERNAME_COUNT_CAP = 50
_VECTOR_COUNT_CAP = 5

# Permissive domain regex — accepts `example.com`, `sub.example.co.uk`,
# rejects schemes, paths, ports, whitespace, and trailing dots.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_INTERNAL_DOMAIN_SUFFIXES = (
    ".internal", ".intranet", ".lan", ".local", ".localhost", ".home",
)


def _clean_domain(value: str, field_name: str = "domain") -> str:
    candidate = value.strip().lower()
    if not _DOMAIN_RE.match(candidate):
        raise ValueError(
            f"{field_name} must be a valid domain name without scheme, path, "
            "port, or trailing dot"
        )
    if candidate.endswith(_INTERNAL_DOMAIN_SUFFIXES):
        raise ValueError(f"{field_name} must be a public internet domain")
    return candidate


def _clean_public_ip(value: str, field_name: str = "ip") -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid IPv4 or IPv6 address") from exc
    if not address.is_global:
        raise ValueError(
            f"{field_name} must be a globally routable address; private, loopback, "
            "link-local, multicast, reserved, and unspecified ranges are blocked"
        )
    return str(address)


def _clean_email(value: str, field_name: str = "email") -> str:
    candidate = value.strip().lower()
    if not _EMAIL_RE.match(candidate):
        raise ValueError(f"{field_name} must be a valid email address")
    return candidate


class SchemaBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ScanCreateSimple(BaseModel):
    """Simplified scan creation — just a domain, runs all vectors automatically."""
    target_domain: str = Field(
        ...,
        min_length=4,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Apex domain to reconnoitre (e.g. example.com)",
    )

    @field_validator("target_domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return _clean_domain(value, "target_domain")


class ScanCreate(BaseModel):
    target_domain: str = Field(
        ...,
        min_length=4,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Apex domain to reconnoitre (e.g. example.com)",
    )
    selected_vectors: List[VectorType] = Field(
        default_factory=lambda: [VectorType.INFRASTRUCTURE],
        max_length=_VECTOR_COUNT_CAP,
        description="Which reconnaissance vectors to run",
    )
    target_usernames: List[str] = Field(
        default_factory=list,
        max_length=_USERNAME_COUNT_CAP,
        description="Optional list of usernames for the USERNAME vector",
    )

    @field_validator("target_domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        return _clean_domain(value, "target_domain")

    @field_validator("target_usernames")
    @classmethod
    def _validate_usernames(cls, value: List[str]) -> List[str]:
        cleaned: list[str] = []
        for raw in value:
            if not isinstance(raw, str):
                raise ValueError("each username must be a string")
            candidate = raw.strip()
            if not candidate:
                continue
            if len(candidate) > _MAX_USERNAME_LENGTH:
                raise ValueError(
                    f"username '{candidate[:16]}...' exceeds "
                    f"{_MAX_USERNAME_LENGTH} characters"
                )
            if not _USERNAME_RE.match(candidate):
                raise ValueError(
                    f"username '{candidate}' contains illegal characters"
                )
            cleaned.append(candidate)
        return cleaned


# ── IP validation ──────────────────────────────────────────────────────
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    r"|"
    r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$"
)


class ScanCreateV2(BaseModel):
    """Unified scan creation — works for domain, IP, or organization targets.

    The ``target_type`` field determines which collectors run: domain →
    full pipeline, IP → IP-focused pipeline (Shodan/Censys/ASN), organization
    → domain-discovery then full pipeline.
    """
    target_value: str = Field(
        ...,
        min_length=2,
        max_length=253,
        description="Target: domain, IP address, or organization name",
    )
    target_type: TargetType = Field(
        default=TargetType.DOMAIN,
        description="Type of target: 'domain', 'ip', or 'organization'",
    )
    selected_vectors: List[VectorType] = Field(
        default_factory=lambda: [VectorType.INFRASTRUCTURE],
        max_length=_VECTOR_COUNT_CAP,
        description="Which reconnaissance vectors to run",
    )
    target_usernames: List[str] = Field(
        default_factory=list,
        max_length=_USERNAME_COUNT_CAP,
        description="Optional list of usernames for the USERNAME vector",
    )

    @model_validator(mode="after")
    def _validate_target(self) -> "ScanCreateV2":
        candidate = self.target_value.strip()
        if self.target_type == TargetType.DOMAIN:
            self.target_value = _clean_domain(candidate, "target_value")
        elif self.target_type == TargetType.IP:
            self.target_value = _clean_public_ip(candidate, "target_value")
        else:
            if any(ord(char) < 32 for char in candidate):
                raise ValueError("organization target contains control characters")
            if "://" in candidate:
                raise ValueError("organization target must be a name, not a URL")
            self.target_value = candidate
        return self

    @field_validator("target_usernames")
    @classmethod
    def _validate_usernames(cls, value: List[str]) -> List[str]:
        cleaned: list[str] = []
        for raw in value:
            if not isinstance(raw, str):
                raise ValueError("each username must be a string")
            candidate = raw.strip()
            if not candidate:
                continue
            if len(candidate) > _MAX_USERNAME_LENGTH:
                raise ValueError(
                    f"username '{candidate[:16]}...' exceeds "
                    f"{_MAX_USERNAME_LENGTH} characters"
                )
            if not _USERNAME_RE.match(candidate):
                raise ValueError(
                    f"username '{candidate}' contains illegal characters"
                )
            cleaned.append(candidate)
        return cleaned


class ScanResponse(SchemaBase):
    id: str
    target_domain: str
    target_type: str = "domain"
    status: ScanStatus
    selected_vectors: List[VectorType]
    target_usernames: List[str]
    created_at: datetime
    completed_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    findings_count: int = 0
    links_count: int = 0


class ScanCreateResponse(SchemaBase):
    task_id: str
    scan: ScanResponse


class ScanDetailResponse(ScanResponse):
    findings: List["FindingResponse"] = Field(default_factory=list)


class SetPrimaryDomainRequest(BaseModel):
    """Request body for setting a scan's primary domain (org scans)."""

    domain: str = Field(..., min_length=1, max_length=255)

    _validate_domain = field_validator("domain")(
        lambda value: _clean_domain(value, "domain")
    )


class FindingResponse(SchemaBase):
    id: str
    scan_id: str
    vector_type: VectorType
    entity_type: EntityType
    entity_value: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    source_module: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    normalized_data: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    created_at: datetime


class PaginatedFindingsResponse(SchemaBase):
    """Findings list with total count for pagination UI."""

    items: List[FindingResponse]
    total: int
    skip: int = 0
    limit: int = 100


class EntityLinkResponse(SchemaBase):
    id: str
    scan_id: str
    source_finding_id: str
    target_finding_id: str
    link_type: LinkType
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: datetime


class AIDorkRequest(BaseModel):
    """Body for `POST /api/ai/generate-dork` and `POST /api/scans/{id}/ai-dork`."""

    prompt: str = Field(
        ...,
        min_length=4,
        max_length=500,
        description="Natural-language description of what to find",
    )

    @field_validator("prompt")
    @classmethod
    def _strip_prompt(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("prompt must not be empty")
        return candidate


class PivotRequest(BaseModel):
    """Body for `POST /api/scans/{id}/pivot` — triggers per-email deep sweep."""

    email: str = Field(
        ...,
        min_length=5,
        max_length=254,
        description="Email address to run holehe/maigret/hibp checks on",
    )

    _validate_email = field_validator("email")(
        lambda value: _clean_email(value, "email")
    )


class SubdomainEnrichRequest(BaseModel):
    """Body for `POST /api/scans/{id}/enrich` — triggers Hunter + XposedOrNot on selected subdomains."""

    subdomains: List[str] = Field(
        ...,
        min_length=1,
        max_length=50,
        description="List of subdomains to enrich (e.g. ['etudiant-isi.utm.tn', 'www.utm.tn'])",
    )

    @field_validator("subdomains")
    @classmethod
    def _validate_subdomains(cls, values: List[str]) -> List[str]:
        return [_clean_domain(value, "subdomain") for value in values]


class EmailBreachRequest(BaseModel):
    """Body for `POST /api/scans/{id}/check-breaches` — triggers XposedOrNot on selected emails."""

    emails: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of email addresses to check against breach databases",
    )

    @field_validator("emails")
    @classmethod
    def _validate_emails(cls, values: List[str]) -> List[str]:
        return [_clean_email(value) for value in values]


class DeepPivotRequest(BaseModel):
    """Body for `POST /api/scans/{id}/deep-pivot` — triggers holehe + maigret + breach checks."""

    identifier: str = Field(
        ...,
        min_length=3,
        max_length=254,
        description="Email address (pivot_type=email) or username (pivot_type=username)",
    )
    pivot_type: str = Field(
        default="email",
        pattern="^(email|username)$",
        description="Whether to treat the identifier as an email or username",
    )


class ThreatIntelRequest(BaseModel):
    """Body for `POST /api/scans/{id}/threat-intel` — triggers GitHub secrets + dnstwist."""

    domain: str = Field(
        ...,
        min_length=4,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Domain to scan for leaked secrets and lookalike domains",
    )

    _validate_domain = field_validator("domain")(
        lambda value: _clean_domain(value, "domain")
    )


class ShodanEnrichRequest(BaseModel):
    """Body for `POST /api/scans/{id}/shodan-enrich` — triggers Shodan and/or Censys Host API on one IP."""

    ip: str = Field(
        ...,
        max_length=45,
        description="IPv4 or IPv6 address to enrich",
    )
    provider: str = Field(
        default="shodan",
        pattern="^(shodan|censys|both)$",
        description="Which enrichment provider(s) to use: 'shodan', 'censys', or 'both'",
    )

    _validate_ip = field_validator("ip")(
        lambda value: _clean_public_ip(value, "ip")
    )


class CensysEnrichRequest(BaseModel):
    """Body for `POST /api/scans/{id}/censys-enrich` — triggers Censys Host API on one IP."""

    ip: str = Field(
        ...,
        max_length=45,
        description="IPv4 or IPv6 address to enrich with Censys Host API",
    )

    _validate_ip = field_validator("ip")(
        lambda value: _clean_public_ip(value, "ip")
    )


class DomainDeepAnalysisRequest(BaseModel):
    """Body for `POST /api/scans/{id}/domain-deep-analysis` — runs hunter + theharvester + github_secrets + dnstwist in parallel."""

    domain: str = Field(
        ...,
        min_length=4,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Domain to deep-analyze (emails, secrets, lookalikes)",
    )

    theharvester_mode: Literal["auto", "quick", "full"] = Field(
        "quick",
        description='"auto" = use full mode if API keys configured, else quick. "quick" = free sources only (fast, ~30s). "full" = use all API-key sources (~900s).',
    )

    _validate_domain = field_validator("domain")(
        lambda value: _clean_domain(value, "domain")
    )


class DnstwistRequest(BaseModel):
    """Body for `POST /api/scans/{id}/dnstwist` — runs dnstwist lookalike detection on a domain."""

    domain: str = Field(
        ...,
        min_length=4,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Domain to generate lookalike permutations for",
    )

    _validate_domain = field_validator("domain")(
        lambda value: _clean_domain(value, "domain")
    )


class TelegramMonitorRequest(BaseModel):
    """Body for `POST /api/scans/{id}/telegram-monitor` — monitors Telegram for brand mentions."""

    domain: str = Field(
        ...,
        min_length=4,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Domain or keyword to monitor on Telegram",
    )
    keyword: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Keyword to search for (e.g. brand name, domain without TLD)",
    )

    _validate_domain = field_validator("domain")(
        lambda value: _clean_domain(value, "domain")
    )


class EmailDeepAnalysisRequest(BaseModel):
    """Body for `POST /api/scans/{id}/email-deep-analysis` — runs xposedornot + holehe + maigret per email."""

    emails: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of email addresses to deep-analyze",
    )

    @field_validator("emails")
    @classmethod
    def _validate_emails(cls, values: List[str]) -> List[str]:
        return [_clean_email(value) for value in values]


class AIQueryResponse(SchemaBase):
    """Audit + UI surface for prior AI dork generations."""

    id: str
    scan_id: str
    user_prompt: str
    generated_dork: str
    model_used: str
    search_results: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime


ScanDetailResponse.model_rebuild()
