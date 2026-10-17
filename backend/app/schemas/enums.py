"""Pydantic enums shared across schemas.

Centralising the taxonomies here means the database columns, the API
request/response schemas, and the frontend dropdowns all stay in sync.
Anywhere a vector type, entity type, severity, link type or scan status
is referenced in a schema, reference the enum below.
"""
from __future__ import annotations

from enum import Enum


class VectorType(str, Enum):
    """Reconnaissance vectors supported by the orchestrator."""

    INFRASTRUCTURE = "INFRASTRUCTURE"
    SERVICES = "SERVICES"
    IDENTITY = "IDENTITY"
    SEARCH = "SEARCH"
    USERNAME = "USERNAME"


class EntityType(str, Enum):
    """The concrete kinds of evidence a finding can represent."""

    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    PORT_SERVICE = "PORT_SERVICE"
    CVE = "CVE"
    EMAIL = "EMAIL"
    BREACH = "BREACH"
    PROFILE = "PROFILE"
    DORK_RESULT = "DORK_RESULT"
    TECHNOLOGY = "TECHNOLOGY"
    TECHNOLOGY_VERSION = "TECHNOLOGY_VERSION"
    OPEN_PORT = "OPEN_PORT"
    GITHUB_REPO = "GITHUB_REPO"
    LEAKED_SECRET = "LEAKED_SECRET"
    TELEGRAM_CHANNEL = "TELEGRAM_CHANNEL"
    TELEGRAM_MESSAGE = "TELEGRAM_MESSAGE"
    TLS_CERT = "TLS_CERT"
    HOST_METADATA = "HOST_METADATA"
    DNS_RECORD = "DNS_RECORD"
    DOMAIN_METADATA = "DOMAIN_METADATA"
    EMAIL_PLATFORM = "EMAIL_PLATFORM"
    LOOKALIKE_DOMAIN = "LOOKALIKE_DOMAIN"
    ONION_SITE = "ONION_SITE"
    DARKWEB_MENTION = "DARKWEB_MENTION"
    CREDENTIAL = "CREDENTIAL"
    URL = "URL"
    PHISHING_SITE = "PHISHING_SITE"
    CLOUD_BUCKET = "CLOUD_BUCKET"
    EXPOSED_FILE = "EXPOSED_FILE"
    ASN_INFO = "ASN_INFO"
    HTTP_HEADER = "HTTP_HEADER"
    HISTORICAL_URL = "HISTORICAL_URL"
    WAYBACK_SNAPSHOT = "WAYBACK_SNAPSHOT"


class Severity(str, Enum):
    """Risk ordering. INFO < LOW < MEDIUM < HIGH < CRITICAL."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class LinkType(str, Enum):
    """Edges produced by the correlation engine."""

    RESOLVES_TO = "RESOLVES_TO"
    HAS_PORT = "HAS_PORT"
    MATCHES_CVE = "MATCHES_CVE"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    BREACHED_IN = "BREACHED_IN"
    REFERENCES = "REFERENCES"
    EXPOSED_IN = "EXPOSED_IN"


class ScanStatus(str, Enum):
    """Lifecycle states of a scan record."""

    QUEUED = "QUEUED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TargetType(str, Enum):
    """What kind of target the user is scanning."""

    DOMAIN = "domain"
    IP = "ip"
    ORGANIZATION = "organization"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
