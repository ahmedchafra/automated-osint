import asyncio
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services import tls_assessment
from app.services.tls_assessment import analyze_certificate, findings_from_assessment


def _certificate(
    hostname: str,
    *,
    key_bits: int = 2048,
    not_before: datetime,
    not_after: datetime,
    self_signed: bool = False,
) -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    issuer = subject if self_signed else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )


def test_certificate_analysis_reports_expiry_without_false_hostname_issue():
    now = datetime(2026, 10, 24, tzinfo=timezone.utc)
    certificate = _certificate(
        "app.example.com",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
    )

    normalized, issues = analyze_certificate(certificate, "app.example.com", now=now)

    assert normalized["hostname_valid"] is True
    assert normalized["public_key_bits"] == 2048
    assert {issue["code"] for issue in issues} == {"certificate_expiry_notice"}


def test_certificate_analysis_detects_expired_mismatch_self_signed_and_weak_key():
    now = datetime(2026, 10, 24, tzinfo=timezone.utc)
    certificate = _certificate(
        "wrong.example.com",
        key_bits=1024,
        not_before=now - timedelta(days=60),
        not_after=now - timedelta(days=1),
        self_signed=True,
    )

    normalized, issues = analyze_certificate(certificate, "app.example.com", now=now)
    codes = {issue["code"] for issue in issues}

    assert normalized["hostname_valid"] is False
    assert {
        "certificate_expired",
        "hostname_mismatch",
        "self_signed_certificate",
        "weak_rsa_key",
    }.issubset(codes)


def test_tls_assessment_emits_summary_and_actionable_vulnerabilities():
    assessment = {
        "endpoint": "tls://app.example.com:443",
        "hostname": "app.example.com",
        "port": 443,
        "supported_protocols": {"TLSv1.2": {"cipher": "TLS_AES_128_GCM_SHA256"}},
        "certificate": {"hostname_valid": False},
        "issues": [
            {
                "code": "hostname_mismatch",
                "title": "Certificate hostname mismatch",
                "severity": "HIGH",
                "description": "Mismatch",
                "remediation": "Replace certificate",
            },
            {
                "code": "certificate_expiry_notice",
                "title": "Certificate expires within 90 days",
                "severity": "LOW",
                "description": "Expiring",
                "remediation": "Confirm renewal",
            },
        ],
    }

    findings = findings_from_assessment(assessment)

    assert findings[0]["entity_type"] == "TLS_ASSESSMENT"
    assert findings[0]["severity"] == "HIGH"
    assert len(findings) == 3
    assert all(finding["source_module"] == "tls_assessment" for finding in findings)
    assert {finding["entity_type"] for finding in findings[1:]} == {"VULNERABILITY"}


def test_tls_url_batch_is_https_only_and_deduplicates_origins(monkeypatch):
    called: list[str] = []

    async def fake_assess(url: str):
        called.append(url)
        parsed = tls_assessment.urlparse(url)
        return {
            "endpoint": f"tls://{parsed.hostname}:{parsed.port or 443}",
            "hostname": parsed.hostname,
            "port": parsed.port or 443,
            "issues": [],
        }

    monkeypatch.setattr(tls_assessment, "assess_tls_endpoint", fake_assess)
    findings = asyncio.run(tls_assessment.assess_tls_urls([
        "https://app.example.com/",
        "https://app.example.com/login",
        "http://plain.example.com/",
        "https://api.example.com:8443/",
    ]))

    assert len(called) == 2
    assert len(findings) == 2
    assert {finding["entity_value"] for finding in findings} == {
        "tls://app.example.com:443",
        "tls://api.example.com:8443",
    }


def test_active_worker_tls_branch_publishes_progress(monkeypatch):
    from app.workers import active_validation

    expected = [{"entity_type": "TLS_ASSESSMENT", "entity_value": "tls://app.example.com:443"}]
    events: list[tuple[str, dict]] = []

    async def fake_assess(urls: list[str]):
        assert urls == ["https://app.example.com/"]
        return expected

    class Publisher:
        async def publish(self, scan_id: str, event: str, payload: dict):
            assert scan_id == "scan-1"
            events.append((event, payload))

    monkeypatch.setattr(active_validation, "assess_tls_urls", fake_assess)
    result = asyncio.run(active_validation._run_tls_assessment(
        ["https://app.example.com/"], Publisher(), "scan-1"
    ))

    assert result == expected
    assert events == [
        ("active_tool_started", {"tool": "tls_assessment", "targets": 1}),
        ("active_tool_completed", {"tool": "tls_assessment", "findings": 1}),
    ]
