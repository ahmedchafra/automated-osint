"""Bounded TLS posture assessment for verified, in-scope HTTPS assets."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import warnings
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from app.services.http_validation import public_ip_set


TLS_CONNECT_TIMEOUT = 7.0
TLS_ASSESSMENT_CONCURRENCY = 5
MAX_TLS_TARGETS = 25

_SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_PROTOCOLS = (
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
)


def _issue(code: str, title: str, severity: str, description: str, remediation: str) -> dict[str, str]:
    return {
        "code": code,
        "title": title,
        "severity": severity,
        "description": description,
        "remediation": remediation,
    }


def _dns_name_matches(hostname: str, pattern: str) -> bool:
    hostname = hostname.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname.endswith(f".{suffix}") and hostname.count(".") == suffix.count(".") + 1
    return hostname == pattern


def _certificate_matches_hostname(certificate: x509.Certificate, hostname: str) -> bool:
    try:
        expected_ip = ipaddress.ip_address(hostname)
    except ValueError:
        expected_ip = None
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        if expected_ip is not None:
            return expected_ip in extension.value.get_values_for_type(x509.IPAddress)
        dns_names = extension.value.get_values_for_type(x509.DNSName)
        if dns_names:
            return any(_dns_name_matches(hostname, name) for name in dns_names)
    except x509.ExtensionNotFound:
        pass
    if expected_ip is not None:
        return False
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return any(_dns_name_matches(hostname, attribute.value) for attribute in common_names)


def analyze_certificate(
    certificate: x509.Certificate,
    hostname: str,
    *,
    now: datetime | None = None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Normalize certificate evidence and derive conservative posture issues."""
    now = now or datetime.now(timezone.utc)
    issues: list[dict[str, str]] = []
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    days_remaining = int((not_after - now).total_seconds() // 86400)
    hostname_valid = _certificate_matches_hostname(certificate, hostname)

    try:
        san_extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_extension.value.get_values_for_type(x509.DNSName)
        ip_addresses = [str(value) for value in san_extension.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names = []
        ip_addresses = []

    if now < not_before:
        issues.append(_issue(
            "certificate_not_yet_valid", "Certificate is not yet valid", "HIGH",
            f"The certificate validity period begins at {not_before.isoformat()}.",
            "Install a certificate whose validity period includes the current time.",
        ))
    elif now > not_after:
        issues.append(_issue(
            "certificate_expired", "Certificate has expired", "HIGH",
            f"The certificate expired at {not_after.isoformat()}.",
            "Renew and deploy the certificate immediately.",
        ))
    elif days_remaining <= 30:
        issues.append(_issue(
            "certificate_expiring_soon", "Certificate expires within 30 days", "MEDIUM",
            f"The certificate has approximately {max(days_remaining, 0)} days remaining.",
            "Renew the certificate and verify automated renewal before expiry.",
        ))
    elif days_remaining <= 90:
        issues.append(_issue(
            "certificate_expiry_notice", "Certificate expires within 90 days", "LOW",
            f"The certificate has approximately {days_remaining} days remaining.",
            "Confirm that automated renewal and deployment are working.",
        ))

    if not hostname_valid:
        issues.append(_issue(
            "hostname_mismatch", "Certificate hostname mismatch", "HIGH",
            f"The certificate does not cover {hostname}.",
            "Deploy a certificate whose SAN includes the requested hostname.",
        ))
    if certificate.issuer == certificate.subject:
        issues.append(_issue(
            "self_signed_certificate", "Self-signed certificate", "MEDIUM",
            "The leaf certificate is self-signed and is not anchored in a public trust chain.",
            "Use a certificate issued by an appropriate trusted CA unless private PKI is intentional.",
        ))

    try:
        signature_hash = certificate.signature_hash_algorithm.name.lower()
    except Exception:
        signature_hash = "unknown"
    if signature_hash in {"md5", "sha1"}:
        issues.append(_issue(
            "weak_signature_algorithm", "Weak certificate signature algorithm", "HIGH",
            f"The leaf certificate uses {signature_hash.upper()} for its signature.",
            "Replace it with a certificate signed using SHA-256 or stronger.",
        ))

    public_key = certificate.public_key()
    key_type = public_key.__class__.__name__
    key_size = getattr(public_key, "key_size", None)
    if isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < 2048:
        issues.append(_issue(
            "weak_rsa_key", "Weak RSA certificate key", "HIGH",
            f"The certificate uses a {public_key.key_size}-bit RSA key.",
            "Use an RSA key of at least 2048 bits or a modern elliptic curve key.",
        ))
    if isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.key_size < 224:
        issues.append(_issue(
            "weak_ec_key", "Weak elliptic-curve certificate key", "HIGH",
            f"The certificate uses a {public_key.key_size}-bit elliptic curve key.",
            "Use a modern curve with at least 224 bits, such as P-256.",
        ))

    normalized = {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": str(certificate.serial_number),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "hostname_valid": hostname_valid,
        "dns_names": dns_names[:500],
        "ip_addresses": ip_addresses[:100],
        "signature_hash": signature_hash,
        "public_key_type": key_type,
        "public_key_bits": key_size,
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
    }
    return normalized, issues


def findings_from_assessment(assessment: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert one successful endpoint assessment into persisted findings."""
    endpoint = str(assessment["endpoint"])
    issues = list(assessment.get("issues") or [])
    severity = max(
        (str(issue.get("severity", "INFO")) for issue in issues),
        key=lambda value: _SEVERITY_RANK.get(value, 0),
        default="INFO",
    )
    findings = [{
        "vector_type": "SERVICES",
        "entity_type": "TLS_ASSESSMENT",
        "entity_value": endpoint,
        "severity": severity,
        "confidence": 1.0,
        "source_module": "tls_assessment",
        "raw_data": {},
        "normalized_data": assessment,
        "tags": ["active", "verified-asset", "tls", "assessment"],
    }]
    for issue in issues:
        issue_severity = str(issue.get("severity") or "INFO")
        findings.append({
            "vector_type": "SERVICES",
            "entity_type": "VULNERABILITY",
            "entity_value": f"tls-{issue['code']} @ {endpoint}",
            "severity": issue_severity,
            "confidence": 1.0,
            "source_module": "tls_assessment",
            "raw_data": {},
            "normalized_data": {
                **issue,
                "name": issue["title"],
                "matched_at": endpoint,
                "hostname": assessment["hostname"],
                "port": assessment["port"],
                "scanner": "tls_assessment",
            },
            "tags": ["active", "verified-asset", "tls", "configuration", issue_severity.lower()],
        })
    return findings


async def _public_addresses(hostname: str) -> list[str]:
    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            records = await asyncio.get_running_loop().getaddrinfo(
                hostname, None, type=socket.SOCK_STREAM
            )
        except (OSError, UnicodeError):
            return []
        addresses = sorted({record[4][0] for record in records})
    return addresses if public_ip_set(addresses) else []


def _context_for(version: ssl.TLSVersion) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = version
        context.maximum_version = version
    if version in {ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1}:
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    return context


async def _probe_protocol(
    hostname: str, port: int, addresses: list[str], label: str, version: ssl.TLSVersion
) -> tuple[dict[str, Any] | None, bytes | None]:
    context = _context_for(version)
    for address in addresses:
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    port,
                    ssl=context,
                    server_hostname=None if _is_ip(hostname) else hostname,
                ),
                timeout=TLS_CONNECT_TIMEOUT,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                continue
            cipher = ssl_object.cipher() or (None, None, None)
            return ({
                "requested": label,
                "negotiated": ssl_object.version(),
                "cipher": cipher[0],
                "cipher_protocol": cipher[1],
                "cipher_bits": cipher[2],
                "connect_ip": address,
            }, ssl_object.getpeercert(binary_form=True))
        except (OSError, ValueError, ssl.SSLError, asyncio.TimeoutError):
            continue
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
    return None, None


async def _probe_trust(
    hostname: str, port: int, addresses: list[str]
) -> tuple[bool | None, str | None]:
    """Verify the peer using the container's public CA store on a pinned IP."""
    verification_errors: list[str] = []
    for address in addresses:
        writer = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    address,
                    port,
                    ssl=ssl.create_default_context(),
                    server_hostname=hostname,
                ),
                timeout=TLS_CONNECT_TIMEOUT,
            )
            return True, None
        except ssl.SSLCertVerificationError as exc:
            verification_errors.append(exc.verify_message or str(exc))
        except (OSError, ValueError, ssl.SSLError, asyncio.TimeoutError):
            continue
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
    if verification_errors:
        return False, verification_errors[0][:500]
    return None, "Trust validation could not be completed"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def assess_tls_endpoint(url: str) -> dict[str, Any] | None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    hostname = parsed.hostname.lower().rstrip(".")
    port = parsed.port or 443
    addresses = await _public_addresses(hostname)
    if not addresses:
        return None

    results = await asyncio.gather(*(
        _probe_protocol(hostname, port, addresses, label, version)
        for label, version in _PROTOCOLS
    ))
    protocols: dict[str, dict[str, Any]] = {}
    certificate_der = None
    connect_ip = None
    for (label, _), (protocol, der) in zip(_PROTOCOLS, results):
        if protocol:
            protocols[label] = protocol
            certificate_der = certificate_der or der
            connect_ip = connect_ip or protocol.get("connect_ip")
    if not protocols or not certificate_der:
        return None

    certificate = x509.load_der_x509_certificate(certificate_der)
    certificate_data, issues = analyze_certificate(certificate, hostname)
    chain_trusted, trust_error = await _probe_trust(hostname, port, addresses)
    certificate_data["chain_trusted"] = chain_trusted
    certificate_data["trust_error"] = trust_error
    if chain_trusted is False:
        issues.append(_issue(
            "untrusted_certificate_chain", "Certificate chain is not publicly trusted", "HIGH",
            f"Public CA verification failed: {trust_error or 'unknown verification error'}.",
            "Deploy the complete certificate chain from a trusted CA, or document the private PKI requirement.",
        ))
    if "TLSv1.0" in protocols:
        issues.append(_issue(
            "tls10_supported", "Deprecated TLS 1.0 is supported", "HIGH",
            "The endpoint accepts TLS 1.0 connections.",
            "Disable TLS 1.0 and require TLS 1.2 or TLS 1.3.",
        ))
    if "TLSv1.1" in protocols:
        issues.append(_issue(
            "tls11_supported", "Deprecated TLS 1.1 is supported", "MEDIUM",
            "The endpoint accepts TLS 1.1 connections.",
            "Disable TLS 1.1 and require TLS 1.2 or TLS 1.3.",
        ))

    endpoint = f"tls://{hostname}:{port}"
    return {
        "endpoint": endpoint,
        "source_url": url,
        "hostname": hostname,
        "port": port,
        "connect_ip": connect_ip,
        "resolved_public_ips": addresses,
        "supported_protocols": protocols,
        "certificate": certificate_data,
        "issues": issues,
        "issue_count": len(issues),
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }


async def assess_tls_urls(urls: list[str]) -> list[dict[str, Any]]:
    """Assess unique HTTPS origins with bounded concurrency and fan-out."""
    unique: dict[tuple[str, int], str] = {}
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.hostname:
            unique.setdefault((parsed.hostname.lower().rstrip("."), parsed.port or 443), url)
    selected = [unique[key] for key in sorted(unique)[:MAX_TLS_TARGETS]]
    semaphore = asyncio.Semaphore(TLS_ASSESSMENT_CONCURRENCY)

    async def assess(url: str):
        async with semaphore:
            return await assess_tls_endpoint(url)

    assessments = await asyncio.gather(*(assess(url) for url in selected), return_exceptions=True)
    findings: list[dict[str, Any]] = []
    for assessment in assessments:
        if isinstance(assessment, dict):
            findings.extend(findings_from_assessment(assessment))
    return findings
