"""Passive DNS and email-authentication posture assessment."""
from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver

from collectors.base import BaseCollector, CollectorMetadata


DNS_TIMEOUT_SECONDS = 3.0
DNS_LIFETIME_SECONDS = 6.0
DNS_QUERY_CONCURRENCY = 6
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
DKIM_SELECTORS = (
    "default", "selector1", "selector2", "google", "k1", "s1", "s2",
    "mail", "smtp", "dkim", "mandrill", "pm", "protonmail", "zoho",
)
DKIM_WILDCARD_PROBE = "_owl-osint-selector-probe"
SEVERITY_WEIGHT = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _hostname(target: str) -> str | None:
    value = target.strip()
    if "://" not in value:
        value = f"https://{value}"
    try:
        hostname = (urlsplit(value).hostname or "").encode("idna").decode("ascii")
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None
    hostname = hostname.lower().rstrip(".")
    if not hostname or "." not in hostname or len(hostname) > 253:
        return None
    return hostname


def _tags(record: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for part in record.split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key:
            parsed[key.lower()] = value.strip()
    return parsed


def _issue(
    issue_id: str,
    title: str,
    severity: str,
    evidence: str,
    remediation: str,
) -> dict[str, str]:
    return {
        "id": issue_id,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "remediation": remediation,
    }


def _status(records: list[str], *, error: str | None = None) -> dict[str, Any]:
    return {"records": records, "query_status": "error" if error else "ok", "error": error}


class DnsEmailPostureCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="dns_email_posture",
        vector="INFRASTRUCTURE",
        description="SPF, DMARC, DKIM, mail transport, DNSSEC, CAA, and delegation posture",
        passive=True,
        requires_api_key=False,
    )

    def __init__(self):
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.nameservers = PUBLIC_RESOLVERS
        self.resolver.timeout = DNS_TIMEOUT_SECONDS
        self.resolver.lifetime = DNS_LIFETIME_SECONDS
        self._semaphore = asyncio.Semaphore(DNS_QUERY_CONCURRENCY)

    async def _query(self, name: str, record_type: str) -> dict[str, Any]:
        async with self._semaphore:
            try:
                answers = await self.resolver.resolve(
                    name, record_type, search=False, raise_on_no_answer=False
                )
                if answers.rrset is None:
                    return _status([])
                records: list[str] = []
                for answer in answers:
                    if record_type == "TXT" and hasattr(answer, "strings"):
                        records.append(
                            b"".join(answer.strings).decode("utf-8", errors="replace")
                        )
                    else:
                        records.append(str(answer))
                return _status(records)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                return _status([])
            except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
                return _status([], error=exc.__class__.__name__)
            except Exception as exc:
                return _status([], error=exc.__class__.__name__)

    async def _queries(
        self, requests: dict[str, tuple[str, str]]
    ) -> dict[str, dict[str, Any]]:
        keys = list(requests)
        values = await asyncio.gather(
            *(self._query(*requests[key]) for key in keys)
        )
        return dict(zip(keys, values))

    @staticmethod
    def _records(result: dict[str, Any]) -> list[str]:
        records = result.get("records")
        return [str(value) for value in records] if isinstance(records, list) else []

    async def collect(self, target: str) -> list[dict[str, Any]]:
        domain = _hostname(target)
        if domain is None:
            return []

        requests = {
            "mx": (domain, "MX"),
            "txt": (domain, "TXT"),
            "ns": (domain, "NS"),
            "soa": (domain, "SOA"),
            "caa": (domain, "CAA"),
            "dnskey": (domain, "DNSKEY"),
            "ds": (domain, "DS"),
            "dmarc": (f"_dmarc.{domain}", "TXT"),
            "mta_sts": (f"_mta-sts.{domain}", "TXT"),
            "tls_rpt": (f"_smtp._tls.{domain}", "TXT"),
            **{
                f"dkim:{selector}": (f"{selector}._domainkey.{domain}", "TXT")
                for selector in DKIM_SELECTORS
            },
            "dkim_wildcard": (
                f"{DKIM_WILDCARD_PROBE}._domainkey.{domain}", "TXT"
            ),
        }
        query_results = await self._queries(requests)

        mx_records = self._records(query_results["mx"])
        txt_records = self._records(query_results["txt"])
        ns_records = [value.rstrip(".") for value in self._records(query_results["ns"])]
        soa_records = self._records(query_results["soa"])
        caa_records = self._records(query_results["caa"])
        dnskey_records = self._records(query_results["dnskey"])
        ds_records = self._records(query_results["ds"])
        spf_records = [value for value in txt_records if value.lower().startswith("v=spf1")]
        dmarc_records = [
            value for value in self._records(query_results["dmarc"])
            if value.lower().startswith("v=dmarc1")
        ]
        mta_sts_records = [
            value for value in self._records(query_results["mta_sts"])
            if value.lower().startswith("v=stsv1")
        ]
        tls_rpt_records = [
            value for value in self._records(query_results["tls_rpt"])
            if value.lower().startswith("v=tlsrptv1")
        ]
        dkim_wildcard_records = [
            value for value in self._records(query_results["dkim_wildcard"])
            if value.lower().startswith("v=dkim1") or "p=" in value.lower()
        ]
        dkim_records: dict[str, list[str]] = {}
        for selector in DKIM_SELECTORS:
            records = [
                value for value in self._records(query_results[f"dkim:{selector}"])
                if value.lower().startswith("v=dkim1") or "p=" in value.lower()
            ]
            if records and records != dkim_wildcard_records:
                dkim_records[selector] = records

        issues: list[dict[str, str]] = []
        null_mx = any(record.strip().endswith(" .") for record in mx_records)
        accepts_mail = bool(mx_records) and not null_mx

        # SPF assessment (RFC 7208).
        spf_query_error = query_results["txt"].get("error")
        spf_control: dict[str, Any] = {
            "status": "unknown" if spf_query_error else "missing",
            "records": spf_records,
            "error": spf_query_error,
        }
        if len(spf_records) > 1:
            spf_control["status"] = "invalid_multiple"
            issues.append(_issue(
                "spf_multiple", "Multiple SPF records", "HIGH",
                f"Published {len(spf_records)} SPF records.",
                "Merge authorization rules into exactly one v=spf1 TXT record.",
            ))
        elif not spf_records:
            if accepts_mail and not spf_query_error:
                issues.append(_issue(
                    "spf_missing", "SPF record missing", "MEDIUM",
                    "The domain accepts mail but publishes no v=spf1 record.",
                    "Publish one SPF record authorizing legitimate outbound senders.",
                ))
        else:
            record = spf_records[0]
            terms = record.split()[1:]
            all_term = next((term for term in terms if re.fullmatch(r"[+?~-]?all", term, re.I)), None)
            dns_terms = [
                term for term in terms
                if re.match(r"[+?~-]?(include:|a(?=[:/\s]|$)|mx(?=[:/\s]|$)|ptr(?=[:/\s]|$)|exists:|redirect=)", term, re.I)
            ]
            spf_control.update({"all_mechanism": all_term, "direct_dns_terms": dns_terms})
            if all_term and all_term.startswith("+"):
                spf_control["status"] = "permissive"
                issues.append(_issue(
                    "spf_pass_all", "SPF authorizes every sender", "HIGH",
                    f"SPF terminates with {all_term}.",
                    "Replace +all with a restrictive policy after validating senders.",
                ))
            elif all_term and all_term.startswith("?"):
                spf_control["status"] = "neutral"
                issues.append(_issue(
                    "spf_neutral", "SPF policy is neutral", "MEDIUM",
                    f"SPF terminates with {all_term}.",
                    "Use ~all during transition or -all after sender validation.",
                ))
            elif all_term and all_term.startswith("~"):
                spf_control["status"] = "softfail"
                issues.append(_issue(
                    "spf_softfail", "SPF remains in soft-fail mode", "LOW",
                    "The SPF record ends in ~all.",
                    "Move to -all when every legitimate sender is covered.",
                ))
            elif all_term and all_term.startswith("-"):
                spf_control["status"] = "strict"
            else:
                spf_control["status"] = "no_all_mechanism"
                issues.append(_issue(
                    "spf_no_all", "SPF has no terminal all mechanism", "LOW",
                    "No all mechanism was observed in the SPF record.",
                    "Add an explicit ~all or -all policy.",
                ))
            if len(dns_terms) > 10:
                issues.append(_issue(
                    "spf_direct_lookup_limit", "SPF exceeds ten direct DNS terms", "HIGH",
                    f"Observed {len(dns_terms)} DNS-triggering terms before recursive expansion.",
                    "Flatten or simplify the SPF policy and verify the full RFC lookup budget.",
                ))

        # DMARC assessment (RFC 9989).
        dmarc_query_error = query_results["dmarc"].get("error")
        dmarc_control: dict[str, Any] = {
            "status": "unknown" if dmarc_query_error else "missing",
            "records": dmarc_records,
            "error": dmarc_query_error,
        }
        if len(dmarc_records) > 1:
            dmarc_control["status"] = "invalid_multiple"
            issues.append(_issue(
                "dmarc_multiple", "Multiple DMARC policy records", "HIGH",
                f"Published {len(dmarc_records)} v=DMARC1 records.",
                "Publish exactly one DMARC policy record.",
            ))
        elif not dmarc_records:
            if (accepts_mail or spf_records) and not dmarc_query_error:
                issues.append(_issue(
                    "dmarc_missing", "DMARC policy missing", "MEDIUM",
                    "No v=DMARC1 record was found at _dmarc.",
                    "Publish DMARC, begin with monitored reporting, then enforce quarantine or reject.",
                ))
        else:
            dmarc_tags = _tags(dmarc_records[0])
            policy = dmarc_tags.get("p", "").lower()
            dmarc_control.update({"tags": dmarc_tags, "policy": policy})
            if policy == "reject":
                dmarc_control["status"] = "reject"
            elif policy == "quarantine":
                dmarc_control["status"] = "quarantine"
            elif policy == "none":
                dmarc_control["status"] = "monitoring"
                issues.append(_issue(
                    "dmarc_monitoring", "DMARC is monitoring only", "LOW",
                    "The DMARC policy is p=none.",
                    "Review reports, align senders, then move to quarantine or reject.",
                ))
            else:
                dmarc_control["status"] = "invalid_policy"
                issues.append(_issue(
                    "dmarc_invalid_policy", "DMARC policy is invalid", "HIGH",
                    f"Observed p={policy or '(missing)' }.",
                    "Set p to none, quarantine, or reject.",
                ))

        # DKIM selector discovery is necessarily non-exhaustive.
        dkim_query_errors = {
            selector: query_results[f"dkim:{selector}"].get("error")
            for selector in DKIM_SELECTORS
            if query_results[f"dkim:{selector}"].get("error")
        }
        revoked = [
            selector for selector, records in dkim_records.items()
            if any(_tags(record).get("p") == "" for record in records)
        ]
        active_selectors = [
            selector for selector, records in dkim_records.items()
            if any(bool(_tags(record).get("p")) for record in records)
        ]
        wildcard_revoked = bool(dkim_wildcard_records) and all(
            _tags(record).get("p") == "" for record in dkim_wildcard_records
        )
        dkim_status = (
            "observed" if active_selectors
            else "revoked_only" if revoked
            else "wildcard_revoked" if wildcard_revoked
            else "wildcard_observed" if dkim_wildcard_records
            else "unknown" if len(dkim_query_errors) == len(DKIM_SELECTORS)
            else "not_observed"
        )
        dkim_control: dict[str, Any] = {
            "status": dkim_status,
            "selectors_checked": list(DKIM_SELECTORS),
            "selectors": dkim_records,
            "active_selectors": active_selectors,
            "discovery_complete": False,
            "query_errors": dkim_query_errors,
            "wildcard_probe": DKIM_WILDCARD_PROBE,
            "wildcard_records": dkim_wildcard_records,
        }
        if revoked:
            dkim_control["revoked_selectors"] = revoked

        # MTA-STS and TLS reporting are assessed from DNS advertisements only.
        mta_sts_error = query_results["mta_sts"].get("error")
        tls_rpt_error = query_results["tls_rpt"].get("error")
        mta_control = {
            "status": "advertised" if mta_sts_records else "unknown" if mta_sts_error else "missing",
            "records": mta_sts_records,
            "policy_fetch": "not_attempted_passive",
            "error": mta_sts_error,
        }
        tls_rpt_control = {
            "status": "configured" if tls_rpt_records else "unknown" if tls_rpt_error else "missing",
            "records": tls_rpt_records,
            "tags": _tags(tls_rpt_records[0]) if len(tls_rpt_records) == 1 else {},
            "error": tls_rpt_error,
        }
        if accepts_mail and not mta_sts_records and not mta_sts_error:
            issues.append(_issue(
                "mta_sts_missing", "MTA-STS is not advertised", "LOW",
                "No v=STSv1 TXT record was found at _mta-sts.",
                "Consider MTA-STS with TLS reporting for downgrade resistance.",
            ))
        if mta_sts_records and not tls_rpt_records and not tls_rpt_error:
            issues.append(_issue(
                "tls_rpt_missing", "SMTP TLS reporting is missing", "LOW",
                "MTA-STS is advertised but no v=TLSRPTv1 record was found.",
                "Publish _smtp._tls with a TLSRPTv1 reporting URI.",
            ))

        # DNSSEC delegation state. This does not claim full cryptographic validation.
        ds_error = query_results["ds"].get("error")
        dnskey_error = query_results["dnskey"].get("error")
        if ds_error or dnskey_error:
            dnssec_status = "unknown"
        elif ds_records and dnskey_records:
            dnssec_status = "delegated"
        elif ds_records:
            dnssec_status = "potentially_broken"
            issues.append(_issue(
                "dnssec_ds_without_dnskey", "DNSSEC delegation may be broken", "HIGH",
                "DS records exist but no DNSKEY response was observed.",
                "Verify the parent DS matches an actively published zone-signing key.",
            ))
        elif dnskey_records:
            dnssec_status = "unsigned_delegation"
            issues.append(_issue(
                "dnssec_dnskey_without_ds", "DNSSEC chain is not delegated", "LOW",
                "DNSKEY records exist but no parent DS record was observed.",
                "Publish the matching DS record at the registrar after validating key rollover state.",
            ))
        else:
            dnssec_status = "unsigned"
        dnssec_control = {
            "status": dnssec_status,
            "ds_records": ds_records,
            "dnskey_count": len(dnskey_records),
            "cryptographically_validated": False,
            "errors": {"ds": ds_error, "dnskey": dnskey_error},
        }

        # Delegation and nameserver reachability through recursive DNS.
        ns_requests = {
            f"{ns}:A": (ns, "A") for ns in ns_records[:8]
        } | {
            f"{ns}:AAAA": (ns, "AAAA") for ns in ns_records[:8]
        }
        ns_addresses = await self._queries(ns_requests) if ns_requests else {}
        unresolved_ns = [
            ns for ns in ns_records[:8]
            if not self._records(ns_addresses.get(f"{ns}:A", {}))
            and not self._records(ns_addresses.get(f"{ns}:AAAA", {}))
            and not ns_addresses.get(f"{ns}:A", {}).get("error")
            and not ns_addresses.get(f"{ns}:AAAA", {}).get("error")
        ]
        if query_results["ns"].get("query_status") == "ok" and len(ns_records) < 2:
            issues.append(_issue(
                "ns_insufficient", "Fewer than two authoritative nameservers", "MEDIUM",
                f"Observed {len(ns_records)} NS record(s).",
                "Publish at least two independently reachable authoritative nameservers.",
            ))
        if unresolved_ns:
            issues.append(_issue(
                "ns_unresolved", "Authoritative nameserver does not resolve", "HIGH",
                ", ".join(unresolved_ns),
                "Repair glue or address records for every authoritative nameserver.",
            ))
        if ns_records and not soa_records and not query_results["soa"].get("error"):
            issues.append(_issue(
                "soa_missing", "SOA record missing", "HIGH",
                "NS records exist but no SOA answer was observed.",
                "Restore a valid SOA record on the authoritative zone.",
            ))

        mx_control = {
            "status": (
                "null_mx" if null_mx
                else "configured" if mx_records
                else "unknown" if query_results["mx"].get("error")
                else "not_configured"
            ),
            "records": mx_records,
            "accepts_mail": accepts_mail,
            "error": query_results["mx"].get("error"),
        }
        caa_control = {
            "status": (
                "configured" if caa_records
                else "unknown" if query_results["caa"].get("error")
                else "not_configured"
            ),
            "records": caa_records,
            "error": query_results["caa"].get("error"),
        }
        delegation_control = {
            "status": "healthy" if len(ns_records) >= 2 and not unresolved_ns and soa_records else "review",
            "nameservers": ns_records,
            "unresolved_nameservers": unresolved_ns,
            "soa_records": soa_records,
            "address_records": {
                key: self._records(value) for key, value in ns_addresses.items()
            },
        }

        all_query_results = {**query_results, **ns_addresses}
        query_errors = [
            {"query": key, "error": value.get("error")}
            for key, value in all_query_results.items() if value.get("error")
        ]
        highest = max(
            (issue["severity"] for issue in issues),
            key=lambda severity: SEVERITY_WEIGHT[severity],
            default="INFO",
        )
        deductions = sum(
            {"HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 0}[issue["severity"]]
            for issue in issues
        )
        score = max(0, 100 - deductions)
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

        return [{
            "type": "DNS_POSTURE",
            "value": domain,
            "severity": highest,
            "confidence": 0.95 if not query_errors else 0.7,
            "details": {
                "domain": domain,
                "score": score,
                "grade": grade,
                "complete": not query_errors,
                "query_errors": query_errors,
                "issues": issues,
                "controls": {
                    "spf": spf_control,
                    "dmarc": dmarc_control,
                    "dkim": dkim_control,
                    "mta_sts": mta_control,
                    "tls_rpt": tls_rpt_control,
                    "mx": mx_control,
                    "dnssec": dnssec_control,
                    "caa": caa_control,
                    "delegation": delegation_control,
                },
            },
            "dns_responses": all_query_results,
        }]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "entity_type": "DNS_POSTURE",
            "entity_value": raw["value"],
            "severity": raw.get("severity", "INFO"),
            "confidence": raw.get("confidence", 0.8),
            "normalized_data": raw.get("details") or {},
            "tags": ["dns", "email-security", "posture"],
        }
