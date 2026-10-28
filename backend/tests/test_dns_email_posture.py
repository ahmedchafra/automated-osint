import asyncio

from collectors.infrastructure.dns_email_posture import DnsEmailPostureCollector


def _result(*records, error=None):
    return {
        "records": list(records),
        "query_status": "error" if error else "ok",
        "error": error,
    }


def _install_fake_dns(monkeypatch, collector, answers):
    async def fake_query(name, record_type):
        return answers.get((name, record_type), _result())

    monkeypatch.setattr(collector, "_query", fake_query)


def test_dns_email_posture_strong_configuration(monkeypatch):
    collector = DnsEmailPostureCollector()
    domain = "example.com"
    answers = {
        (domain, "MX"): _result("10 mail.example.com."),
        (domain, "TXT"): _result("v=spf1 include:_spf.example.net -all"),
        (domain, "NS"): _result("ns1.example.net.", "ns2.example.net."),
        (domain, "SOA"): _result("ns1.example.net. hostmaster.example.com. 1 3600 600 86400 300"),
        (domain, "CAA"): _result('0 issue "letsencrypt.org"'),
        (domain, "DNSKEY"): _result("257 3 13 ABC"),
        (domain, "DS"): _result("12345 13 2 ABC"),
        (f"_dmarc.{domain}", "TXT"): _result("v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
        (f"_mta-sts.{domain}", "TXT"): _result("v=STSv1; id=20261023"),
        (f"_smtp._tls.{domain}", "TXT"): _result("v=TLSRPTv1; rua=mailto:tls@example.com"),
        (f"selector1._domainkey.{domain}", "TXT"): _result("v=DKIM1; k=rsa; p=ABC"),
        ("ns1.example.net", "A"): _result("192.0.2.1"),
        ("ns2.example.net", "AAAA"): _result("2001:db8::2"),
    }
    _install_fake_dns(monkeypatch, collector, answers)

    finding = asyncio.run(collector.execute(domain))[0]
    controls = finding["normalized_data"]["controls"]

    assert finding["entity_type"] == "DNS_POSTURE"
    assert finding["severity"] == "INFO"
    assert finding["normalized_data"]["grade"] == "A"
    assert controls["spf"]["status"] == "strict"
    assert controls["dmarc"]["status"] == "reject"
    assert controls["dkim"]["status"] == "observed"
    assert controls["dnssec"]["status"] == "delegated"
    assert controls["delegation"]["status"] == "healthy"


def test_dns_email_posture_surfaces_actionable_weaknesses(monkeypatch):
    collector = DnsEmailPostureCollector()
    domain = "example.com"
    answers = {
        (domain, "MX"): _result("10 mail.example.com."),
        (domain, "TXT"): _result("v=spf1 +all"),
        (domain, "NS"): _result("ns1.example.net."),
        (domain, "SOA"): _result(),
        (domain, "DNSKEY"): _result("257 3 13 ABC"),
        (domain, "DS"): _result(),
        ("ns1.example.net", "A"): _result(),
        ("ns1.example.net", "AAAA"): _result(),
    }
    _install_fake_dns(monkeypatch, collector, answers)

    finding = asyncio.run(collector.execute(domain))[0]
    issues = {item["id"]: item for item in finding["normalized_data"]["issues"]}

    assert finding["severity"] == "HIGH"
    assert "spf_pass_all" in issues
    assert "dmarc_missing" in issues
    assert "mta_sts_missing" in issues
    assert "dnssec_dnskey_without_ds" in issues
    assert "ns_insufficient" in issues
    assert "ns_unresolved" in issues
    assert "soa_missing" in issues
    assert finding["normalized_data"]["controls"]["dkim"]["status"] == "not_observed"


def test_dns_email_posture_does_not_treat_query_error_as_missing_record(monkeypatch):
    collector = DnsEmailPostureCollector()
    domain = "example.com"
    answers = {
        (domain, "MX"): _result(error="Timeout"),
        (domain, "NS"): _result(error="Timeout"),
        (f"_dmarc.{domain}", "TXT"): _result(error="Timeout"),
    }
    _install_fake_dns(monkeypatch, collector, answers)

    finding = asyncio.run(collector.execute(domain))[0]
    issues = {item["id"] for item in finding["normalized_data"]["issues"]}

    assert finding["normalized_data"]["complete"] is False
    assert "dmarc_missing" not in issues
    assert "ns_insufficient" not in issues
    controls = finding["normalized_data"]["controls"]
    assert controls["mx"]["status"] == "unknown"
    assert controls["dmarc"]["status"] == "unknown"


def test_dns_email_posture_partial_errors_do_not_create_false_weaknesses(monkeypatch):
    collector = DnsEmailPostureCollector()
    domain = "example.com"
    answers = {
        (domain, "MX"): _result("10 mail.example.com."),
        (domain, "TXT"): _result(error="Timeout"),
        (domain, "NS"): _result("ns1.example.net.", "ns2.example.net."),
        (domain, "SOA"): _result("ns1.example.net. hostmaster.example.com. 1 3600 600 86400 300"),
        (domain, "DS"): _result(error="Timeout"),
        (domain, "DNSKEY"): _result("257 3 13 ABC"),
        (f"_dmarc.{domain}", "TXT"): _result(error="Timeout"),
        (f"_mta-sts.{domain}", "TXT"): _result(error="Timeout"),
        (f"_smtp._tls.{domain}", "TXT"): _result(error="Timeout"),
        ("ns1.example.net", "A"): _result("192.0.2.1"),
        ("ns2.example.net", "A"): _result("192.0.2.2"),
    }
    _install_fake_dns(monkeypatch, collector, answers)

    finding = asyncio.run(collector.execute(domain))[0]
    issues = {item["id"] for item in finding["normalized_data"]["issues"]}
    controls = finding["normalized_data"]["controls"]

    assert not {"spf_missing", "dmarc_missing", "mta_sts_missing", "tls_rpt_missing"} & issues
    assert controls["spf"]["status"] == "unknown"
    assert controls["dmarc"]["status"] == "unknown"
    assert controls["mta_sts"]["status"] == "unknown"
    assert controls["tls_rpt"]["status"] == "unknown"
    assert controls["dnssec"]["status"] == "unknown"


def test_dns_email_posture_does_not_mislabel_wildcard_dkim_as_selectors(monkeypatch):
    collector = DnsEmailPostureCollector()
    domain = "example.com"
    wildcard_record = "v=DKIM1; p="
    answers = {
        (f"{selector}._domainkey.{domain}", "TXT"): _result(wildcard_record)
        for selector in (
            "default", "selector1", "selector2", "google", "k1", "s1", "s2",
            "mail", "smtp", "dkim", "mandrill", "pm", "protonmail", "zoho",
        )
    }
    answers[("_owl-osint-selector-probe._domainkey.example.com", "TXT")] = _result(wildcard_record)
    _install_fake_dns(monkeypatch, collector, answers)

    finding = asyncio.run(collector.execute(domain))[0]
    dkim = finding["normalized_data"]["controls"]["dkim"]

    assert dkim["status"] == "wildcard_revoked"
    assert dkim["selectors"] == {}
    assert dkim["wildcard_records"] == [wildcard_record]
