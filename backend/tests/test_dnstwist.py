import asyncio
import json
from types import SimpleNamespace

from collectors.search.dnstwist import DnstwistCollector


def test_dnstwist_cli_output_is_captured_and_normalized(monkeypatch, capsys):
    payload = [
        {"domain": "example.com", "fuzzer": "*original", "dns_a": ["1.1.1.1"]},
        {"domain": "examp1e.com", "fuzzer": "homoglyph", "dns_a": ["2.2.2.2"]},
        {"domain": "exampl3.com", "fuzzer": "replacement"},
    ]

    monkeypatch.setattr("collectors.search.dnstwist.shutil.which", lambda _: "/usr/bin/dnstwist")
    monkeypatch.setattr(
        "collectors.search.dnstwist.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
        ),
    )

    results = asyncio.run(DnstwistCollector().execute("example.com"))

    assert capsys.readouterr().out == ""
    assert [item["entity_value"] for item in results] == ["examp1e.com", "exampl3.com"]
    assert results[0]["entity_type"] == "PHISHING_SITE"
    assert results[1]["entity_type"] == "LOOKALIKE_DOMAIN"
