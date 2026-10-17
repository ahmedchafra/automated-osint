"""Manual Censys SDK smoke check.

Run only when explicitly testing a configured Censys account:

    CENSYS_API_SECRET=... python tests/test_censys.py
"""

import os

from censys.search import CensysHosts


token = os.environ.get("CENSYS_API_SECRET")
if not token:
    raise SystemExit("CENSYS_API_SECRET is required")

client = CensysHosts(api_token=token)
host = client.view("8.8.8.8")
print(f"Type: {type(host)}")
if isinstance(host, dict):
    print(f"Top-level keys: {list(host.keys())}")
    services = host.get("services", [])
    print(f"Services count: {len(services)}")
