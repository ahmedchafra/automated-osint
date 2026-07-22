"""Check findings in a completed scan for new data types."""
import urllib.request, json

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZWUyOTRhYy1iZjk0LTQxMDktOWM1ZS05ZGRlZmNiMjI1NTAiLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzg0MDY1NzE5fQ.I_cQQZUnLlnNx6kg3CDWxpuvt-bgFVFfVwPs5sXejg8"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

# Check several completed scans for new data
scan_ids = [
    "b3b92b8e-ef82-4cb8-b08e-afbf0bafe11a",
    "21a83b95-2a70-420b-a5b4-221320ef71f7",
    "191ef3f5-2caf-4bd6-b9f7-b647b16f4d99",
]

for sid in scan_ids:
    req = urllib.request.Request(f"http://localhost:8000/api/scans/{sid}", headers=HEADERS)
    d = json.load(urllib.request.urlopen(req))
    req2 = urllib.request.Request(f"http://localhost:8000/api/findings/?scan_id={sid}&limit=50", headers=HEADERS)
    d2 = json.load(urllib.request.urlopen(req2))
    items = d2.get("items", [])
    types = {}
    for f in items:
        t = f["entity_type"]
        types[t] = types.get(t, 0) + 1
    has_tls = any(f["entity_type"] == "TLS_CERT" for f in items)
    has_hm = any(f["entity_type"] == "HOST_METADATA" for f in items)
    has_ds = any(f.get("normalized_data", {}).get("discovery_source") for f in items if f["entity_type"] == "SUBDOMAIN")

    print(f"\n=== {sid[:8]} target={d['target_domain']} status={d['status']} findings={d['findings_count']} ===")
    print(f"  TLS_CERT: {has_tls} | HOST_METADATA: {has_hm} | discovery_source: {has_ds}")
    print(f"  Types: {json.dumps(types)}")

# If none have new data, run a quick direct collector test
print("\n\n=== NOW RUNNING DIRECT COLLECTOR TEST ===")
import asyncio

async def test():
    from collectors.infrastructure.crtsh import CrtshCollector
    from collectors.infrastructure.shodan_internetdb import ShodanInternetDbCollector

    c = CrtshCollector()
    r = await c.execute("cloudflare.com")
    types = {}
    for item in r:
        t = item["entity_type"]
        types[t] = types.get(t, 0) + 1
    print(f"\ncrtsh: {len(r)} results, types={json.dumps(types)}")
    # Show TLS_CERT sample
    for item in r:
        if item["entity_type"] == "TLS_CERT":
            nd = item["normalized_data"]
            print(f"  Sample TLS_CERT: issuer={nd.get('issuer',{})}")
            print(f"  subdomains_covered={len(nd.get('subdomains_covered',[]))} items")
            break

    c2 = ShodanInternetDbCollector()
    r2 = await c2.execute("8.8.8.8")
    types2 = {}
    for item in r2:
        t = item["entity_type"]
        types2[t] = types2.get(t, 0) + 1
    print(f"\nshodan_internetdb: {len(r2)} results, types={json.dumps(types2)}")
    for item in r2:
        nd = item["normalized_data"]
        print(f"  [{item['entity_type']}] {item['entity_value']}")
        print(f"    hostnames={nd.get('hostnames',[])}")
        print(f"    tags={nd.get('tags',[])}")

asyncio.run(test())
