"""Check TLS_CERT quality in scan b3b92b8e."""
import urllib.request, json

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZWUyOTRhYy1iZjk0LTQxMDktOWM1ZS05ZGRlZmNiMjI1NTAiLCJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6ImFkbWluIiwiZXhwIjoxNzg0MDY1NzE5fQ.I_cQQZUnLlnNx6kg3CDWxpuvt-bgFVFfVwPs5sXejg8"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

req = urllib.request.Request("http://localhost:8000/api/findings/?scan_id=b3b92b8e-ef82-4cb8-b08e-afbf0bafe11a&limit=100", headers=HEADERS)
d = json.load(urllib.request.urlopen(req))
items = d.get("items", [])

print(f"Total items sampled: {len(items)}")

tls_certs = [f for f in items if f["entity_type"] == "TLS_CERT"]
print(f"\nTLS_CERT entries: {len(tls_certs)}")

for i, cert in enumerate(tls_certs[:5]):
    nd = cert.get("normalized_data", {})
    print(f"\n--- TLS_CERT #{i+1} ---")
    print(f"  value: {cert['entity_value'][:60]}")
    print(f"  source: {cert.get('source_module','?')}")
    print(f"  subject: {nd.get('subject',{})}")
    print(f"  issuer: {nd.get('issuer',{})}")
    print(f"  serial: {str(nd.get('serial',''))[:30]}")
    print(f"  not_before: {str(nd.get('not_before',''))[:10]}")
    print(f"  not_after: {str(nd.get('not_after',''))[:10]}")
    subs = nd.get("subdomains_covered", [])
    print(f"  subdomains_covered: {len(subs)} items")

# Also check raw_data to see what was stored
if tls_certs:
    rd = tls_certs[0].get("raw_data", {})
    print(f"\nRaw data keys: {list(rd.keys()) if isinstance(rd, dict) else type(rd).__name__}")

# Now check subdomains for discovery_source
subdomains = [f for f in items if f["entity_type"] == "SUBDOMAIN"]
print(f"\nSUBDOMAIN entries: {len(subdomains)}")
for s in subdomains[:3]:
    nd = s.get("normalized_data", {})
    print(f"  {s['entity_value']} src={s.get('source_module','?')} disc_src={nd.get('discovery_source','N/A')}")
