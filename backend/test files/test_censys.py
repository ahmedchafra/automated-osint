"""Quick test of censys-platform SDK response format."""
import os
import sys

token = os.environ.get("CENSYS_API_SECRET", "")
print(f"Token present: {bool(token)}, length: {len(token)}")

from censys.search import CensysHosts

client = CensysHosts(api_token=token)

try:
    host = client.view("8.8.8.8")
    print(f"Type: {type(host)}")
    if isinstance(host, dict):
        print(f"Top-level keys: {list(host.keys())}")
        services = host.get("services", [])
        print(f"Services count: {len(services)}")
        if services:
            svc = services[0]
            print(f"First service keys: {list(svc.keys())}")
            print(f"Port: {svc.get('port')}")
            print(f"Service name: {svc.get('service_name')}")
    else:
        print(f"Dir: {[x for x in dir(host) if not x.startswith('_')]}")
        # Try accessing as object
        if hasattr(host, 'services'):
            svcs = host.services
            print(f"Services attr type: {type(svcs)}, len: {len(svcs) if svcs else 0}")
            if svcs:
                svc = svcs[0]
                print(f"Service type: {type(svc)}")
                print(f"Service dir: {[x for x in dir(svc) if not x.startswith('_')]}")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
