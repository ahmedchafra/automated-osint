"""Quick test of censys-platform SDK response format."""
import os
import sys

# Read the API token from .env
token = "censys_2V9vaPcc_MS8zTtGmVJRLa3zXNfC6xsA3"

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
            print(f"Banner: {svc.get('banner', '')[:100]}")
    else:
        print(f"Dir: {[x for x in dir(host) if not x.startswith('_')]}")
        # Try accessing as object
        print(f"Services attr: {host.services if hasattr(host, 'services') else 'N/A'}")
except Exception as e:
    print(f"Error: {type(e).__name__}: {e}")
