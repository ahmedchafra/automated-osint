"""Central target-scope policy used by discovery and active collectors."""
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
import ipaddress
from urllib.parse import urlparse

from app.services.asset_service import canonical_hostname


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


def default_scope_manifest(target_type: str, target: str) -> dict:
    manifest = {
        "allowed_domains": [],
        "allowed_cidrs": [],
        "excluded_domains": [],
        "excluded_cidrs": [],
        "excluded_url_paths": [],
        "allowed_ports": [],
        "allow_subdomains": True,
        "allow_resolved_ips": True,
        "included_assets": [],
    }
    if target_type == "ip":
        address = ipaddress.ip_address(target)
        manifest["allowed_cidrs"] = [f"{address}/{address.max_prefixlen}"]
    elif target_type == "domain":
        manifest["allowed_domains"] = [canonical_hostname(target)]
    return manifest


def normalized_scope_manifest(manifest: dict | None, target_type: str, target: str) -> dict:
    result = default_scope_manifest(target_type, target)
    if not manifest:
        return result
    for key in (
        "allowed_domains", "allowed_cidrs", "excluded_domains",
        "excluded_cidrs", "excluded_url_paths", "allowed_ports",
    ):
        if key in manifest:
            result[key] = list(manifest[key] or [])
    result["included_assets"] = list(manifest.get("included_assets") or [])
    for key in ("allow_subdomains", "allow_resolved_ips"):
        if key in manifest:
            result[key] = bool(manifest[key])
    if target_type == "domain" and target:
        root = canonical_hostname(target)
        if root not in result["allowed_domains"]:
            result["allowed_domains"].append(root)
    elif target_type == "ip" and target:
        address = ipaddress.ip_address(target)
        host_cidr = f"{address}/{address.max_prefixlen}"
        if host_cidr not in result["allowed_cidrs"]:
            result["allowed_cidrs"].append(host_cidr)
    return result


class ScopeEvaluator:
    def __init__(self, manifest: dict | None, *, target_type: str = "domain", target: str = ""):
        self.manifest = normalized_scope_manifest(manifest, target_type, target)
        self.allowed_domains = tuple(canonical_hostname(v) for v in self.manifest["allowed_domains"])
        self.excluded_domains = tuple(canonical_hostname(v) for v in self.manifest["excluded_domains"])
        self.allowed_networks = tuple(ipaddress.ip_network(v, strict=False) for v in self.manifest["allowed_cidrs"])
        self.excluded_networks = tuple(ipaddress.ip_network(v, strict=False) for v in self.manifest["excluded_cidrs"])
        self.included_assets = frozenset(self.manifest["included_assets"])

    @staticmethod
    def _matches_domain(hostname: str, rule: str, include_children: bool = True) -> bool:
        return hostname == rule or (include_children and hostname.endswith(f".{rule}"))

    def evaluate_hostname(self, value: str) -> ScopeDecision:
        try:
            hostname = canonical_hostname(value)
        except (UnicodeError, ValueError):
            return ScopeDecision(False, "invalid hostname")
        if any(self._matches_domain(hostname, rule) for rule in self.excluded_domains):
            return ScopeDecision(False, "matches excluded domain")
        include_children = self.manifest["allow_subdomains"]
        if any(self._matches_domain(hostname, rule, include_children) for rule in self.allowed_domains):
            return ScopeDecision(True, "matches allowed domain")
        return ScopeDecision(False, "outside allowed domains")

    def evaluate_ip(self, value: str, *, derived_from_allowed_host: bool = False) -> ScopeDecision:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return ScopeDecision(False, "invalid IP address")
        if not address.is_global:
            return ScopeDecision(False, "non-public IP address blocked")
        if any(address in network for network in self.excluded_networks):
            return ScopeDecision(False, "matches excluded CIDR")
        if any(address in network for network in self.allowed_networks):
            return ScopeDecision(True, "matches allowed CIDR")
        if derived_from_allowed_host and self.manifest["allow_resolved_ips"]:
            return ScopeDecision(True, "resolved from allowed hostname")
        return ScopeDecision(False, "outside allowed CIDRs")

    def evaluate_port(self, port: int) -> ScopeDecision:
        if not 1 <= port <= 65535:
            return ScopeDecision(False, "invalid port")
        allowed = self.manifest["allowed_ports"]
        if allowed and port not in allowed:
            return ScopeDecision(False, "port not explicitly allowed")
        return ScopeDecision(True, "port allowed")

    def evaluate_url(self, value: str) -> ScopeDecision:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ScopeDecision(False, "only HTTP(S) URLs are allowed")
        host_decision = self.evaluate_hostname(parsed.hostname)
        if not host_decision.allowed:
            return host_decision
        path = parsed.path or "/"
        if any(fnmatch(path, pattern) for pattern in self.manifest["excluded_url_paths"]):
            return ScopeDecision(False, "matches excluded URL path")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            return ScopeDecision(False, "invalid URL port")
        return self.evaluate_port(port)

    def evaluate_asset(self, asset_type: str, value: str, *, derived: bool = False) -> ScopeDecision:
        inclusion_key = f"{asset_type}:{value.strip()}"
        if inclusion_key in self.included_assets:
            if asset_type == "IP_ADDRESS" and not self.evaluate_ip(value, derived_from_allowed_host=True).allowed:
                return ScopeDecision(False, "manual inclusion rejected: IP is not public")
            return ScopeDecision(True, "manually included")
        if asset_type in {"DOMAIN", "SUBDOMAIN"}:
            return self.evaluate_hostname(value)
        if asset_type == "IP_ADDRESS":
            return self.evaluate_ip(value, derived_from_allowed_host=derived)
        if asset_type == "URL":
            return self.evaluate_url(value)
        return ScopeDecision(False, "asset type is not scannable")
