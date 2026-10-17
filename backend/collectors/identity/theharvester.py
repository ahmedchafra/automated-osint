"""theHarvester email/subdomain/host collector.

Subprocess wrapper around theHarvester CLI (pip install theHarvester).
Runs every available source against a target domain and parses the
text output for emails, subdomains, hosts, IPs, people, social-media
profiles, and interesting URLs.

FREE sources (no API key needed — used unconditionally):
  baidu, certspotter, chaos, commoncrawl, crtsh, duckduckgo, gitlab,
  hudsonrock, linkedin, linkedin_links, netcraft, omnisint, otx,
  rapiddns, robtex, shodanInternetDB, subdomaincenter,
  subdomainfinderc99, sublist3r, thc, threatcrowd, urlscan,
  waybackarchive, yahoo

API-KEY sources (activated when .env var is set):
  bevigil, bitbucket, brave, bufferoverun, builtwith, criminalip,
  dehashed, dnsdumpster, dymo, fofa, fullhunt, hackertarget,
  haveibeenpwned, hunterhow, intelx, leakix, leaklookup, mojeek,
  netlas, onyphe, pentesttools, projectdiscovery, rocketreach,
  securityscorecard, securityTrails, sherlockeye, shodan, tomba,
  venacus, virustotal, whoisxml, windvane, zoomeye

  The backend automatically writes your configured .env API keys into
  the theHarvester api-keys.yaml (correct nested format) before each run.

EXCLUDED (would double-burn quota or crash):
  hunter     → we have a dedicated hunter_domain collector
  censys     → theHarvester needs legacy API id+secret, we use PAT
  github     → v4.11.1 key-format bug even with valid GITHUB_TOKEN

NOTE: Uses synchronous subprocess.Popen instead of asyncio.create_subprocess_exec.
The collector runs in a thread pool via task_utils._run_collector_in_loop, so
asyncio subprocesses would inherit pipe fds to Tor (which theHarvester spawns),
causing proc.communicate() to hang. Synchronous subprocess with start_new_session=True
and os.killpg ensures all child processes (including Tor) are cleaned up on timeout.
"""
from __future__ import annotations

import asyncio
import functools
import os
import re
import signal
import subprocess
import shutil
import sys
import tempfile
from typing import Any, Dict, List

import yaml

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class TheHarvesterCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="theharvester",
        vector="IDENTITY",
        description="theHarvester email/subdomain/host enum (all free sources + auto API keys)",
        passive=True,
        requires_api_key=False,
    )

    def __init__(self, free_only: bool = False, timeout: int = 300, limit: int = 500):
        """Create theHarvester collector.

        Args:
            free_only: If True, only use free sources (no API key required).
                        Used by initial_scan.py for fast Phase 1 enumeration.
                        Default False uses all available sources (free + API-key).
            timeout:  Subprocess timeout in seconds. 300 is fine for free-only
                        mode (~24 sources). Full mode (~55 sources) needs ~900s.
            limit:    Per-source result limit passed as -l to theHarvester CLI.
                        Default 500 matches theHarvester's own default.
                        Set higher (e.g. 50000) for deep analysis full mode.
        """
        self.free_only = free_only
        self.TIMEOUT = timeout
        self.LIMIT = limit

    # ── Free sources (no API key needed) ─────────────────────────────────
    # Every source returned by theHarvester's Core.get_supportedengines() that
    # is NOT listed in Core._API_KEY_FIELDS. These are all used unconditionally.
    FAST_FREE = [
        "baidu",
        "certspotter",
        "chaos",
        "commoncrawl",
        "crtsh",
        "duckduckgo",
        "gitlab",
        "hudsonrock",
        "linkedin",
        "linkedin_links",
        "netcraft",
        "omnisint",
        "otx",
        "rapiddns",
        "robtex",
        "shodanInternetDB",
        "subdomaincenter",
        "subdomainfinderc99",
        "sublist3r",
        "thc",
        "threatcrowd",
        "urlscan",
        "waybackarchive",
        "yahoo",
    ]

    # ── API-key sources ────────────────────────────────────────────────
    # The theHarvester's Core._API_KEY_FIELDS defines API-key providers.
    # We map our Settings attr names → theHarvester YAML provider names
    # (keys in the apikeys: section — must match _API_KEY_FIELDS exactly).
    # Only providers whose env var has a non-None value get written into
    # the api-keys.yaml file.
    #
    # NOTE: Source names for the -b argument differ from YAML provider
    # names in a few cases (camelCase vs lowercase). See _source_name()
    # for the mapping.
    #
    # EXCLUDED sources:
    #   hunter    → double-burns 50-free/month quota
    #   censys    → needs legacy id+secret; we use a PAT
    #   github    → v4.11.1 key-format bug even with valid GITHUB_TOKEN
    _SETTINGS_TO_YAML_KEY: dict[str, str] = {
        "SHODAN_API_KEY": "shodan",
        "HIBP_API_KEY": "haveibeenpwned",
        "HACKERTARGET_API_KEY": "hackertarget",
        "BUFFEROVERUN_API_KEY": "bufferoverun",
        "VT_API_KEY": "virustotal",
        "LEAKIX_API_KEY": "leakix",
        "DNSDUMPSTER_API_KEY": "dnsdumpster",
        "SECURITYTRAILS_KEY": "securityTrails",
        "FULLHUNT_API_KEY": "fullhunt",
        "BEVIGIL_API_KEY": "bevigil",
        "TOMBA_API_KEY": "tomba",
        "BRAVE_API_KEY": "brave",
        "DYMO_API_KEY": "dymo",
        "NETLAS_API_KEY": "netlas",
        "CRIMINALIP_API_KEY": "criminalip",
        "HUNTERHOW_API_KEY": "hunterhow",
        "MOJEEK_API_KEY": "mojeek",
        "WINDVANE_API_KEY": "windvane",
        "VENACUS_API_KEY": "venacus",
        "ZOOMEYE_API_KEY": "zoomeye",
        "BUILTWITH_API_KEY": "builtwith",
        "INTELX_API_KEY": "intelx",
        "ONYPHE_API_KEY": "onyphe",
        "FOFA_API_KEY": "fofa",
        "SHERLOCKEYE_API_KEY": "sherlockeye",
        "PENTESTTOOLS_API_KEY": "pentestTools",
        "PROJECTDISCOVERY_KEY": "projectDiscovery",
        "ROCKETREACH_API_KEY": "rocketreach",
        "SECURITYSCORECARD_KEY": "securityscorecard",
        "WHOISXML_API_KEY": "whoisxml",
        "DEHASHED_API_KEY": "dehashed",
        "LEAKLOOKUP_API_KEY": "leaklookup",
    }

    # ── Source names for -b argument ────────────────────────────────────
    # For most sources the -b name matches the YAML provider name, but
    # a few differ in casing (the -b argument uses Core.get_supportedengines()
    # names which are lowercase for some entries where _API_KEY_FIELDS uses
    # camelCase).
    _YAML_KEY_TO_SOURCE: dict[str, str] = {
        "projectDiscovery": "projectdiscovery",
        "pentestTools": "pentesttools",
    }

    # Providers that need special YAML fields beyond just "key".
    _MULTI_FIELD_PROVIDERS: dict[str, dict[str, str]] = {
        "fofa": {"key": "key", "email": "email"},
        "tomba": {"key": "key", "secret": "secret"},
    }

    @staticmethod
    def _yaml_key_to_source(yaml_key: str) -> str:
        """Convert a YAML provider name to theHarvester -b source name."""
        return TheHarvesterCollector._YAML_KEY_TO_SOURCE.get(yaml_key, yaml_key)

    @property
    def sources(self) -> list[str]:
        """Build source list for the -b argument.

        When free_only=True: return only free sources (no API key needed).
        When free_only=False: return all free sources + API sources whose env
        var is set and whose theHarvester provider name is known."""
        if self.free_only:
            return list(self.FAST_FREE)

        sources = list(self.FAST_FREE)

        for attr_name, yaml_key in self._SETTINGS_TO_YAML_KEY.items():
            val = getattr(settings, attr_name, None)
            if val:
                source_name = self._yaml_key_to_source(yaml_key)
                sources.append(source_name)

        return sources

    def _build_cmd(
        self, theharvester_bin: str, target: str, output_base: str
    ) -> list[str]:
        """Build the command list to run theHarvester.

        Uses the wrapper script (which patches aiohttp's resolver for
        Windows + Python 3.13 compatibility) when available, otherwise
        falls back to the raw binary.
        """
        base_args = [
            "-d", target,
            "-b", ",".join(self.sources),
            "-l", str(self.LIMIT),
            "-f", output_base,
        ]

        wrapper = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "scripts",
            "theharvester_runner.py",
        )
        if os.path.exists(wrapper):
            python = shutil.which("python") or sys.executable
            return [python, wrapper, *base_args]

        return [theharvester_bin, *base_args]

    def _ensure_api_keys_yaml(self) -> None:
        """Write ~/.theHarvester/api-keys.yaml in the correct nested format
        theHarvester's Core._read_config + Core.api_keys() expects.

        Format:
            apikeys:
              shodan:
                key: VALUE
              virustotal:
                key: VALUE
              ...
        """
        path = os.path.expanduser("~/.theHarvester/api-keys.yaml")
        os.makedirs(os.path.dirname(path), exist_ok=True)

        apikeys: dict[str, dict[str, str]] = {}
        for attr_name, provider in self._SETTINGS_TO_YAML_KEY.items():
            val = getattr(settings, attr_name, None)
            if not val or not str(val).strip():
                continue

            # Build the provider entry
            if provider in self._MULTI_FIELD_PROVIDERS:
                fields = self._MULTI_FIELD_PROVIDERS[provider]
                entry: dict[str, str] = {}
                for field_key, field_name in fields.items():
                    # For multi-field providers we use the value for the
                    # primary field; secondary fields are empty placeholders.
                    entry[field_key] = val if field_name == field_key else ""
                apikeys[provider] = entry
            else:
                apikeys[provider] = {"key": val}

        with open(path, "w") as f:
            yaml.dump({"apikeys": apikeys}, f, default_flow_style=False)

    # Soft cap — 55 sources in a single subprocess can take several minutes.
    # Each source runs sequentially inside theHarvester. Some (thc, duckduckgo)
    # are slow; others fail fast. We use 300s to cover most normal runs.
    TIMEOUT = 300

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Run theHarvester CLI and parse the text output.

        Uses synchronous subprocess.Popen with start_new_session=True so that
        all child processes (including Tor, which theHarvester spawns) are in
        the same process group. On timeout, os.killpg kills the entire group,
        preventing the pipe-inheritance hang that asyncio.create_subprocess_exec
        suffers from.
        """
        if not target or "." not in target:
            return []

        theharvester_bin = shutil.which("theHarvester")
        if not theharvester_bin:
            print("[theharvester] binary not found. Install with: pip install theHarvester")
            return []

        # Write API keys from env → theHarvester YAML before each run
        self._ensure_api_keys_yaml()

        # A fixed /tmp output name made concurrent scans read and overwrite
        # each other's JSON/XML files. It also allowed a failed run to parse
        # stale data from an earlier target. Give every invocation its own
        # directory and remove it after parsing.
        output_dir = tempfile.mkdtemp(prefix="osint-theharvester-")
        output_base = os.path.join(output_dir, "results")
        cmd = self._build_cmd(theharvester_bin, target, output_base)

        # Use synchronous subprocess to avoid the asyncio subprocess pipe hang
        # caused by Tor inheriting the subprocess file descriptors.
        loop = asyncio.get_event_loop()
        try:
            stdout, stderr = await loop.run_in_executor(
                None, functools.partial(self._run_subprocess, timeout=self.TIMEOUT), cmd
            )

            # Parse text output (always available) plus this run's structured
            # files. The merge applies validation and per-kind safety caps.
            text_results = self._parse_text(target, stdout)
            json_results = self._parse_json_output(target, output_base + ".json")
            xml_results = self._parse_xml_output(target, output_base + ".xml")
            return self._merge_results(
                text_results, json_results + xml_results, domain=target
            )
        finally:
            shutil.rmtree(output_dir, ignore_errors=True)

    def _run_subprocess(self, cmd: list[str], *, timeout: int) -> tuple[str, str]:
        """Run theHarvester subprocess synchronously with a process-group kill.

        This runs in a thread executor (not the main thread) and uses
        start_new_session=True so that theHarvester + Tor share a process
        group. On timeout, killpg kills all processes in the group.

        A timeout kills only the subprocess's own process group. We deliberately
        never use a broad ``pkill tor`` cleanup because the container's shared
        Tor daemon belongs to the Ahmia collector.

        Args:
            cmd:     Command list to execute.
            timeout: Timeout in seconds (self.TIMEOUT from the instance).
        """
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,  # new process group — includes Tor children
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            return stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
        except subprocess.TimeoutExpired:
            print(f"[theharvester] timed out after {timeout}s")
            # Kill the entire process group (theHarvester + Tor + any children)
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            proc.communicate()  # drain pipes after kill
            return "", ""

    def _parse_text(self, domain: str, output: str) -> List[Dict[str, Any]]:
        """Parse theHarvester text output into per-record findings.

        The CLI output is a series of labelled sections like:
            [*] Emails found:
            user@example.com
            ...
            [*] People found:
            John Doe
            ...
            [*] Interesting Urls found:
            https://shodan.io/host/...
            ...
            [*] Hosts found:
            sub.example.com
            ...
        """
        results: List[Dict[str, Any]] = []

        email_re = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
        sub_re = re.compile(
            rf"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)*{re.escape(domain)}",
            re.IGNORECASE,
        )
        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        url_re = re.compile(r"https?://[^\s]+")
        twitter_re = re.compile(r"@(\w+)")

        current_section = ""
        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            # Detect section headers:
            #   "[*] Hosts found: 989"
            #   "Emails found: 3"
            section_match = re.match(
                r"^\s*(?:\[[\*\+-]\]\s*)?([A-Za-z][A-Za-z ]+?)\s*:\s*(?:\d+\s*)?$",
                line,
            )
            if section_match and len(section_match.group(1)) < 35:
                current_section = section_match.group(1).strip().lower()
                continue

            # Strip leading markers ("[+]", "* ", "- ", ".")
            cleaned = re.sub(r"^[\[\(\{\*\-]\s*", "", line).rstrip("])}:") \
                        .strip().lstrip(".")
            if not cleaned:
                continue

            # ── Dispatch by section ───────────────────────────────────────
            if "interesting" in current_section and "url" in current_section:
                m = url_re.search(cleaned)
                if m:
                    results.append({
                        "kind": "url",
                        "value": m.group(0),
                        "domain": domain,
                        "source_section": current_section,
                    })

            elif "twitter" in current_section and "user" in current_section:
                m = twitter_re.search(cleaned)
                if m:
                    results.append({
                        "kind": "twitter",
                        "value": m.group(1),
                        "domain": domain,
                        "source_section": current_section,
                    })
                elif cleaned:
                    results.append({
                        "kind": "twitter",
                        "value": cleaned,
                        "domain": domain,
                        "source_section": current_section,
                    })

            elif "linkedin" in current_section and "user" in current_section:
                if cleaned:
                    results.append({
                        "kind": "linkedin_profile",
                        "value": cleaned,
                        "domain": domain,
                        "source_section": current_section,
                    })

            elif "linkedin" in current_section and "link" in current_section:
                if cleaned.startswith("http"):
                    results.append({
                        "kind": "linkedin_url",
                        "value": cleaned,
                        "domain": domain,
                        "source_section": current_section,
                    })

            elif "people" in current_section:
                if cleaned and not cleaned.startswith("http"):
                    results.append({
                        "kind": "person",
                        "value": cleaned,
                        "domain": domain,
                        "source_section": current_section,
                    })

            elif "email" in current_section:
                m = email_re.search(cleaned)
                if m and m.group(0).lower().endswith("@" + domain.lower()):
                    results.append({
                        "kind": "email",
                        "value": m.group(0).lower(),
                        "domain": domain,
                        "source_section": current_section,
                    })

            elif "host" in current_section or "subdomain" in current_section or "vhost" in current_section:
                m = sub_re.search(cleaned)
                if m and m.group(0).lower() != domain.lower():
                    results.append({
                        "kind": "subdomain",
                        "value": m.group(0).lower(),
                        "domain": domain,
                        "source_section": current_section,
                    })
                ip_match = ip_re.search(cleaned)
                if ip_match:
                    results.append({
                        "kind": "ip",
                        "value": ip_match.group(0),
                        "domain": domain,
                        "source_section": current_section,
                    })

            elif "ip" in current_section:
                m = ip_re.search(cleaned)
                if m:
                    results.append({
                        "kind": "ip",
                        "value": m.group(0),
                        "domain": domain,
                        "source_section": current_section,
                    })

        return results

    def _parse_json_output(
        self, domain: str, output_path: str
    ) -> List[Dict[str, Any]]:
        """Read the JSON output file theHarvester generates via -f.

        The JSON has structured data for ALL sections (emails, hosts, IPs,
        people, ASNs, vhosts, interesting URLs, etc.) which is more reliable
        than regex-parsing the text output.

        Falls back to empty list if the file doesn't exist or is unreadable.
        """
        import json as stdlib_json
        try:
            with open(output_path) as f:
                data = stdlib_json.load(f)
        except (FileNotFoundError, stdlib_json.JSONDecodeError, OSError):
            return []

        results: List[Dict[str, Any]] = []

        # ── Emails ───────────────────────────────────────────────────────
        for email in data.get("emails", []):
            if isinstance(email, str) and "@" in email:
                results.append({
                    "kind": "email",
                    "value": email.strip().lower(),
                    "domain": domain,
                    "source_section": "emails",
                })

        # ── IPs ──────────────────────────────────────────────────────────
        for ip in data.get("ips", []):
            if isinstance(ip, str):
                results.append({
                    "kind": "ip",
                    "value": ip.strip(),
                    "domain": domain,
                    "source_section": "ips",
                })

        # ── Hosts / subdomains (format: "hostname:ip" or "hostname") ─────
        for host_entry in data.get("hosts", []):
            if not isinstance(host_entry, str):
                continue
            if ":" in host_entry:
                hostname, ip_addr = host_entry.rsplit(":", 1)
                hostname = hostname.strip()
                ip_addr = ip_addr.strip()
                if hostname and ip_addr:
                    results.append({
                        "kind": "subdomain",
                        "value": hostname.lower(),
                        "domain": domain,
                        "source_section": "hosts",
                    })
                    results.append({
                        "kind": "ip",
                        "value": ip_addr,
                        "domain": domain,
                        "source_section": "hosts",
                    })
            else:
                hostname = host_entry.strip()
                if hostname:
                    results.append({
                        "kind": "subdomain",
                        "value": hostname.lower(),
                        "domain": domain,
                        "source_section": "hosts",
                    })

        # ── Virtual hosts ────────────────────────────────────────────────
        for vhost_entry in data.get("vhosts", []):
            if not isinstance(vhost_entry, str):
                continue
            if ":" in vhost_entry:
                hostname = vhost_entry.rsplit(":", 1)[0].strip()
            else:
                hostname = vhost_entry.strip()
            if hostname:
                results.append({
                    "kind": "subdomain",
                    "value": hostname.lower(),
                    "domain": domain,
                    "source_section": "vhosts",
                })

        # ── People ───────────────────────────────────────────────────────
        for person in data.get("people", []):
            if isinstance(person, str) and person.strip():
                results.append({
                    "kind": "person",
                    "value": person.strip(),
                    "domain": domain,
                    "source_section": "people",
                })

        # ── Twitter / LinkedIn ───────────────────────────────────────────
        for handle in data.get("twitter_people", []):
            if isinstance(handle, str):
                results.append({
                    "kind": "twitter",
                    "value": handle.strip().lstrip("@"),
                    "domain": domain,
                    "source_section": "twitter_people",
                })
        for profile in data.get("linkedin_people", []):
            if isinstance(profile, str):
                results.append({
                    "kind": "linkedin_profile",
                    "value": profile.strip(),
                    "domain": domain,
                    "source_section": "linkedin_people",
                })
        for link in data.get("linkedin_links", []):
            if isinstance(link, str) and link.startswith("http"):
                results.append({
                    "kind": "linkedin_url",
                    "value": link.strip(),
                    "domain": domain,
                    "source_section": "linkedin_links",
                })

        # ── Interesting URLs ─────────────────────────────────────────────
        for url in data.get("interesting_urls", []):
            if isinstance(url, str) and url.startswith("http"):
                results.append({
                    "kind": "url",
                    "value": url.strip(),
                    "domain": domain,
                    "source_section": "interesting_urls",
                })

        # ── ASNs ─────────────────────────────────────────────────────────
        for asn_entry in data.get("asns", []):
            if isinstance(asn_entry, str) and asn_entry.strip():
                results.append({
                    "kind": "asn",
                    "value": asn_entry.strip(),
                    "domain": domain,
                    "source_section": "asns",
                })

        # ── Trello URLs ──────────────────────────────────────────────────
        for url in data.get("trello_urls", []):
            if isinstance(url, str) and url.startswith("http"):
                results.append({
                    "kind": "url",
                    "value": url.strip(),
                    "domain": domain,
                    "source_section": "trello_urls",
                })

        # ── Takeover results (subdomain takeover vulnerabilities) ────────
        # Skipped: not yet mapped to an entity type. The data is available
        # in the JSON output if takeover checks are ever enabled.
        # takeover = data.get("takeover_results", {})

        return results

    def _parse_xml_output(
        self, domain: str, output_path: str
    ) -> List[Dict[str, Any]]:
        """Read the XML output file theHarvester generates via -f.

        The XML output contains host:IP mappings (<host><ip/><hostname/>)
        which the text output doesn't always pair cleanly, plus additional
        email entries.
        """
        import xml.etree.ElementTree as ET
        try:
            tree = ET.parse(output_path)
            root = tree.getroot()
        except (FileNotFoundError, ET.ParseError, OSError):
            return []

        results: List[Dict[str, Any]] = []

        for child in root:
            if child.tag == "host":
                ip_elem = child.find("ip")
                hn_elem = child.find("hostname")
                if ip_elem is not None and hn_elem is not None:
                    # Hostname + IP mapping
                    hostname = (hn_elem.text or "").strip().lower()
                    ip_addr = (ip_elem.text or "").strip()
                    if hostname and ip_addr:
                        results.append({
                            "kind": "subdomain",
                            "value": hostname,
                            "domain": domain,
                            "source_section": "hosts",
                        })
                        results.append({
                            "kind": "ip",
                            "value": ip_addr,
                            "domain": domain,
                            "source_section": "hosts",
                        })
                else:
                    # Plain hostname (no IP)
                    hostname = (child.text or "").strip().lower()
                    if hostname:
                        results.append({
                            "kind": "subdomain",
                            "value": hostname,
                            "domain": domain,
                            "source_section": "hosts",
                        })

            elif child.tag == "email":
                email = (child.text or "").strip().lower()
                if "@" in email:
                    results.append({
                        "kind": "email",
                        "value": email,
                        "domain": domain,
                        "source_section": "emails",
                    })

            elif child.tag == "vhost":
                ip_elem = child.find("ip")
                hn_elem = child.find("hostname")
                if ip_elem is not None and hn_elem is not None:
                    hostname = (hn_elem.text or "").strip().lower()
                    if hostname:
                        results.append({
                            "kind": "subdomain",
                            "value": hostname,
                            "domain": domain,
                            "source_section": "vhosts",
                        })
                else:
                    hostname = (child.text or "").strip().lower()
                    if hostname:
                        results.append({
                            "kind": "subdomain",
                            "value": hostname,
                            "domain": domain,
                            "source_section": "vhosts",
                        })

        return results

    @staticmethod
    def _merge_results(
        *result_lists: List[Dict[str, Any]], domain: str = ""
    ) -> List[Dict[str, Any]]:
        """Deduplicate results across parsing methods.

        JSON output is more reliable than text parsing (structured vs regex),
        so JSON results take precedence. Dedup key: (kind, value).
        """
        import ipaddress

        seen: set[tuple[str, str]] = set()
        merged: List[Dict[str, Any]] = []
        counts: dict[str, int] = {}
        caps = {
            "subdomain": 500,
            "ip": 250,
            "email": 500,
            "url": 500,
            "person": 500,
        }
        root = domain.strip().lower().rstrip(".")

        for results in result_lists:
            for item in results:
                key = (item.get("kind", ""), item.get("value", ""))
                if not key[0] or not key[1]:
                    continue
                kind, value = key[0], str(key[1]).strip().lower()
                if kind == "subdomain":
                    if value.startswith("*.") or not value.endswith("." + root):
                        continue
                    labels = value.split(".")
                    if any(
                        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                        for label in labels
                    ):
                        continue
                elif kind == "email" and not value.endswith("@" + root):
                    continue
                elif kind == "ip":
                    try:
                        if not ipaddress.ip_address(value).is_global:
                            continue
                    except ValueError:
                        continue
                if counts.get(kind, 0) >= caps.get(kind, 1000):
                    continue
                if key not in seen:
                    seen.add(key)
                    merged.append(item)
                    counts[kind] = counts.get(kind, 0) + 1

        return merged

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Map theHarvester output to platform entity types."""
        kind = raw.get("kind", "email")
        value = raw.get("value", "")
        section = raw.get("source_section", "")
        domain = raw.get("domain", "")

        if kind == "email":
            return {
                "entity_type": "EMAIL",
                "entity_value": value,
                "severity": "LOW",
                "confidence": 0.7,
                "normalized_data": {
                    "email": value,
                    "domain": domain,
                    "source": "theharvester",
                    "source_section": section,
                },
            }

        if kind == "subdomain":
            return {
                "entity_type": "SUBDOMAIN",
                "entity_value": value,
                "severity": "INFO",
                "confidence": 0.75,
                "normalized_data": {
                    "subdomain": value,
                    "parent_domain": domain,
                    "source": "theharvester",
                    "source_section": section,
                },
            }

        if kind == "ip":
            return {
                "entity_type": "IP_ADDRESS",
                "entity_value": value,
                "severity": "INFO",
                "confidence": 0.7,
                "normalized_data": {
                    "ip": value,
                    "domain": domain,
                    "source": "theharvester",
                    "source_section": section,
                },
            }

        if kind in ("person", "twitter", "linkedin_profile", "linkedin_url"):
            profile_data: dict[str, Any] = {
                "full_name": value if kind == "person" else "",
                "source": "theharvester",
                "source_section": section,
            }
            if kind == "twitter":
                profile_data["twitter_handle"] = value
            if kind == "linkedin_profile":
                profile_data["linkedin_profile"] = value
            if kind == "linkedin_url":
                profile_data["linkedin_url"] = value
                return {
                    "entity_type": "PROFILE",
                    "entity_value": value,
                    "severity": "LOW",
                    "confidence": 0.6,
                    "normalized_data": profile_data,
                }

            return {
                "entity_type": "PROFILE",
                "entity_value": value,
                "severity": "LOW",
                "confidence": 0.6,
                "normalized_data": profile_data,
            }

        if kind == "url":
            return {
                "entity_type": "URL",
                "entity_value": value,
                "severity": "INFO",
                "confidence": 0.7,
                "normalized_data": {
                    "url": value,
                    "domain": domain,
                    "source": "theharvester",
                    "source_section": section,
                },
            }

        if kind == "asn":
            return {
                "entity_type": "ASN_INFO",
                "entity_value": value,
                "severity": "INFO",
                "confidence": 0.7,
                "normalized_data": {
                    "asn": value,
                    "domain": domain,
                    "source": "theharvester",
                },
            }

        # Fallback
        return {
            "entity_type": kind.upper() if kind else "INFO",
            "entity_value": value,
            "severity": "INFO",
            "confidence": 0.5,
            "normalized_data": {
                "kind": kind,
                "value": value,
                "domain": domain,
                "source": "theharvester",
                "source_section": section,
            },
        }
