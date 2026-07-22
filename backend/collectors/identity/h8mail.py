"""h8mail email OSINT collector.

Subprocess wrapper around h8mail CLI. Targets one or more email
addresses and reports where the email shows up across free breach and
identity sources.

Free sources always checked (no API key needed):
  - scylla.so            (free, breach compilation dumps)
  - hunter.io public     (free, related email count)
  - emailrep.io          (email reputation — free tier, rate-limited)

API-key sources (pass via -k flag from .env when configured):
  - hunter.io private    (cleartext related emails — uses HUNTER_API_KEY)
  - haveibeenpwned       (breach count — uses HIBP_API_KEY)
  - emailrep.io full     (reputation + social profiles — EMAILREP_API_KEY)
  - snusbase             (breach data — SNUSBASE_API_KEY)
  - leaklookup           (leak lookup — LEAKLOOKUP_API_KEY)
  - dehashed             (breached credentials — DEHASHED_API_KEY)
  - intelx               (intelligence X — INTELX_API_KEY)

Set the matching env var in backend/.env to activate each source.

GitHub: https://github.com/khast3x/h8mail
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from app.config import settings
from collectors.base import BaseCollector, CollectorMetadata


class H8mailCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="h8mail",
        vector="IDENTITY",
        description="h8mail email OSINT (emailrep, scylla, xposedornot)",
        passive=True,
        requires_api_key=False,
    )

    # h8mail is parallel internally; cap the outer run so a slow source
    # doesn't block the worker forever.
    TIMEOUT = 120

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Run h8mail against one email and parse its output.

        h8mail takes one target at a time via the CLI; for batch runs,
        the calling task iterates over emails.
        """
        if "@" not in target:
            return []

        h8mail_bin = shutil.which("h8mail")
        if not h8mail_bin:
            print("[h8mail] binary not found. Install with: pip install h8mail")
            return []

        # h8mail free sources: scylla.so (breach dumps), hunter.io public
        # (related emails), emailrep.io (reputation). Remove --skip-default
        # so these actually run. API keys for premium services are passed
        # via -k when available.
        with tempfile.TemporaryDirectory(prefix="h8mail_") as tmpdir:
            out_file = Path(tmpdir) / "h8mail_output.json"
            cmd = [
                h8mail_bin,
                "-t", target,
                "-j", str(out_file),  # -j writes JSON (--output writes CSV)
            ]

            # Pass available API keys via -k "KEY=VALUE,KEY=VALUE"
            apikeys = []
            if settings.HUNTER_API_KEY:
                apikeys.append(f"hunterio={settings.HUNTER_API_KEY}")
            if settings.HIBP_API_KEY:
                apikeys.append(f"hibp={settings.HIBP_API_KEY}")
            if settings.EMAILREP_API_KEY:
                apikeys.append(f"emailrep={settings.EMAILREP_API_KEY}")
            if settings.SNUSBASE_API_KEY:
                apikeys.append(f"snusbase={settings.SNUSBASE_API_KEY}")
            if settings.LEAKLOOKUP_API_KEY:
                apikeys.append(f"leaklookup={settings.LEAKLOOKUP_API_KEY}")
            if settings.DEHASHED_API_KEY:
                apikeys.append(f"dehashed={settings.DEHASHED_API_KEY}")
            if settings.INTELX_API_KEY:
                apikeys.append(f"intelx={settings.INTELX_API_KEY}")
            if apikeys:
                cmd.extend(["-k", ",".join(apikeys)])

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.TIMEOUT
                )
            except asyncio.TimeoutError:
                print(f"[h8mail] timed out after {self.TIMEOUT}s for {target}")
                return []
            except Exception as e:
                print(f"[h8mail] subprocess error: {e}")
                return []

        # h8mail writes JSON or text to --output; try JSON first
        if out_file.exists() and out_file.stat().st_size > 0:
            try:
                data = json.loads(out_file.read_text(encoding="utf-8"))
                return self._parse_json(target, data)
            except (json.JSONDecodeError, OSError):
                pass

        # Fall back to text parse if JSON was empty/malformed
        return self._parse_text(target, stdout.decode(errors="ignore"))

    # EmailRep prints: "EmailRep: <summary> | <reputation> | <suspicious> | ..."
    _EMAILREP_RE = re.compile(
        r"EmailRep:\s*(?P<summary>[^|]+)\s*\|\s*(?P<reputation>[^|]+)"
    )
    # h8mail breach header
    _BREACH_HEADER_RE = re.compile(
        r"\[!\]\s*Passwords found:|(?:\[\+\])\s*Breach:\s*([^\s]+)",
        re.IGNORECASE,
    )

    def _parse_json(self, email: str, data: dict) -> List[Dict[str, Any]]:
        """Parse h8mail's JSON output (when --output is JSON)."""
        results: List[Dict[str, Any]] = []
        targets = data.get("targets") or []
        for tgt in targets:
            tgt_email = tgt.get("target", email)
            for breach in tgt.get("data") or tgt.get("breaches") or []:
                results.append({
                    "kind": "breach",
                    "email": tgt_email,
                    "breach_name": breach.get("name") or breach.get("source") or "Unknown",
                    "breach_date": breach.get("date"),
                    "data_classes": breach.get("data", []),
                })
            # EmailRep summary, if present
            er = tgt.get("emailrep") or {}
            if er:
                results.append({
                    "kind": "emailrep",
                    "email": tgt_email,
                    "reputation": er.get("reputation"),
                    "suspicious": er.get("suspicious"),
                    "references": er.get("references"),
                    "details": er,
                })
        return results

    def _parse_text(self, email: str, output: str) -> List[Dict[str, Any]]:
        """Parse h8mail's plain-text output for breach names and EmailRep.

        h8mail's text output looks like (free sources only):

            == Targeting user@example.com ==
            EmailRep: user@example.com has been seen... | high | no | no
            [!] Passwords found:
            [-]   No passwords leaked
            [+] Breach: SomeBreach
            [+] Breach: AnotherBreach
            [i] No API key supplied for some modules, using free ones
        """
        results: List[Dict[str, Any]] = []

        if not output:
            return results

        for line in output.splitlines():
            line = line.strip()

            # EmailRep summary line
            m = self._EMAILREP_RE.search(line)
            if m:
                results.append({
                    "kind": "emailrep",
                    "email": email,
                    "reputation": m.group("reputation").strip(),
                    "summary": m.group("summary").strip(),
                })
                continue

            # Breach line — h8mail 2.5 formats this as "[+] Breach: Name"
            # or "[!]  Found in: Name1, Name2"
            m = re.search(r"\[\+\]\s*Breach:\s*(\S+)", line)
            if m:
                results.append({
                    "kind": "breach",
                    "email": email,
                    "breach_name": m.group(1),
                    "breach_date": None,
                    "data_classes": [],
                })
                continue

            # Some h8mail builds print "Found in: A, B, C" on one line.
            m = re.search(r"Found in:\s*(.+)$", line)
            if m:
                for name in m.group(1).split(","):
                    name = name.strip()
                    if name and name.lower() != "none":
                        results.append({
                            "kind": "breach",
                            "email": email,
                            "breach_name": name,
                            "breach_date": None,
                            "data_classes": [],
                        })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Map h8mail results to BREACH / CREDENTIAL / DOMAIN_METADATA findings.

        h8mail returns a mix of:
          - breach records (BREACH entity)  — comes from scylla + hibp
          - reputation data (PROFILE entity) — comes from emailrep.io
          - sometimes leaked passwords (CREDENTIAL entity, CRITICAL severity)
        """
        kind = raw.get("kind", "breach")

        if kind == "emailrep":
            return {
                "entity_type": "PROFILE",
                "entity_value": f"{raw['email']}::emailrep",
                "severity": "LOW",
                "confidence": 0.75,
                "normalized_data": {
                    "username": raw["email"].split("@")[0],
                    "platform": "emailrep",
                    "url": f"https://emailrep.io/{raw['email']}",
                    "reputation": raw.get("reputation"),
                    "summary": raw.get("summary"),
                    "source": "h8mail_emailrep",
                },
            }

        if kind == "credential":
            return {
                "entity_type": "CREDENTIAL",
                "entity_value": f"{raw['email']}::{raw.get('source', 'unknown')}",
                "severity": "CRITICAL",
                "confidence": 0.9,
                "normalized_data": {
                    "email": raw["email"],
                    "password_hash_or_plain": raw.get("password", ""),
                    "source": raw.get("source", ""),
                    "source_module": "h8mail",
                },
            }

        # Default: breach
        breach_name = raw.get("breach_name", "Unknown")
        return {
            "entity_type": "BREACH",
            "entity_value": f"{raw['email']}::{breach_name}",
            "severity": "HIGH",
            "confidence": 0.85,
            "normalized_data": {
                "email": raw["email"],
                "breach_name": breach_name,
                "breach_date": raw.get("breach_date"),
                "data_classes": raw.get("data_classes", []),
                "source": "h8mail",
            },
        }
