"""Holehe email-to-platform collector.

Uses the holehe CLI tool (pip install holehe) to check which platforms
an email address is registered on. Runs as a subprocess since holehe
uses trio/asyncio internally and is designed as a CLI tool.

No API key required — queries sites' registration/password-recovery endpoints.
GitHub: https://github.com/megadose/holehe

Holehe v1.61 does not have a --json flag. It outputs colored text to stdout
and optionally writes CSV with --csv. We parse the text output for [+] markers,
filtering out non-platform status lines.
"""
from __future__ import annotations

import asyncio
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from collectors.base import BaseCollector, CollectorMetadata


class HoleheCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="holehe",
        vector="IDENTITY",
        description="Holehe email-to-platform registration checker",
        passive=True,
        requires_api_key=False,
    )

    TIMEOUT = 120  # holehe can be slow checking many sites

    # Holehe text output lines look like:
    #   [+] PlatformName : https://platform.com/user
    #   [+] PlatformName
    # We exclude status/summary lines that are not real platform names.
    _POSITIVE_RE = re.compile(r'\[\+\]\s+(.+?)\s*:\s*(https?://\S+)')
    _POSITIVE_NAME_RE = re.compile(r'\[\+\]\s+(.+)')

    # Lines that are definitely not platform names
    _NON_PLATFORM = re.compile(
        r'(email used|not used|rate limit|rate_limit|'
        r'^\d+$|^[a-z]+ [a-z]+ used|'
        r'checking|results|done|finished|completed)',
        re.IGNORECASE,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Run holehe CLI against an email and parse text output."""
        if "@" not in target:
            return []

        holehe_bin = shutil.which("holehe")
        if not holehe_bin:
            print("[holehe] binary not found. Install with: pip install holehe")
            return []

        cmd = [
            holehe_bin, target,
            "--no-clear",
            "--no-color",
        ]

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
            print(f"[holehe] timed out after {self.TIMEOUT}s for {target}")
            return []
        except Exception as e:
            print(f"[holehe] subprocess error: {e}")
            return []

        return self._parse_text(target, stdout.decode())

    def _parse_csv(self, email: str, csv_path: str) -> List[Dict[str, Any]]:
        """Parse holehe CSV output file."""
        results: List[Dict[str, Any]] = []
        try:
            path = Path(csv_path)
            if not path.exists() or path.stat().st_size == 0:
                return []
            text = path.read_text(encoding="utf-8")
        except OSError:
            return []

        for line in text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("name,") or line.startswith("domain"):
                continue  # skip header
            parts = line.split(",", 2)
            if len(parts) >= 2:
                platform = parts[0].strip().strip('"')
                domain = parts[1].strip().strip('"')
                url = parts[2].strip().strip('"') if len(parts) > 2 else ""
                if platform and platform.lower() != "name":
                    results.append({
                        "email": email,
                        "platform": platform,
                        "domain": domain,
                        "url": url,
                        "exists": True,
                    })

        return results

    def _parse_text(self, email: str, output: str) -> List[Dict[str, Any]]:
        """Parse holehe text output for [+] lines, filtering non-platform lines."""
        results: List[Dict[str, Any]] = []
        seen_platforms = set()

        for line in output.splitlines():
            # Strip ANSI color codes
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line).strip()
            if not clean:
                continue

            # 1. Try matching platform with URL: [+] PlatformName : https://...
            m = self._POSITIVE_RE.match(clean)
            if m:
                platform = m.group(1).strip()
                url = m.group(2).strip()
                key = platform.lower()
                if key not in seen_platforms and not self._NON_PLATFORM.search(platform):
                    seen_platforms.add(key)
                    results.append({
                        "email": email,
                        "platform": platform,
                        "domain": "",
                        "url": url,
                        "exists": True,
                    })
                continue

            # 2. Fallback: match [+] PlatformName without a URL, but
            #    exclude non-platform status/summary lines.
            if clean.startswith('[+]'):
                candidate = clean[3:].strip()
                if not candidate:
                    continue
                # Ignore lines that look like status summaries
                if self._NON_PLATFORM.search(candidate):
                    continue
                key = candidate.lower()
                if key not in seen_platforms:
                    seen_platforms.add(key)
                    results.append({
                        "email": email,
                        "platform": candidate,
                        "domain": "",
                        "url": "",
                        "exists": True,
                    })

        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "EMAIL_PLATFORM",
            "entity_value": f"{raw['email']}@{raw['platform']}",
            "severity": "INFO",
            "confidence": 0.85,
            "normalized_data": {
                "email": raw["email"],
                "platform": raw["platform"],
                "domain": raw.get("domain", ""),
                "url": raw.get("url", ""),
                "registered": raw.get("exists", False),
                "source": "holehe",
            },
        }
