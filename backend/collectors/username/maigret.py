"""Maigret username-to-profiles collector.

Uses the maigret CLI tool (pip install maigret) to search 3,000+ sites
for a given username. Runs as a subprocess since maigret is designed as
a CLI tool with its own async event loop.

No API key required for core functionality.
GitHub: https://github.com/soxoj/maigret
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from collectors.base import BaseCollector, CollectorMetadata


class MaigretCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="maigret",
        vector="USERNAME",
        description="Maigret username OSINT (3000+ sites)",
        passive=True,
        requires_api_key=False,
    )

    # Generous outer cap so maigret has time to check many sites. It writes
    # NDJSON incrementally, so if the TIMEOUT fires we still get partial
    # results from whatever was discovered so far.
    TIMEOUT = 600  # 10 minutes — soft cap, partial results returned on timeout

    # Per-site network timeout. 4s is tight enough to keep things moving
    # while still giving legitimate sites time to respond.
    PER_SITE_TIMEOUT = 4

    # Number of sites to check (via --top-sites, ranked by Alexa Top).
    # Default maigret is 500; we set 500 for reliable completion times.
    SITE_LIMIT = 500

    # Max concurrent HTTP connections. Higher = faster completion but more
    # aggressive on source servers. 20 is a good balance.
    MAX_CONNECTIONS = 20

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """Run maigret CLI against a username and parse NDJSON output.

        Returns partial results even if maigret is killed by the timeout —
        the NDJSON report file is written incrementally so we can recover
        what was discovered before the deadline.
        """
        username = target.strip().lstrip("@")
        if not username:
            return []

        maigret_bin = shutil.which("maigret")
        if not maigret_bin:
            print("[maigret] binary not found. Install with: pip install maigret")
            return []

        with tempfile.TemporaryDirectory(prefix="maigret_") as tmpdir:
            cmd = [
                maigret_bin,
                "--json", "ndjson",
                "--folderoutput", tmpdir,
                "--no-progressbar",
                "--timeout", str(self.PER_SITE_TIMEOUT),
                "--retries", "0",
                "-n", str(self.MAX_CONNECTIONS),     # concurrent connections
                "--top-sites", str(self.SITE_LIMIT), # total sites to check
                "--no-recursion",                     # skip recursive search
                "--no-extracting",                    # skip page parsing
                username,
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
                # Maigret was killed — but it writes the NDJSON report
                # incrementally, so we can still recover partial results
                # from the tempdir before it gets cleaned up. We have to
                # escape the context manager to read the files first.
                # Strategy: copy report out before letting tempdir die.
                print(f"[maigret] timed out after {self.TIMEOUT}s for {username}, "
                      "returning partial results")
                return self._read_reports(tmpdir, username)
            except Exception as e:
                print(f"[maigret] subprocess error: {e}")
                return []

            # Maigret writes NDJSON (one JSON object per line) to a report file.
            # Read all .json files from the temp directory and parse line-by-line.
            return self._read_reports(tmpdir, username)

    def _read_reports(self, tmpdir: str, username: str) -> List[Dict[str, Any]]:
        """Parse NDJSON report files left by maigret in tmpdir.

        Works on partial output too — maigret flushes each result line as
        it finds (or rules out) a site, so this returns whatever was
        discovered before the process exited or was killed.
        """
        results: List[Dict[str, Any]] = []
        for report_path in Path(tmpdir).glob("*.json"):
            try:
                text = report_path.read_text(encoding="utf-8")
            except OSError:
                continue
            for line in text.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                url = item.get("url_user") or item.get("url_main") or item.get("url")
                if not url:
                    continue
                sitename = item.get("sitename") or item.get("site", {}).get("name", "unknown")
                tags = item.get("site", {}).get("tags", []) if isinstance(item.get("site"), dict) else []
                status_raw = item.get("status", "found")
                if isinstance(status_raw, dict):
                    status_str = status_raw.get("status", "found") if isinstance(status_raw, dict) else str(status_raw)
                else:
                    status_str = str(status_raw)
                results.append({
                    "username": username,
                    "platform": sitename,
                    "url": url,
                    "status": status_str,
                    "tags": tags,
                    "found": status_str.lower() in ("found", "claimed"),
                })
        return results

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "PROFILE",
            "entity_value": raw["url"],
            "severity": "INFO",
            "confidence": 0.8,
            "normalized_data": {
                "username": raw["username"],
                "platform": raw["platform"],
                "url": raw["url"],
                "status": raw.get("status", "found"),
                "tags": raw.get("tags", []),
                "source": "maigret",
            },
        }
