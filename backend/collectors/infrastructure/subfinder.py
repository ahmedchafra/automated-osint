import asyncio
import json
import os
import shutil
import subprocess
from typing import List, Dict, Any

from collectors.base import BaseCollector, CollectorMetadata


class SubfinderCollector(BaseCollector):
    metadata = CollectorMetadata(
        name="subfinder",
        vector="INFRASTRUCTURE",
        description="Subfinder passive subdomain enumeration (40+ sources)",
        passive=True,
        requires_api_key=False,
    )

    async def collect(self, target: str) -> List[Dict[str, Any]]:
        """
        Run subfinder as a subprocess to enumerate subdomains.
        Returns a list of dicts with subdomain + source info.
        If subfinder is not installed or fails, returns empty list.
        """
        # Clean the target (remove protocol, path, etc.)
        target = target.replace("https://", "").replace("http://", "").split("/")[0]
        target = target.strip().rstrip(".")  # subfinder expects clean domain

        # Check if subfinder binary exists in PATH
        subfinder_path = shutil.which("subfinder")
        if not subfinder_path:
            print("[subfinder] subfinder binary not found in PATH. Skipping.")
            return []

        # Build command: subfinder -d {target} -silent -json
        # -silent suppresses progress output
        # -json outputs one JSON object per line
        cmd = [subfinder_path, "-d", target, "-silent", "-json"]

        try:
            # Run the command with a timeout via synchronous subprocess
            # (avoids asyncio subprocess hang in thread-pool event loops on Linux)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=60.0,
                ),
            )

            if result.returncode != 0:
                err_msg = result.stderr.decode().strip()[:200]
                print(f"[subfinder] non-zero exit {result.returncode} for {target}: {err_msg}")
                return []

            # Parse JSON lines — subfinder -json outputs one JSON obj per line
            output = result.stdout.decode(errors="ignore")
            results_by_host: dict[str, dict] = {}

            def record_host(host: str, source: str, input_value: str) -> None:
                existing = results_by_host.get(host)
                if existing is None:
                    results_by_host[host] = {
                        "type": "SUBDOMAIN",
                        "value": host,
                        "source": source,
                        "sources": [source] if source else [],
                        "input": input_value,
                    }
                    return
                sources = set(existing.get("sources", []))
                if source:
                    sources.add(source)
                existing["sources"] = sorted(sources)

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    host = obj.get("host", "").strip().lower()
                    if host and host.endswith(target):
                        record_host(
                            host,
                            str(obj.get("source", "unknown")),
                            str(obj.get("input", target)),
                        )
                except json.JSONDecodeError:
                    # If not JSON, maybe it's plain text fallback
                    # Some versions output plain text; try to treat line as host
                    possible = line.strip().lower()
                    if possible and possible.endswith(target):
                        record_host(possible, "unknown", target)
                    continue

            return list(results_by_host.values())

        except FileNotFoundError:
            print("[subfinder] subfinder binary not found")
            return []
        except subprocess.TimeoutExpired:
            print(f"[subfinder] timeout after 60s for target {target}")
            return []
        except Exception as e:
            print(f"[subfinder] unexpected error: {e}")
            return []

    def normalize(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "entity_type": "SUBDOMAIN",
            "entity_value": raw.get("value", ""),
            "severity": "INFO",
            "confidence": 0.95,
            "normalized_data": {
                "source": "subfinder",
                "subdomain": raw.get("value", ""),
                "discovery_source": raw.get("source", "unknown"),  # which subfinder source found it
                "provider_sources": raw.get("sources", []),
                "input": raw.get("input", ""),
            },
        }
