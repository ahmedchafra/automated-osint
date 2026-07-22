"""Test script to run theHarvester and h8mail locally on utm.tn.
Writes results to test_output.log so we can read it."""
import sys
import os
import json
import subprocess
import tempfile
import shutil
from pathlib import Path

LOG = Path(__file__).parent / "test_output.log"

def log(msg):
    print(msg)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

# Clear log
LOG.write_text("", encoding="utf-8")

log("=" * 60)
log("TESTING THEHARVESTER + H8MAIL")
log("=" * 60 + "\n")

# ── Test 0: Python / environment ──
log(f"Python: {sys.executable}")
log(f"Path: {os.environ.get('PATH', '')[:500]}")
log("")

# ── Test 1: theHarvester ──
log("=" * 60)
log("TEST 1: theHarvester on utm.tn")
log("=" * 60)

th_bin = shutil.which("theHarvester")
log(f"theHarvester binary: {th_bin}")

if th_bin:
    try:
        version = subprocess.run([th_bin, "--version"], capture_output=True, text=True, timeout=15)
        log(f"Version stdout: {version.stdout[:200]}")
        log(f"Version stderr: {version.stderr[:200]}")
    except Exception as e:
        log(f"Version check error: {e}")

    # Test with a small set of fast sources first
    try:
        log("\nRunning theHarvester -d utm.tn -b thc,crtsh,certspotter -l 50 ...")
        result = subprocess.run(
            [th_bin, "-d", "utm.tn", "-b", "thc,crtsh,certspotter,duckduckgo,yahoo,robtex",
             "-l", "50", "-f", "/tmp/th_test"],
            capture_output=True, text=True, timeout=120
        )
        log(f"\ntheHarvester stdout ({len(result.stdout)} chars):")
        log(result.stdout[:3000])
        if result.stderr:
            log(f"\ntheHarvester stderr ({len(result.stderr)} chars):")
            log(result.stderr[:1500])
        log(f"\nReturn code: {result.returncode}")
    except subprocess.TimeoutExpired:
        log("\ntheHarvester timed out (120s)")
    except Exception as e:
        log(f"\ntheHarvester error: {e}")
else:
    log("theHarvester NOT found - checking pip...")
    try:
        pip_check = subprocess.run(
            [sys.executable, "-m", "pip", "show", "theHarvester"],
            capture_output=True, text=True, timeout=30
        )
        log(f"pip show: {pip_check.stdout[:500]}")
        if pip_check.stderr:
            log(f"pip stderr: {pip_check.stderr[:200]}")
    except Exception as e:
        log(f"pip error: {e}")

# ── Test 2: h8mail ──
log("\n" + "=" * 60)
log("TEST 2: h8mail on test@utm.tn")
log("=" * 60)

h8_bin = shutil.which("h8mail")
log(f"h8mail binary: {h8_bin}")

if h8_bin:
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "h8_output.json")
            log(f"\nRunning h8mail -t test@utm.tn -j {out_file} ...")
            result = subprocess.run(
                [h8_bin, "-t", "test@utm.tn", "-j", out_file],
                capture_output=True, text=True, timeout=60
            )
            log(f"\nh8mail stdout ({len(result.stdout)} chars):")
            log(result.stdout[:3000])
            if result.stderr:
                log(f"\nh8mail stderr ({len(result.stderr)} chars):")
                log(result.stderr[:1500])
            log(f"\nReturn code: {result.returncode}")
            if os.path.exists(out_file):
                with open(out_file) as f:
                    data = json.load(f)
                log(f"\nh8mail JSON output:")
                log(json.dumps(data, indent=2)[:3000])
    except subprocess.TimeoutExpired:
        log("\nh8mail timed out (60s)")
    except Exception as e:
        log(f"\nh8mail error: {e}")
else:
    log("h8mail NOT found")
    try:
        pip_check = subprocess.run(
            [sys.executable, "-m", "pip", "show", "h8mail"],
            capture_output=True, text=True, timeout=30
        )
        log(f"pip show: {pip_check.stdout[:500]}")
    except Exception as e:
        log(f"pip error: {e}")

# ── Test 3: Registry check ──
log("\n" + "=" * 60)
log("TEST 3: Collector registry")
log("=" * 60)

try:
    sys.path.insert(0, str(Path(__file__).parent / "backend"))
    from collectors.registry import registry
    for name in ["theharvester", "h8mail", "serper_dork_search", "serper_search"]:
        try:
            cls = registry.get_collector(name)
            inst = cls()
            m = inst.metadata
            log(f"  ✓ {name}: vector={m.vector}, passive={m.passive}, key={m.requires_api_key}")
        except Exception as e:
            log(f"  ✗ {name}: {e}")
except Exception as e:
    log(f"Registry error: {e}")

# ── Test 4: Dork config ──
log("\n" + "=" * 60)
log("TEST 4: Dork config check")
log("=" * 60)

try:
    from app.config import settings
    log(f"  SERPER_API_KEY set: {bool(settings.SERPER_API_KEY)}")
    log(f"  GROQ_API_KEY set: {bool(settings.GROQ_API_KEY)}")
    log(f"  GROQ_API_KEY value: {settings.GROQ_API_KEY[:10] + '...' if settings.GROQ_API_KEY else 'EMPTY'}")
except Exception as e:
    log(f"Config error: {e}")

log("\n" + "=" * 60)
log("DONE - results in test_output.log")
log("=" * 60)
