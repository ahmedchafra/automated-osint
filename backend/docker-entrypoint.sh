#!/bin/bash
# Entrypoint that ensures tools are installed before starting the app.
# Downloads subfinder if not present (handles Docker build network issues).
# Installs theHarvester from GitHub (not on PyPI under its name).
# Starts the Tor daemon if installed (used by the Ahmia dark-web collector).

set -e

# ── Subfinder ──────────────────────────────────────────────────────────────

SUBFINDER_BIN="/usr/local/bin/subfinder"
SUBFINDER_URL="https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_amd64.zip"

if [ ! -f "$SUBFINDER_BIN" ]; then
    echo "[entrypoint] Installing subfinder..."
    TMP_ZIP=$(mktemp /tmp/subfinder.XXXXXX.zip)
    curl -sL --connect-timeout 15 --max-time 120 "$SUBFINDER_URL" -o "$TMP_ZIP"
    unzip -o "$TMP_ZIP" -d /usr/local/bin/
    chmod +x /usr/local/bin/subfinder
    rm -f "$TMP_ZIP"
    echo "[entrypoint] Subfinder installed: $(subfinder -version 2>&1 | head -1)"
else
    echo "[entrypoint] Subfinder already installed: $(subfinder -version 2>&1 | head -1)"
fi

# ── theHarvester ───────────────────────────────────────────────────────────
# NOTE: The PyPI package "theHarvester" is a DIFFERENT project (version 0.0.1
# stub). The real theHarvester by laramies must be installed from GitHub.
if ! command -v theHarvester >/dev/null 2>&1; then
    echo "[entrypoint] Installing theHarvester from GitHub (master)..."
    pip install --no-cache-dir git+https://github.com/laramies/theHarvester.git@master 2>&1 | tail -3
    if command -v theHarvester >/dev/null 2>&1; then
        echo "[entrypoint] theHarvester installed: $(theHarvester --version 2>&1 | head -1 || echo 'OK')"
    else
        echo "[entrypoint] WARNING: theHarvester install failed — collector will be unavailable"
    fi
else
    echo "[entrypoint] theHarvester already installed"
fi

# ── h8mail ─────────────────────────────────────────────────────────────────
if ! command -v h8mail >/dev/null 2>&1; then
    echo "[entrypoint] WARNING: h8mail not found — collector will be unavailable"
fi

# ── theHarvester API keys ─────────────────────────────────────────────────
# Generate ~/.theHarvester/api-keys.yaml from .env vars so API-key-gated
# sources are available. Only writes non-empty env vars.
if command -v theHarvester >/dev/null 2>&1; then
    THEHARVESTER_DIR="$HOME/.theHarvester"
    mkdir -p "$THEHARVESTER_DIR"

    # Helper: write env var -> YAML key if the env var is non-empty
    _write_key() {
        local env_var="$1" yaml_key="$2"
        eval "val=\${$env_var:-}"
        if [ -n "$val" ]; then
            echo "${yaml_key}: $val" >> "$THEHARVESTER_DIR/api-keys.yaml"
        fi
    }

    # Overwrite file with header
    cat > "$THEHARVESTER_DIR/api-keys.yaml" <<- KEYS
# Auto-generated from .env - theHarvester API keys
---
KEYS

    # NOTE: hunter is NOT written - we have a dedicated hunter_domain
    # collector. Running it via theHarvester too would double-burn the
    # 50-free/month quota.
    # NOTE: GITHUB_TOKEN -> "github" key is written for reference but the
    # github-code source is disabled in v4.11.1 (key-format parsing bug).

    # -- Your existing pipeline keys --
    _write_key "SHODAN_API_KEY"    "shodan"
    _write_key "CENSYS_API_ID"     "censys_id"
    _write_key "CENSYS_API_SECRET" "censys_secret"
    _write_key "GITHUB_TOKEN"      "github"

    # -- Free-tier API keys --
    # Set the matching env var in .env and rebuild -> auto-activates.
    _write_key "HACKERTARGET_API_KEY"    "hackertarget"     # 50 req/month
    _write_key "BUFFEROVERUN_API_KEY"    "bufferoverun"     # 100 free/month
    _write_key "VT_API_KEY"              "virustotal"       # 500 lookups/day
    _write_key "URLSCAN_API_KEY"         "urlscan"          # free rate-limited
    _write_key "OTX_API_KEY"             "otx"              # free registration
    _write_key "LEAKIX_API_KEY"          "leakix"           # 3000 req/month
    _write_key "DNSDUMPSTER_API_KEY"     "dnsdumpster"      # 50 queries/day
    _write_key "SECURITYTRAILS_KEY"      "securitytrails"   # 50 queries/month
    _write_key "FULLHUNT_API_KEY"        "fullhunt"         # 50 queries
    _write_key "BEVIGIL_API_KEY"         "bevigil"          # 50 queries/month
    _write_key "TOMBA_API_KEY"           "tomba"            # 25 searches/month
    _write_key "BRAVE_API_KEY"           "brave"            # free plan
    _write_key "DYMO_API_KEY"            "dymo"             # free tier
    _write_key "NETLAS_API_KEY"          "netlas"           # 50 requests/day
    _write_key "CRIMINALIP_API_KEY"      "criminalip"       # 100 free
    _write_key "HUNTERHOW_API_KEY"       "hunterhow"        # 10k free/30d
    _write_key "MOJEEK_API_KEY"          "mojeek"           # 5000 free credits
    _write_key "WINDVANE_API_KEY"        "windvane"         # 100 free queries
    _write_key "VENACUS_API_KEY"         "venacus"          # 1 free search/day
    _write_key "ZOOMEYE_API_KEY"         "zoomeye"          # 5 free results/day
    _write_key "BUILTWITH_API_KEY"       "builtwith"        # 50 free queries ever

    # -- Paid / limited free trial --
    _write_key "INTELX_API_KEY"          "intelx"           # paid
    _write_key "ONYPHE_API_KEY"          "onyphe"           # paid
    _write_key "FOFA_API_KEY"            "fofa"             # paid
    _write_key "SHERLOCKEYE_API_KEY"     "sherlockeye"      # paid
    _write_key "PENTESTTOOLS_API_KEY"    "pentesttools"     # paid
    _write_key "PROJECTDISCOVERY_KEY"    "projectdiscovery" # paid
    _write_key "ROCKETREACH_API_KEY"     "rocketreach"      # paid
    _write_key "SECURITYSCORECARD_KEY"   "securityscorecard"# paid
    _write_key "WHOISXML_API_KEY"        "whoisxml"         # paid
    _write_key "DEHASHED_API_KEY"        "dehashed"         # paid
    _write_key "HIBP_API_KEY"            "haveibeenpwned"   # paid
    _write_key "LEAKLOOKUP_API_KEY"      "leaklookup"       # paid

    echo "[entrypoint] theHarvester api-keys.yaml generated ($THEHARVESTER_DIR/api-keys.yaml)"
fi

# ── Tor daemon ─────────────────────────────────────────────────────────────
if command -v tor >/dev/null 2>&1; then
    if ! pgrep -x tor >/dev/null 2>&1; then
        echo "[entrypoint] Starting Tor daemon for Ahmia collector..."
        tor >/tmp/tor.log 2>&1 &
        sleep 2
        echo "[entrypoint] Tor started (SOCKS5: 127.0.0.1:9050)"
    else
        echo "[entrypoint] Tor already running"
    fi
else
    echo "[entrypoint] Tor not installed — Ahmia collector will use HTTP API only"
fi

# Run the main container command
exec "$@"
