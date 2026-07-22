"""theHarvester runner wrapper.

Patches aiohttp to use ThreadedResolver (fixes DNS resolution on
Windows + Python 3.13 where aiohttp's default AsyncResolver via aiodns
fails with "Could not contact DNS servers"), then runs theHarvester CLI.

Called by the TheHarvesterCollector instead of the raw theHarvester binary.
"""
import sys
import os

# ── Patch aiohttp BEFORE anything imports theHarvester ──────────────
# On Windows + Python 3.13 aiohttp's AsyncResolver (backed by aiodns)
# fails DNS resolution. ThreadedResolver uses the OS getaddrinfo and works.
import aiohttp.connector
import aiohttp.resolver

# On Windows + Python 3.13, aiohttp's AsyncResolver (from aiodns) fails with
# "Could not contact DNS servers". ThreadedResolver uses the OS getaddrinfo
# and works reliably.
# NOTE: aiohttp.connector also imports DefaultResolver as a local name, so we
# must patch BOTH modules — patching only aiohttp.resolver isn't enough.
aiohttp.resolver.DefaultResolver = aiohttp.resolver.ThreadedResolver
aiohttp.connector.DefaultResolver = aiohttp.resolver.ThreadedResolver

# ── Now import and run theHarvester ─────────────────────────────────
from theHarvester.theHarvester import main

if __name__ == "__main__":
    sys.exit(main())
