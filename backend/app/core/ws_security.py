"""WebSocket authentication helpers.

The scan-event stream broadcasts progress events that include target
domain names, finding counts, and (downstream) potentially sensitive
correlation results. Subscribing without auth would let anyone with a
scan ID listen to live updates.

We accept the API key in three places (in order of preference):
  1. The `?api_key=` query parameter (what the browser WebSocket API can send).
  2. The `X-API-Key` header (works for native clients and tests).
  3. The `Sec-WebSocket-Protocol` subprotocol header (browser-safe fallback).

The streamer is the only place we need to enforce this — FastAPI's
`Security()` dependency does not run on WebSocket routes the same way
it does on HTTP routes.
"""
from __future__ import annotations

from typing import Optional

from fastapi import WebSocket, status

from app.config import settings


def _extract_key_from_protocol(websocket: WebSocket) -> Optional[str]:
    """Browsers cannot set arbitrary headers on a WebSocket. The standard
    escape hatch is the `Sec-WebSocket-Protocol` header: client sends a
    subprotocol name like `api-key.<value>`, server echoes it back."""
    for header in (websocket.headers.get("sec-websocket-protocol"),):
        if not header:
            continue
        for token in header.split(","):
            token = token.strip()
            if token.startswith("api-key."):
                return token[len("api-key."):]
    return None


async def authenticate_websocket(websocket: WebSocket) -> bool:
    """Return True when the connection supplies a valid API key.

    On rejection we close the socket with the appropriate WS close code
    so the client can distinguish auth failure from a transient network
    drop and avoid reconnecting in a tight loop.
    """
    api_key = (
        websocket.query_params.get("api_key")
        or websocket.headers.get("x-api-key")
        or _extract_key_from_protocol(websocket)
    )

    if api_key and api_key == settings.API_KEY:
        return True

    await websocket.close(
        code=status.WS_1008_POLICY_VIOLATION,
        reason="Invalid or missing API key",
    )
    return False
