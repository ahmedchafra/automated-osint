"""WebSocket authentication and scan authorization helpers.

The scan-event stream broadcasts progress events that include target
domain names, finding counts, and (downstream) potentially sensitive
correlation results. Subscribing without auth would let anyone with a
scan ID listen to live updates.

Browser clients authenticate with a ``bearer.<JWT>`` WebSocket subprotocol.
Native service clients may continue to use the ``X-API-Key`` header, but the
shared key is never accepted in a URL and is no longer shipped to browsers.

The streamer is the only place we need to enforce this — FastAPI's
`Security()` dependency does not run on WebSocket routes the same way
it does on HTTP routes.
"""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, WebSocket, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.auth import check_scan_access, verify_token
from app.models.user import User


def _extract_bearer_protocol(websocket: WebSocket) -> tuple[Optional[str], Optional[str]]:
    header = websocket.headers.get("sec-websocket-protocol")
    if not header:
        return None, None
    for protocol in header.split(","):
        protocol = protocol.strip()
        if protocol.startswith("bearer."):
            return protocol[len("bearer."):], protocol
    return None, None


async def authenticate_websocket(
    websocket: WebSocket,
    scan_id: str,
    db: AsyncSession,
) -> tuple[bool, Optional[str]]:
    """Authenticate the socket and authorize access to its scan.

    On rejection we close the socket with the appropriate WS close code
    so the client can distinguish auth failure from a transient network
    drop and avoid reconnecting in a tight loop.
    """
    api_key = websocket.headers.get("x-api-key")
    if api_key and api_key == settings.API_KEY:
        return True, None

    token, protocol = _extract_bearer_protocol(websocket)
    if token:
        try:
            payload = verify_token(token)
            user_id = payload.get("sub")
            if not user_id:
                raise HTTPException(status_code=401, detail="Missing token subject")
            user = (
                await db.execute(
                    select(User).where(User.id == user_id, User.is_active.is_(True))
                )
            ).scalar_one_or_none()
            if not user:
                raise HTTPException(status_code=401, detail="Inactive or unknown user")
            await check_scan_access(db, scan_id, user, require_modify=False)
            return True, protocol
        except HTTPException:
            pass

    await websocket.close(
        code=status.WS_1008_POLICY_VIOLATION,
        reason="Invalid credentials or scan access denied",
    )
    return False, None
