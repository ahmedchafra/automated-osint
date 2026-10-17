from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from app.core.ws_security import authenticate_websocket
from app.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.streaming import RedisScanEventStreamer, get_scan_event_streamer

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}")
async def scan_events_socket(
    websocket: WebSocket,
    scan_id: str,
    streamer: RedisScanEventStreamer = Depends(get_scan_event_streamer),
    db: AsyncSession = Depends(get_db),
):
    """Stream live scan events to a subscribed client.

    Auth is enforced BEFORE `accept()` so an unauthenticated client never
    receives a single byte from the server. See `authenticate_websocket`
    for accepted auth channels.
    """
    authenticated, subprotocol = await authenticate_websocket(websocket, scan_id, db)
    if not authenticated:
        return

    await websocket.accept(subprotocol=subprotocol)
    try:
        await streamer.stream(websocket, scan_id)
    except WebSocketDisconnect:
        return
