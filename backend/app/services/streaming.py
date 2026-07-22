from collections.abc import AsyncIterator
from typing import Callable, Optional

import redis.asyncio as redis
from fastapi import WebSocket

from app.config import settings


class RedisScanEventStreamer:
    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL

    async def stream(self, websocket: WebSocket, scan_id: str) -> None:
        client = redis.Redis.from_url(self.redis_url, decode_responses=True)
        pubsub = client.pubsub()
        channel = f"scan:{scan_id}"

        try:
            await pubsub.subscribe(channel)
            await websocket.send_json({"event": "connected", "scan_id": scan_id, "channel": channel})

            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message.get("type") == "message":
                    await websocket.send_text(message["data"])
        finally:
            try:
                await pubsub.unsubscribe(channel)
            except Exception:
                pass
            try:
                await pubsub.aclose()
            except Exception:
                pass
            try:
                await client.aclose()
            except Exception:
                pass


def get_scan_event_streamer() -> RedisScanEventStreamer:
    return RedisScanEventStreamer()

