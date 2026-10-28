import asyncio

from fastapi import WebSocket
from sqlalchemy.exc import SQLAlchemyError

from app.core.exceptions import sqlalchemy_exception_handler


def test_database_exception_handler_closes_websocket_without_http_attributes():
    sent: list[dict] = []

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message: dict):
        sent.append(message)

    websocket = WebSocket(
        {
            "type": "websocket",
            "path": "/ws/scans/test",
            "raw_path": b"/ws/scans/test",
            "root_path": "",
            "scheme": "ws",
            "query_string": b"",
            "headers": [(b"x-request-id", b"ws-test-id")],
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
            "subprotocols": [],
            "state": {},
        },
        receive,
        send,
    )

    result = asyncio.run(sqlalchemy_exception_handler(websocket, SQLAlchemyError("test")))

    assert result is None
    assert sent == [{
        "type": "websocket.close",
        "code": 1011,
        "reason": "Database error (request ws-test-id)",
    }]
