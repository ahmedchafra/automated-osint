"""Global exception handlers with structured logging and correlation IDs.

Each request gets a `X-Request-ID` (generated if missing). The handlers
include it in the response and log the full traceback server-side so
operators can correlate a user-visible error to a log line without
exposing internals.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import Request, WebSocket, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("osint.errors")


def _request_id(connection: Request | WebSocket) -> str:
    return connection.headers.get("X-Request-ID") or uuid.uuid4().hex


def _log_context(connection: Request | WebSocket, request_id: str) -> dict[str, str]:
    return {
        "request_id": request_id,
        "path": connection.url.path,
        "method": getattr(connection, "method", "WEBSOCKET"),
    }


async def sqlalchemy_exception_handler(request: Request | WebSocket, exc: SQLAlchemyError):
    rid = _request_id(request)
    logger.exception(
        "database error",
        extra=_log_context(request, rid),
    )
    if isinstance(request, WebSocket):
        await request.close(code=1011, reason=f"Database error (request {rid})")
        return None
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "A database error occurred.",
            "request_id": rid,
        },
        headers={"X-Request-ID": rid},
    )


async def generic_exception_handler(request: Request | WebSocket, exc: Exception):
    rid = _request_id(request)
    logger.exception(
        "unhandled exception",
        extra=_log_context(request, rid),
    )
    if isinstance(request, WebSocket):
        await request.close(code=1011, reason=f"Internal error (request {rid})")
        return None
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An unexpected error occurred.",
            "request_id": rid,
        },
        headers={"X-Request-ID": rid},
    )
