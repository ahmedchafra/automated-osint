"""Global exception handlers with structured logging and correlation IDs.

Each request gets a `X-Request-ID` (generated if missing). The handlers
include it in the response and log the full traceback server-side so
operators can correlate a user-visible error to a log line without
exposing internals.
"""
from __future__ import annotations

import logging
import uuid

from fastapi import Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("osint.errors")


def _request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID") or uuid.uuid4().hex


async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    rid = _request_id(request)
    logger.exception(
        "database error",
        extra={"request_id": rid, "path": request.url.path, "method": request.method},
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "A database error occurred.",
            "request_id": rid,
        },
        headers={"X-Request-ID": rid},
    )


async def generic_exception_handler(request: Request, exc: Exception):
    rid = _request_id(request)
    logger.exception(
        "unhandled exception",
        extra={"request_id": rid, "path": request.url.path, "method": request.method},
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An unexpected error occurred.",
            "request_id": rid,
        },
        headers={"X-Request-ID": rid},
    )