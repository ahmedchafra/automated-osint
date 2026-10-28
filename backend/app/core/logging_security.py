"""Logging defaults that prevent credentials in HTTP query strings from leaking."""
import logging


def suppress_http_client_request_logs(*args, **kwargs) -> None:
    # httpx's INFO message includes the complete URL, including API-key query
    # parameters used by several collectors. Collector-owned logs remain on.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
