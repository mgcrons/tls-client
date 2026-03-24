"""Proxy URL formatting (parity with Go internal/utils FormatProxy)."""

from __future__ import annotations


def format_proxy(proxy: str) -> str:
    """
    Normalize proxy string to an http:// URL.

    Supported inputs:
    - host:port -> http://host:port
    - host:port:user:pass -> http://user:pass@host:port

    Raises:
        ValueError: if the segment count is not 2 or 4.
    """
    parts = proxy.split(":")
    if len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    if len(parts) == 4:
        host, port, user, password = parts
        return f"http://{user}:{password}@{host}:{port}"
    raise ValueError("invalid proxy format")
