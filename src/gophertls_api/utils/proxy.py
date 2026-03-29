"""Proxy URL formatting (parity with Go internal/utils FormatProxy)."""

from __future__ import annotations

from enum import Enum


class ProxyType(Enum):
    """Upstream proxy scheme understood by libcurl / curl_cffi."""

    HTTP = "http"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


def parse_proxy_type(raw: str | None) -> ProxyType:
    """
    Map ``x-tls-proxy-type`` (or default) to a ``ProxyType``.

    Accepts case-insensitive ``HTTP`` (default when empty), ``SOCKS4``,
    ``SOCKS5``.

    Raises:
        ValueError: if the token is not a supported proxy type.
    """
    text = (raw or "").strip().upper().replace("-", "")
    if not text or text == "HTTP":
        return ProxyType.HTTP
    if text == "SOCKS4":
        return ProxyType.SOCKS4
    if text == "SOCKS5":
        return ProxyType.SOCKS5
    raise ValueError(f"invalid proxy type: {raw!r}")


def format_proxy(proxy: str, proxy_type: ProxyType = ProxyType.HTTP) -> str:
    """
    Normalize proxy string to a URL with the given scheme.

    Supported inputs:
    - host:port -> {scheme}://host:port
    - host:port:user:pass -> {scheme}://user:pass@host:port

    ``proxy_type`` selects the scheme: ``http``, ``socks4``, or ``socks5``.

    Raises:
        ValueError: if the segment count is not 2 or 4.
    """
    parts = proxy.split(":")
    prefix = f"{proxy_type.value}://"
    if len(parts) == 2:
        host, port = parts
        return f"{prefix}{host}:{port}"
    if len(parts) == 4:
        host, port, user, password = parts
        return f"{prefix}{user}:{password}@{host}:{port}"
    raise ValueError("invalid proxy format")
