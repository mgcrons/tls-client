"""Response body handling; curl_cffi decodes Content-Encoding when fetching content."""

from __future__ import annotations

from typing import Any


def upstream_body_bytes(response: Any) -> bytes:
    """
    Return the upstream response body as bytes.

    curl_cffi follows Accept-Encoding and exposes decoded bytes on ``.content``,
    matching the Go handler's goal of returning a decompressed body to the client.
    """
    return response.content
