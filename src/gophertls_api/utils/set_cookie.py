"""Utilities for parsing HTTP ``Set-Cookie`` headers.

The upstream client (``curl_cffi``) can expose cookies, but parsing varies with
header format. For robustness, we also parse raw ``set-cookie`` header lines
so we can reliably forward cookies to the API caller.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from gophertls_api.utils.cookies import normalize_samesite


_QUOTED_VALUE_RE = re.compile(r'^"(.*)"$')


def _strip_quotes(value: str) -> str:
    m = _QUOTED_VALUE_RE.match(value.strip())
    if not m:
        return value.strip()
    return m.group(1)


def parse_set_cookie_header(set_cookie: str) -> dict[str, object] | None:
    """
    Parse a single ``Set-Cookie`` header line into Starlette/FastAPI
    ``set_cookie`` kwargs.

    Args:
        set_cookie: A single header line (NOT multiple cookies; do not split on
            commas).

    Returns:
        Dict compatible with ``Response.set_cookie``
        (key/value/path/domain/secure/httponly/etc), or None if the cookie
        cannot be parsed.
    """

    # Example: `name=value; Path=/; Secure; HttpOnly; SameSite=None`
    parts = [p.strip() for p in set_cookie.split(";") if p.strip()]
    if not parts:
        return None

    if "=" not in parts[0]:
        return None

    name, value = parts[0].split("=", 1)
    name = name.strip()
    if not name:
        return None

    value = _strip_quotes(value)

    path: str | None = None
    domain: str | None = None
    secure = False
    httponly = False
    samesite: str | None = None
    expires: datetime | None = None
    max_age: int | None = None

    for attr in parts[1:]:
        if "=" in attr:
            k, v = attr.split("=", 1)
            key = k.strip().lower()
            raw_v = _strip_quotes(v)
        else:
            key = attr.strip().lower()
            raw_v = ""

        if key == "path":
            path = raw_v
        elif key == "domain":
            domain = raw_v
        elif key == "secure":
            secure = True
        elif key == "httponly":
            httponly = True
        elif key == "samesite":
            samesite = normalize_samesite(raw_v)
        elif key == "expires":
            try:
                dt = parsedate_to_datetime(raw_v)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                expires = dt.astimezone(timezone.utc)
            except Exception:
                # If expiry parsing fails, treat as session cookie.
                expires = None
        elif key == "max-age":
            try:
                max_age = int(raw_v)
            except Exception:
                max_age = None

    kwargs: dict[str, object] = {
        "key": name,
        "value": value,
        "path": path or "/",
        "domain": domain,
        "secure": secure,
        "httponly": httponly,
    }
    if samesite is not None:
        kwargs["samesite"] = samesite
    if expires is not None:
        kwargs["expires"] = expires
    if max_age is not None:
        kwargs["max_age"] = max_age

    return kwargs
