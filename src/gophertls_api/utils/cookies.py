"""SameSite normalization for Starlette set_cookie (values: lax, strict, none)."""

from __future__ import annotations


def normalize_samesite(raw: str | None) -> str | None:
    """Return a Starlette-compatible samesite value, or None to omit the attribute."""
    if not raw:
        return None
    v = raw.strip().lower()
    if v in ("lax", "strict", "none"):
        return v
    return None
