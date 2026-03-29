"""Parse and validate /go/pher request headers into a typed config."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from urllib.parse import urlparse

from fastapi import Request

from gophertls_api.profiles.map import resolve_impersonate
from gophertls_api.utils.proxy import format_proxy, parse_proxy_type

METHODS_WITHOUT_BODY = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
SUPPORTED_METHODS = METHODS_WITHOUT_BODY | {"POST", "PUT", "PATCH", "DELETE"}

TLS_URL = "x-tls-url"
TLS_METHOD = "x-tls-method"
TLS_PROXY = "x-tls-proxy"
TLS_PROXY_TYPE = "x-tls-proxy-type"
TLS_PROFILE = "x-tls-profile"
TLS_TIMEOUT = "x-tls-timeout"
TLS_FOLLOW_REDIRECTS = "x-tls-follow-redirects"
TLS_FORCE_H1 = "x-tls-force-h1"
TLS_INSECURE = "x-tls-insecure-skip-verify"
TLS_RANDOM_EXT = "x-tls-with-random-extension-order"
TLS_HEADER_ORDER = "x-tls-header-order"
TLS_PSEUDO_ORDER = "x-tls-pseudo-order"
TLS_DEBUG_COOKIES = "x-tls-debug-cookies"
TLS_VERBOSE_CURL = "x-tls-verbose-curl"

PSEUDO_MAP = {
    ":method": "m",
    ":authority": "a",
    ":scheme": "s",
    ":path": "p",
}


@dataclass(frozen=True)
class TlsForwardConfig:
    """Normalized settings for one upstream call."""

    request_url: str
    request_method: str
    forward_headers: list[tuple[str, str]]
    request_body: bytes
    proxy: str | None
    impersonate: str
    timeout_seconds: float
    follow_redirects: bool
    force_http1: bool
    insecure_skip_verify: bool
    # When None, execute_upstream should not override
    # curl_cffi fingerprint settings.
    with_random_extension_order: bool | None
    pseudo_headers_curl: str | None
    debug_cookies: bool
    verbose_curl: bool


def _get_header(request: Request, name: str) -> str:
    return (request.headers.get(name) or "").strip()


def _get_optional_header(request: Request, name: str) -> str | None:
    """Return stripped header value, or None if the header is absent/empty."""
    raw = request.headers.get(name)
    if raw is None:
        return None
    text = raw.strip()
    return text or None


def _parse_bool(raw: str, default: str, field: str) -> bool:
    text = (raw.strip() or default).lower()
    if text == "true":
        return True
    if text == "false":
        return False
    raise ValueError(f"invalid {field}: {raw or default}")


def _parse_comma_list(raw: str, field: str) -> list[str]:
    cleaned = raw.replace(" ", "")
    items = [item for item in cleaned.split(",") if item]
    if not items:
        raise ValueError(f"invalid {field}: {raw}")
    return items


def _parse_bool_optional(raw: str | None, default: bool, field: str) -> bool:
    """Parse optional boolean header values."""
    if raw is None:
        return default
    return _parse_bool(raw, "true" if default else "false", field)


def _parse_pseudo_order(raw: str) -> str:
    order = []
    for item in _parse_comma_list(raw, "pseudo header order"):
        if item not in PSEUDO_MAP:
            raise ValueError(f"unknown pseudo header: {item}")
        order.append(PSEUDO_MAP[item])
    return "".join(order)


def build_forward_headers(
    incoming_headers: list[tuple[str, str]],
    preferred_order: list[str],
    method: str,
) -> list[tuple[str, str]]:
    """
    Strip x-tls/meta headers and enforce preferred order first.

    Note: in ASGI, header names are provided lower-cased. To preserve
    user-provided casing for ordered headers, we use the original tokens from
    `preferred_order` when emitting headers.
    """
    skip_content_type = method in METHODS_WITHOUT_BODY
    canonical_names: dict[str, str] = {}
    groups: OrderedDict[str, list[tuple[str, str]]] = OrderedDict()

    # Map normalized header name -> user-provided casing token.
    order_display: dict[str, str] = {}
    for token in preferred_order:
        cleaned = token.strip()
        if not cleaned:
            continue
        order_display.setdefault(cleaned.lower(), cleaned)

    for key, value in incoming_headers:
        lower_key = key.lower()
        if lower_key.startswith("x-tls-"):
            continue
        if lower_key == "content-length":
            continue
        if lower_key == "host":
            continue
        if skip_content_type and lower_key == "content-type":
            continue
        if lower_key not in canonical_names:
            canonical_names[lower_key] = key
        groups.setdefault(lower_key, []).append(
            (canonical_names[lower_key], value)
        )

    ordered: list[tuple[str, str]] = []
    used: set[str] = set()
    for token in preferred_order:
        lk = token.lower()
        if lk in groups:
            display_key = order_display.get(lk, canonical_names.get(lk, lk))
            # Emit all occurrences using the ordered header's display casing.
            ordered.extend([(display_key, v) for _, v in groups[lk]])
            used.add(lk)

    for key, values in groups.items():
        if key not in used:
            ordered.extend(values)

    return ordered


async def parse_tls_forward_request(request: Request) -> TlsForwardConfig:
    """Parse API headers/body, returning a validated forwarding config."""
    request_url = _get_header(request, TLS_URL)
    if not request_url:
        raise ValueError(f"no {TLS_URL}")
    parsed_url = urlparse(request_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("invalid request URL")

    method = _get_header(request, TLS_METHOD).upper()
    if not method:
        raise ValueError(f"no {TLS_METHOD}")
    if method not in SUPPORTED_METHODS:
        raise ValueError(f"invalid request method: {method}")

    profile = _get_header(request, TLS_PROFILE)
    if not profile:
        raise ValueError(f"no {TLS_PROFILE}")
    impersonate = resolve_impersonate(profile)

    proxy_raw = _get_header(request, TLS_PROXY)
    if proxy_raw:
        proxy_kind = parse_proxy_type(_get_header(request, TLS_PROXY_TYPE))
        proxy = format_proxy(proxy_raw, proxy_kind)
    else:
        proxy = None

    timeout_raw = _get_header(request, TLS_TIMEOUT) or "30"
    try:
        timeout_seconds = float(timeout_raw)
    except ValueError as exc:
        raise ValueError(f"invalid client timeout: {timeout_raw}") from exc

    follow_redirects = _parse_bool(
        _get_header(request, TLS_FOLLOW_REDIRECTS), "true", "follow redirects"
    )
    force_http1 = _parse_bool(
        _get_header(request, TLS_FORCE_H1),
        "false",
        "force http/1.1",
    )
    insecure_skip_verify = _parse_bool(
        _get_header(request, TLS_INSECURE), "false", "insecure skip verify"
    )
    random_ext_raw = _get_optional_header(request, TLS_RANDOM_EXT)
    with_random_extension_order = (
        _parse_bool(random_ext_raw, "true", "random extension order")
        if random_ext_raw is not None
        else None
    )

    debug_cookies_raw = _get_optional_header(request, TLS_DEBUG_COOKIES)
    debug_cookies = _parse_bool_optional(
        debug_cookies_raw, False, "debug cookies"
    )

    verbose_curl_raw = _get_optional_header(request, TLS_VERBOSE_CURL)
    verbose_curl = _parse_bool_optional(verbose_curl_raw, False, "verbose curl")

    header_order_raw = _get_header(request, TLS_HEADER_ORDER)
    if not header_order_raw:
        raise ValueError(f"no {TLS_HEADER_ORDER}")
    header_order = _parse_comma_list(header_order_raw, "header order")

    pseudo_order_raw = _get_optional_header(request, TLS_PSEUDO_ORDER)
    pseudo_headers_curl = (
        _parse_pseudo_order(pseudo_order_raw) if pseudo_order_raw else None
    )

    body = await request.body()
    if method in METHODS_WITHOUT_BODY:
        body = b""

    incoming_headers = [
        (key.decode("latin-1"), value.decode("latin-1"))
        for key, value in request.scope.get("headers", [])
    ]
    forward_headers = build_forward_headers(
        incoming_headers, header_order, method
    )

    return TlsForwardConfig(
        request_url=request_url,
        request_method=method,
        forward_headers=forward_headers,
        request_body=body,
        proxy=proxy,
        impersonate=impersonate,
        timeout_seconds=timeout_seconds,
        follow_redirects=follow_redirects,
        force_http1=force_http1,
        insecure_skip_verify=insecure_skip_verify,
        with_random_extension_order=with_random_extension_order,
        pseudo_headers_curl=pseudo_headers_curl,
        debug_cookies=debug_cookies,
        verbose_curl=verbose_curl,
    )
