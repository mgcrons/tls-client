"""
Execute the upstream HTTP request with curl_cffi (browser impersonation, proxy, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import Cookie
from typing import Mapping

from curl_cffi import CurlOpt, CurlHttpVersion
from curl_cffi.requests import Session
from curl_cffi.requests.impersonate import ExtraFingerprints

from gophertls_api.models.tls_request import TlsForwardConfig
from gophertls_api.utils.decompression import upstream_body_bytes


@dataclass(frozen=True)
class UpstreamResult:
    """Upstream response pieces needed to build the API response."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    set_cookie_headers: tuple[str, ...]
    cookies: tuple[Cookie, ...]


def _response_headers_map(headers: Mapping[str, str]) -> dict[str, str]:
    """Drop hop-by-hop / encoding headers like the Go ``getResponseHeaders``."""
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in ("content-length", "content-encoding", "set-cookie"):
            continue
        out[key] = value
    return out


def execute_upstream(config: TlsForwardConfig) -> UpstreamResult:
    """
    Perform one upstream request using a fresh Session (no cross-request state).

    Raises:
        Exception: on network/TLS/curl failures (wrapped by the handler).
    """
    print(config)
    curl_options = {CurlOpt.HTTP2_PSEUDO_HEADERS_ORDER: config.pseudo_headers_curl}
    extra_fp = ExtraFingerprints(
        tls_permute_extensions=config.with_random_extension_order
    )
    http_version = CurlHttpVersion.V1_1 if config.force_http1 else None

    with Session(
        verify=not config.insecure_skip_verify,
        timeout=config.timeout_seconds,
        allow_redirects=config.follow_redirects,
        impersonate=config.impersonate,  # type: ignore[arg-type]
        proxy=config.proxy,
        http_version=http_version,
        curl_options=curl_options,
        extra_fp=extra_fp,
        default_headers=False,
    ) as session:
        resp = session.request(
            config.request_method,  # type: ignore[arg-type]
            config.request_url,
            headers=config.forward_headers,
            data=config.request_body if config.request_body else None,
            timeout=config.timeout_seconds,
        )

    body = upstream_body_bytes(resp)
    header_map = _response_headers_map(resp.headers)
    set_cookie_headers = tuple(resp.headers.get_list("set-cookie"))
    cookie_tuple = tuple(resp.cookies.jar)
    print(resp.status_code)
    print(resp.headers)
    print(resp.cookies)
    print(set_cookie_headers)
    print(cookie_tuple)

    return UpstreamResult(
        status_code=resp.status_code,
        headers=header_map,
        body=body,
        set_cookie_headers=set_cookie_headers,
        cookies=cookie_tuple,
    )
