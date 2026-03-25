"""POST /go/pher — forward request with curl_cffi impersonation."""

from __future__ import annotations

from datetime import datetime, timezone
from http.cookiejar import Cookie

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from gophertls_api.models.tls_request import parse_tls_forward_request
from gophertls_api.services.upstream_http import UpstreamResult, execute_upstream
from gophertls_api.utils.cookies import normalize_samesite

router = APIRouter()


def _error_response(message: str) -> JSONResponse:
    """Match Go ``handleErrorResponse`` (500 + JSON body)."""
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": message},
    )


def _cookie_http_only(cookie: Cookie) -> bool:
    rest = getattr(cookie, "_rest", None) or {}
    return "HttpOnly" in rest or str(rest.get("http_only", "")).lower() == "true"


def _cookie_samesite(cookie: Cookie) -> str | None:
    rest = getattr(cookie, "_rest", None) or {}
    raw = rest.get("SameSite") or rest.get("samesite")
    if raw is None:
        return None
    return normalize_samesite(str(raw))


def _build_response(result: UpstreamResult) -> Response:
    resp = Response(content=result.body, status_code=result.status_code)
    for key, value in result.headers.items():
        resp.headers[key] = value

    for cookie in result.cookies:
        expires_dt: datetime | None = None
        if cookie.expires:
            expires_dt = datetime.fromtimestamp(float(cookie.expires), tz=timezone.utc)

        ss = _cookie_samesite(cookie)
        kwargs: dict = {
            "key": cookie.name,
            "value": cookie.value or "",
            "path": cookie.path or "/",
            "domain": cookie.domain if cookie.domain_specified else None,
            "secure": cookie.secure,
            "httponly": _cookie_http_only(cookie),
            "expires": expires_dt,
        }
        if ss is not None:
            kwargs["samesite"] = ss
        resp.set_cookie(**kwargs)

    return resp


@router.post("/pher")
async def tls_forward(request: Request) -> Response:
    try:
        config = await parse_tls_forward_request(request)
    except ValueError as exc:
        return _error_response(f"error while extracting tls data: {exc}")

    try:
        result = execute_upstream(config)
    except Exception:
        return _error_response("error while doing request")

    print(result.status_code)
    print(result.headers)
    print(result.cookies)
    return _build_response(result)
