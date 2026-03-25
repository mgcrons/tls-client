"""POST /go/pher — forward request with curl_cffi impersonation."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from gophertls_api.models.tls_request import parse_tls_forward_request
from gophertls_api.services.upstream_http import UpstreamResult, execute_upstream
from gophertls_api.utils.set_cookie import parse_set_cookie_header

router = APIRouter()


def _error_response(message: str) -> JSONResponse:
    """Match Go ``handleErrorResponse`` (500 + JSON body)."""
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": message},
    )


def _build_response(result: UpstreamResult) -> Response:
    resp = Response(content=result.body, status_code=result.status_code)
    for key, value in result.headers.items():
        resp.headers[key] = value

    for set_cookie in result.set_cookie_headers:
        kwargs = parse_set_cookie_header(set_cookie)
        if kwargs is None:
            continue
        # `Response.set_cookie` ignores unknown/optional keys; keep parser output
        # aligned with Starlette's expected argument names.
        resp.set_cookie(**kwargs)  # type: ignore[arg-type]

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
    print(result.set_cookie_headers)
    return _build_response(result)
