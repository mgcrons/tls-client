"""FastAPI application factory."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from gophertls_api.handlers.tls_forward import router as tls_router

logger = logging.getLogger("gophertls_api")


def create_app() -> FastAPI:
    app = FastAPI(title="GopherTLS", version="0.1.0")

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        logger.info("%s %s", request.method, request.url.path)
        return await call_next(request)

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": "internal server error"},
        )

    app.include_router(tls_router, prefix="/go")

    return app


app = create_app()
