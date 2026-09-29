import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles

from app.api.integrations import router as integration_router
from app.api.routes import router
from app.core.config import PUBLIC_DEMO_RUN_LIMIT, ROOT, Settings
from app.core.errors import DomainError
from app.core.openapi import SentinelAPI
from app.core.security import BodyLimitMiddleware
from app.services.platform import Platform

logger = logging.getLogger("sentinelflow")


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.platform = Platform(config)
        yield
        application.state.platform.close()

    application = SentinelAPI(
        title="SentinelFlow",
        version="0.1.0",
        description=(
            "Evidence-first detection engineering. All operational APIs are also under /api. "
            + (
                "Public demo: shared synthetic telemetry only. Uploads, rule mutations, "
                "status/notes, and developer evidence endpoints are disabled. "
                "Sigma accepts only bundled samples; reset requires an operator token."
                if config.public_demo
                else "Local analyst mode."
            )
        ),
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    application.public_demo = config.public_demo
    application.add_middleware(
        BodyLimitMiddleware,
        max_bytes=128 * 1024 if config.public_demo else config.max_upload_bytes * 2 + 65_536,
    )
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.allowed_hosts))
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.allowed_origins),
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @application.middleware("http")
    async def boundaries(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        origin = request.headers.get("origin")
        denied_origin = False
        if request.method not in {"GET", "HEAD", "OPTIONS"} and origin:
            same_origin = origin == f"{request.url.scheme}://{request.headers.get('host', '')}"
            if origin not in config.allowed_origins and not same_origin:
                denied_origin = True
        path = request.url.path
        index = ROOT / "frontend" / "dist" / "index.html"
        spa = path == "/" or any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in (
                "/dashboard",
                "/events",
                "/alerts",
                "/rules",
                "/testing",
                "/detections",
                "/replay",
                "/sigma",
                "/evidence",
                "/validation",
                "/integrations",
                "/notifications",
            )
        )
        if denied_origin:
            response: Response = JSONResponse(
                {
                    "error": {"code": "origin_denied", "message": "Origin is not allowed"},
                    "request_id": request_id,
                },
                status_code=403,
            )
        elif (
            not config.public_demo
            and request.method == "GET"
            and "text/html" in request.headers.get("accept", "")
            and spa
            and index.exists()
        ):
            response = FileResponse(index)
        else:
            response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = (
            "no-store" if not path.startswith("/assets/") else "public, max-age=3600"
        )
        script_policy = "'self' 'unsafe-inline'" if path in {"/docs", "/api/docs"} else "'self'"
        response.headers["Content-Security-Policy"] = (
            f"default-src 'self'; script-src {script_policy}; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        return response

    @application.exception_handler(DomainError)
    async def domain_error(request: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse(
            {
                "error": {"code": exc.code, "message": exc.message},
                "request_id": getattr(request.state, "request_id", ""),
            },
            status_code=exc.status_code,
        )

    @application.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {"field": ".".join(map(str, error["loc"])), "message": error["msg"]}
            for error in exc.errors()
        ]
        return JSONResponse(
            {
                "error": {
                    "code": "invalid_request",
                    "message": "Request validation failed",
                    "details": errors,
                },
                "request_id": getattr(request.state, "request_id", ""),
            },
            status_code=422,
        )

    @application.exception_handler(Exception)
    async def internal_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error(
            "Unhandled request failure id=%s",
            getattr(request.state, "request_id", ""),
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        return JSONResponse(
            {
                "error": {
                    "code": "internal_error",
                    "message": "Internal error; inspect local server logs",
                },
                "request_id": getattr(request.state, "request_id", ""),
            },
            status_code=500,
        )

    @application.get("/health", tags=["Health"])
    @application.get("/api/health", include_in_schema=False)
    def health() -> dict[str, Any]:
        result = {
            "status": "ok",
            "version": "0.1.0",
            "auth_required": bool(config.api_token) and not config.public_demo,
        }
        if config.public_demo:
            result.update(public_demo=True, public_demo_run_limit=PUBLIC_DEMO_RUN_LIMIT)
        return result

    @application.get("/favicon.svg", include_in_schema=False)
    def favicon() -> FileResponse:
        return FileResponse(ROOT / "frontend" / "public" / "favicon.svg")

    @application.get("/docs", include_in_schema=False)
    @application.get("/api/docs", include_in_schema=False)
    def docs() -> HTMLResponse:
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title="SentinelFlow API",
            swagger_js_url="/swagger/swagger-ui-bundle.js",
            swagger_css_url="/swagger/swagger-ui.css",
            swagger_favicon_url="/favicon.svg",
            swagger_ui_parameters={"validatorUrl": None, "queryConfigEnabled": False},
        )

    application.include_router(router)
    application.include_router(router, prefix="/api", include_in_schema=False)
    application.include_router(integration_router)
    application.include_router(integration_router, prefix="/api", include_in_schema=False)

    swagger = Path(__file__).parent / "static/swagger"
    application.mount("/swagger", StaticFiles(directory=swagger), name="swagger")
    dist = ROOT / "frontend" / "dist"
    if not config.public_demo and (dist / "assets").is_dir():
        application.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @application.get("/{path:path}", include_in_schema=False)
    def frontend(path: str) -> FileResponse:
        if config.public_demo:
            raise DomainError(
                "Backend API only; open the separately deployed frontend", 404, "not_found"
            )
        relative = PurePosixPath(path)
        if (
            relative.is_absolute()
            or PureWindowsPath(path).drive
            or "\\" in path
            or "\x00" in path
            or ".." in relative.parts
        ):
            raise DomainError("Route not found", 404, "not_found")
        candidate = dist
        for part in relative.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise DomainError("Route not found", 404, "not_found")
        candidate = candidate.resolve()
        if candidate.is_relative_to(dist.resolve()) and candidate.is_file():
            return FileResponse(candidate)
        if path == "" and (dist / "index.html").exists():
            return FileResponse(dist / "index.html")
        raise DomainError("Route not found", 404, "not_found")

    return application


app = create_app()
