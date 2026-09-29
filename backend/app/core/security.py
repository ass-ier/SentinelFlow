import asyncio
import secrets
import time
from typing import Annotated

from fastapi import Depends, Header, Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import DomainError
from app.integrations.auth import scoped_identity
from app.services.platform import Platform


def get_platform(request: Request) -> Platform:
    platform = request.app.state.platform
    if not isinstance(platform, Platform):
        raise DomainError("Application is not initialized", 503, "not_ready")
    return platform


def analyst(
    request: Request,
    platform: Annotated[Platform, Depends(get_platform)],
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    if platform.settings.public_demo:
        return "public-demo"
    integration = scoped_identity(platform, authorization)
    if integration is not None:
        path = request.url.path.removeprefix("/api")
        if (
            request.method == "GET"
            and (path == "/alerts" or (path.startswith("/alerts/") and path.count("/") == 2))
            and "alerts:read" in integration[1].scopes
        ):
            return integration[0]
        raise DomainError("Integration token does not grant analyst access", 403, "scope_denied")
    token = platform.settings.api_token
    if token:
        if (
            not authorization
            or not authorization.startswith("Bearer ")
            or not authorization.isascii()
            or not secrets.compare_digest(authorization[7:], token)
        ):
            raise DomainError("A valid local API token is required", 401, "unauthorized")
        return "token-analyst"
    if authorization:
        raise DomainError("The supplied token is invalid or revoked", 401, "unauthorized")
    if request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
        raise DomainError("Unauthenticated access is limited to loopback", 403, "local_only")
    return "local-analyst"


def local_features(platform: Annotated[Platform, Depends(get_platform)]) -> None:
    if platform.settings.public_demo:
        raise DomainError(
            "This operation is unavailable in the shared synthetic-only public demo. "
            "Use a private local installation for analyst changes or custom input.",
            403,
            "public_demo_restricted",
        )


def operator(
    request: Request,
    platform: Annotated[Platform, Depends(get_platform)],
    authorization: Annotated[str | None, Header()] = None,
) -> str:
    if not platform.settings.public_demo:
        return analyst(request, platform, authorization)
    token = platform.settings.api_token
    if (
        not token
        or not authorization
        or not authorization.startswith("Bearer ")
        or not authorization.isascii()
        or not secrets.compare_digest(authorization[7:], token)
    ):
        raise DomainError(
            "Public demo reset is operator-only; visitor access cannot reset the database.",
            403,
            "public_demo_restricted",
        )
    return "token-analyst"


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int, timeout_seconds: float = 10) -> None:
        self.app, self.max_bytes = app, max_bytes
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        max_bytes = (
            min(self.max_bytes, 512 * 1024)
            if scope.get("path", "").removeprefix("/api") == "/ingest/windows"
            else self.max_bytes
        )
        content_length = headers.get(b"content-length")
        try:
            if content_length is not None and not content_length.isdigit():
                raise ValueError("Content-Length must contain only ASCII digits")
            too_large = content_length is not None and int(content_length) > max_bytes
        except ValueError:
            response = JSONResponse(
                {"error": {"code": "invalid_length", "message": "Invalid Content-Length"}},
                status_code=400,
            )
            await response(scope, receive, send)
            return
        body = bytearray()
        deadline = time.monotonic() + self.timeout_seconds
        while not too_large:
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise TimeoutError
                message = await asyncio.wait_for(receive(), remaining)
            except TimeoutError:
                response = JSONResponse(
                    {
                        "error": {
                            "code": "request_timeout",
                            "message": "Request body timed out; retry with a smaller upload",
                        }
                    },
                    status_code=408,
                )
                await response(scope, receive, send)
                return
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > max_bytes:
                too_large = True
                break
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        if too_large:
            response = JSONResponse(
                {"error": {"code": "size_limit", "message": "Request body exceeds the size limit"}},
                status_code=413,
            )
            await response(scope, receive, send)
            return
        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
