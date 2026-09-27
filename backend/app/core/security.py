import secrets
from typing import Annotated

from fastapi import Depends, Header, Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import DomainError
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
    if request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
        raise DomainError("Unauthenticated access is limited to loopback", 403, "local_only")
    return "local-analyst"


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        try:
            too_large = content_length is not None and int(content_length) > self.max_bytes
        except ValueError:
            response = JSONResponse(
                {"error": {"code": "invalid_length", "message": "Invalid Content-Length"}},
                status_code=400,
            )
            await response(scope, receive, send)
            return
        messages: list[Message] = []
        total = 0
        while not too_large:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > self.max_bytes:
                too_large = True
                break
            messages.append(message)
            if not message.get("more_body", False):
                break
        if too_large:
            response = JSONResponse(
                {"error": {"code": "size_limit", "message": "Request body exceeds the size limit"}},
                status_code=413,
            )
            await response(scope, receive, send)
            return
        index = 0

        async def replay_receive() -> Message:
            nonlocal index
            if index < len(messages):
                message = messages[index]
                index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)
