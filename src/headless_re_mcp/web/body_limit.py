"""ASGI request-body limits for the local web console."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

_MAX_WEB_REQUEST_BODY_BYTES = 8 * 1024 * 1024

AsgiMessage = dict[str, Any]
AsgiReceive = Callable[[], Awaitable[AsgiMessage]]
AsgiSend = Callable[[AsgiMessage], Awaitable[None]]


async def _send_error(send: AsgiSend, status: int, detail: str) -> None:
    payload = json.dumps({"detail": detail}, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class RequestBodyLimitMiddleware:
    """Buffer at most one bounded request before handing it to FastAPI.

    FastAPI parses JSON before route-level field checks run. Without an ASGI
    boundary, a caller can make the process allocate an arbitrary request body
    even though the eventual message, persona, or config value is rejected.
    """

    def __init__(
        self,
        app: Callable[[dict[str, Any], AsgiReceive, AsgiSend], Awaitable[None]],
        *,
        max_body_bytes: int = _MAX_WEB_REQUEST_BODY_BYTES,
    ) -> None:
        self.app = app
        self.max_body_bytes = max(1, int(max_body_bytes))

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        lengths = {
            value.strip()
            for name, value in scope.get("headers", [])
            if bytes(name).lower() == b"content-length"
        }
        if len(lengths) > 1:
            await _send_error(send, 400, "invalid_content_length")
            return
        if lengths:
            try:
                content_length = int(next(iter(lengths)))
            except (TypeError, ValueError):
                await _send_error(send, 400, "invalid_content_length")
                return
            if content_length < 0:
                await _send_error(send, 400, "invalid_content_length")
                return
            if content_length > self.max_body_bytes:
                await _send_error(send, 413, "request_body_too_large")
                return

        messages: list[AsgiMessage] = []
        total = 0
        while True:
            message = await receive()
            messages.append(message)
            if message.get("type") == "http.disconnect":
                break
            if message.get("type") != "http.request":
                continue
            body = message.get("body", b"")
            total += len(body) if isinstance(body, bytes) else 0
            if total > self.max_body_bytes:
                await _send_error(send, 413, "request_body_too_large")
                return
            if not message.get("more_body", False):
                break

        position = 0

        async def replay() -> AsgiMessage:
            nonlocal position
            if position < len(messages):
                message = messages[position]
                position += 1
                return message
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)
