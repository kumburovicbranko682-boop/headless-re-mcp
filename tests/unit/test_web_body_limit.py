from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.web.body_limit import RequestBodyLimitMiddleware


@pytest.mark.asyncio
async def test_request_body_limit_rejects_chunked_bodies_before_routing() -> None:
    routed = False
    incoming = iter(
        [
            {"type": "http.request", "body": b"x" * 600, "more_body": True},
            {"type": "http.request", "body": b"y" * 600, "more_body": False},
        ]
    )
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return next(incoming)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def downstream(
        _scope: dict[str, Any],
        _receive: Any,
        _send: Any,
    ) -> None:
        nonlocal routed
        routed = True

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {"type": "http", "headers": []},
        receive,
        send,
    )

    assert routed is False
    assert sent[0]["status"] == 413
    assert b"request_body_too_large" in sent[1]["body"]


@pytest.mark.asyncio
async def test_request_body_limit_uses_content_length_before_receiving() -> None:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        raise AssertionError("oversized declared bodies must not be received")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    async def downstream(
        _scope: dict[str, Any],
        _receive: Any,
        _send: Any,
    ) -> None:
        raise AssertionError("oversized declared bodies must not be routed")

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {"type": "http", "headers": [(b"content-length", b"2048")]},
        receive,
        send,
    )

    assert sent[0]["status"] == 413


@pytest.mark.asyncio
async def test_request_body_limit_replays_an_accepted_body() -> None:
    incoming = iter(
        [
            {"type": "http.request", "body": b'{"a":', "more_body": True},
            {"type": "http.request", "body": b"1}", "more_body": False},
        ]
    )
    received: list[bytes] = []

    async def receive() -> dict[str, Any]:
        return next(incoming)

    async def send(_message: dict[str, Any]) -> None:
        return None

    async def downstream(
        _scope: dict[str, Any],
        replay: Any,
        _send: Any,
    ) -> None:
        while True:
            message = await replay()
            received.append(message.get("body", b""))
            if not message.get("more_body", False):
                break

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {"type": "http", "headers": [(b"content-length", b"7")]},
        receive,
        send,
    )

    assert b"".join(received) == b'{"a":1}'
