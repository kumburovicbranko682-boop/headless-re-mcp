"""Header-validation and stream edges of the request-body limit middleware.

``test_web_body_limit`` pins the two rejections that matter most (declared and
streamed over-limit) and the accepted-body replay. This file pins the rest of
the ASGI boundary: the pass-throughs that must not buffer, the Content-Length
values that must be refused before a byte is read, and the stream shapes the
buffer loop has to survive -- a mid-stream disconnect, an interleaved non-body
message, and a downstream that pulls past the end of the buffered request.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.web.body_limit import RequestBodyLimitMiddleware


def _sink() -> tuple[list[dict[str, Any]], Any]:
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    return sent, send


def _feed(messages: list[dict[str, Any]]) -> Any:
    incoming = iter(messages)

    async def receive() -> dict[str, Any]:
        return next(incoming)

    return receive


@pytest.mark.asyncio
async def test_non_http_scope_passes_straight_through() -> None:
    """A websocket/lifespan scope is handed to the app untouched -- the body
    guard only applies to HTTP requests."""
    routed_with: dict[str, Any] = {}

    async def receive() -> dict[str, Any]:
        raise AssertionError("a non-http scope must not be buffered")

    sent, send = _sink()

    async def downstream(scope: dict[str, Any], recv: Any, snd: Any) -> None:
        routed_with["scope"] = scope
        routed_with["receive"] = recv

    middleware = RequestBodyLimitMiddleware(downstream)
    await middleware({"type": "websocket"}, receive, send)

    assert routed_with["scope"]["type"] == "websocket"
    # The app got the original receive, not the buffering replay.
    assert routed_with["receive"] is receive
    assert sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
async def test_bodyless_methods_are_not_buffered(method: str) -> None:
    routed = False

    async def receive() -> dict[str, Any]:
        raise AssertionError("bodyless methods must not be received from")

    sent, send = _sink()

    async def downstream(_scope: dict[str, Any], recv: Any, _snd: Any) -> None:
        nonlocal routed
        routed = True
        assert recv is receive

    middleware = RequestBodyLimitMiddleware(downstream)
    await middleware(
        {"type": "http", "method": method, "headers": [(b"content-length", b"999999999")]},
        receive,
        send,
    )

    assert routed is True
    assert sent == []


@pytest.mark.asyncio
async def test_conflicting_content_length_headers_are_refused() -> None:
    routed = False

    sent, send = _sink()

    async def receive() -> dict[str, Any]:
        raise AssertionError("a conflicting length must be refused before receiving")

    async def downstream(_scope: dict[str, Any], _recv: Any, _snd: Any) -> None:
        nonlocal routed
        routed = True

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-length", b"10"), (b"content-length", b"20")],
        },
        receive,
        send,
    )

    assert routed is False
    assert sent[0]["status"] == 400
    assert b"invalid_content_length" in sent[1]["body"]


@pytest.mark.asyncio
async def test_a_single_repeated_length_value_is_accepted() -> None:
    """Two identical Content-Length headers collapse to one value and are not
    treated as a conflict."""
    received: list[bytes] = []
    sent, send = _sink()
    receive = _feed([{"type": "http.request", "body": b"okay", "more_body": False}])

    async def downstream(_scope: dict[str, Any], replay: Any, _snd: Any) -> None:
        message = await replay()
        received.append(message.get("body", b""))

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {
            "type": "http",
            "method": "POST",
            "headers": [(b"content-length", b"4"), (b"content-length", b"4")],
        },
        receive,
        send,
    )

    assert received == [b"okay"]
    assert sent == []


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [b"not-a-number", b"12.5", b""])
async def test_unparseable_content_length_is_refused(raw: bytes) -> None:
    sent, send = _sink()

    async def receive() -> dict[str, Any]:
        raise AssertionError("an unparseable length must be refused before receiving")

    async def downstream(_scope: dict[str, Any], _recv: Any, _snd: Any) -> None:
        raise AssertionError("an unparseable length must not be routed")

    middleware = RequestBodyLimitMiddleware(downstream)
    await middleware(
        {"type": "http", "method": "POST", "headers": [(b"content-length", raw)]},
        receive,
        send,
    )

    assert sent[0]["status"] == 400
    assert b"invalid_content_length" in sent[1]["body"]


@pytest.mark.asyncio
async def test_negative_content_length_is_refused() -> None:
    sent, send = _sink()

    async def receive() -> dict[str, Any]:
        raise AssertionError("a negative length must be refused before receiving")

    async def downstream(_scope: dict[str, Any], _recv: Any, _snd: Any) -> None:
        raise AssertionError("a negative length must not be routed")

    middleware = RequestBodyLimitMiddleware(downstream)
    await middleware(
        {"type": "http", "method": "POST", "headers": [(b"content-length", b"-1")]},
        receive,
        send,
    )

    assert sent[0]["status"] == 400
    assert b"invalid_content_length" in sent[1]["body"]


@pytest.mark.asyncio
async def test_a_disconnect_ends_buffering_and_is_replayed() -> None:
    """A client that drops mid-request stops the buffer loop, and the recorded
    disconnect is what the app replays -- no error is synthesized."""
    replayed: list[str] = []
    sent, send = _sink()
    receive = _feed([{"type": "http.disconnect"}])

    async def downstream(_scope: dict[str, Any], replay: Any, _snd: Any) -> None:
        message = await replay()
        replayed.append(message["type"])

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {"type": "http", "method": "POST", "headers": []},
        receive,
        send,
    )

    assert replayed == ["http.disconnect"]
    assert sent == []


@pytest.mark.asyncio
async def test_non_request_messages_are_buffered_without_counting() -> None:
    """A message that is neither a body chunk nor a disconnect is kept in order
    but does not add to the byte total, and the following body is accepted."""
    bodies: list[bytes] = []
    sent, send = _sink()
    receive = _feed(
        [
            {"type": "http.request.custom"},
            {"type": "http.request", "body": b"payload", "more_body": False},
        ]
    )

    async def downstream(_scope: dict[str, Any], replay: Any, _snd: Any) -> None:
        while True:
            message = await replay()
            if message.get("type") == "http.request":
                bodies.append(message.get("body", b""))
            if message.get("type") == "http.disconnect":
                break
            if not message.get("more_body", False) and message.get("type") == "http.request":
                break

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {"type": "http", "method": "POST", "headers": []},
        receive,
        send,
    )

    assert bodies == [b"payload"]
    assert sent == []


@pytest.mark.asyncio
async def test_replay_past_the_end_yields_a_disconnect() -> None:
    """A downstream that pulls more messages than were buffered gets a synthetic
    disconnect rather than raising."""
    tail: dict[str, Any] = {}
    sent, send = _sink()
    receive = _feed([{"type": "http.request", "body": b"hi", "more_body": False}])

    async def downstream(_scope: dict[str, Any], replay: Any, _snd: Any) -> None:
        await replay()  # the single buffered body chunk
        tail["extra"] = await replay()  # one past the end

    middleware = RequestBodyLimitMiddleware(downstream, max_body_bytes=1024)
    await middleware(
        {"type": "http", "method": "POST", "headers": [(b"content-length", b"2")]},
        receive,
        send,
    )

    assert tail["extra"] == {"type": "http.disconnect"}
    assert sent == []
