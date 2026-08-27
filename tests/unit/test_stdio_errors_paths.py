"""Guard-path tests for the stdio transport that answers unreadable requests.

Every track -- Android, web, .NET, portable, and PE alike -- reaches the
server through ``stdio_server_with_parse_replies``.  These tests drive the
real transport with in-memory stdin/stdout buffers so the reader task, the
writer task, and the reply-on-parse-failure paths all execute without a live
MCP client attached.
"""

from __future__ import annotations

import io
import json
import sys
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCResponse

from headless_re_mcp.mcp.stdio_errors import (
    _MAX_STDIO_MESSAGE_BYTES,
    _error_for_parse_failure,
    _read_bounded_line,
    _request_id,
    stdio_server_with_parse_replies,
)


class _KeepOpenBytesIO(io.BytesIO):
    """A BytesIO whose close is a no-op.

    The transport wraps stdout in a TextIOWrapper; when that wrapper is
    collected it closes the underlying buffer, which would destroy the
    captured output before the assertions get to read it.
    """

    def close(self) -> None:
        pass


def _patch_stdio(monkeypatch: pytest.MonkeyPatch, input_bytes: bytes) -> io.BytesIO:
    out = _KeepOpenBytesIO()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(input_bytes)))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=out))
    return out


def _stdout_records(buffer: io.BytesIO) -> list[dict[str, Any]]:
    text = buffer.getvalue().decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line]


@pytest.mark.asyncio
async def test_read_bounded_line_returns_empty_at_eof() -> None:
    line, oversized = await _read_bounded_line(io.BytesIO(b""), limit=64)
    assert line == b""
    assert oversized is False


@pytest.mark.asyncio
async def test_read_bounded_line_drain_stops_at_eof_without_newline() -> None:
    """An oversized record cut off by EOF must not spin the drain loop forever."""
    stream = io.BytesIO(b"x" * 100)
    line, oversized = await _read_bounded_line(stream, limit=64)
    assert oversized is True
    assert len(line) == 65
    following, following_oversized = await _read_bounded_line(stream, limit=64)
    assert following == b""
    assert following_oversized is False


def test_request_id_rejects_ids_a_reply_cannot_be_correlated_to() -> None:
    assert _request_id("{not json") is None
    assert _request_id("[1, 2]") is None
    assert _request_id('{"jsonrpc": "2.0"}') is None
    assert _request_id('{"id": true}') is None
    assert _request_id('{"id": 1.5}') is None
    assert _request_id('{"id": null}') is None
    assert _request_id('{"id": 7}') == 7
    assert _request_id('{"id": "abc"}') == "abc"


def test_parse_failure_reply_uses_the_first_line_of_the_exception() -> None:
    reply = _error_for_parse_failure('{"id": 3}', ValueError("bad value\nsecond line"))
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 3
    assert dumped["error"]["code"] == -32600
    assert dumped["error"]["message"] == "bad value"


def test_parse_failure_reply_truncates_very_long_messages() -> None:
    reply = _error_for_parse_failure('{"id": 4}', ValueError("x" * 5000))
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert len(dumped["error"]["message"]) == 2048


def test_parse_failure_without_an_id_stays_silent() -> None:
    assert _error_for_parse_failure("[1]", ValueError("nope")) is None


@pytest.mark.asyncio
async def test_transport_forwards_valid_requests_and_outbound_replies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = _patch_stdio(monkeypatch, b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
    received: list[SessionMessage] = []
    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            async with write_stream:
                async for session_message in read_stream:
                    received.append(session_message)
                    reply = JSONRPCMessage(
                        JSONRPCResponse(jsonrpc="2.0", id=1, result={"ok": True})
                    )
                    await write_stream.send(SessionMessage(reply))
    assert len(received) == 1
    request = received[0].message.root
    assert request.method == "ping"
    assert request.id == 1
    assert _stdout_records(out) == [{"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}]


@pytest.mark.asyncio
async def test_transport_answers_an_unreadable_request_that_has_an_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request that json-parses but fails validation still gets its error."""
    out = _patch_stdio(monkeypatch, b'{"jsonrpc":"2.0","id":7,"method":123}\n')
    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            async with write_stream:
                received = [message async for message in read_stream]
    assert received == []
    records = _stdout_records(out)
    assert len(records) == 1
    assert records[0]["id"] == 7
    assert records[0]["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_transport_drops_garbage_without_an_id_and_keeps_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"{not json at all\n" + b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    out = _patch_stdio(monkeypatch, payload)
    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            async with write_stream:
                received = [message async for message in read_stream]
    assert [message.message.root.id for message in received] == [2]
    assert _stdout_records(out) == []


@pytest.mark.asyncio
async def test_transport_recovers_after_an_oversized_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An oversized record whose id is unreadable is dropped, not fatal."""
    huge = b'{"pad":"' + b"a" * _MAX_STDIO_MESSAGE_BYTES + b'"}\n'
    valid = b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    out = _patch_stdio(monkeypatch, huge + valid)
    with anyio.fail_after(30):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            async with write_stream:
                received = [message async for message in read_stream]
    assert [message.message.root.id for message in received] == [2]
    assert _stdout_records(out) == []


@pytest.mark.asyncio
async def test_transport_answers_an_oversized_record_whose_prefix_carries_the_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the retained prefix happens to be complete JSON, the id gets a reply."""
    cap = _MAX_STDIO_MESSAGE_BYTES
    head = b'{"jsonrpc":"2.0","id":9,"method":"ping","pad":"'
    tail = b'"}'
    document = head + b"a" * (cap + 1 - len(head) - len(tail)) + tail
    assert len(document) == cap + 1
    out = _patch_stdio(monkeypatch, document + b"overflow\n")
    with anyio.fail_after(30):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            async with write_stream:
                received = [message async for message in read_stream]
    assert received == []
    records = _stdout_records(out)
    assert len(records) == 1
    assert records[0]["id"] == 9
    assert records[0]["error"]["code"] == -32600
    assert "exceeds" in records[0]["error"]["message"]
