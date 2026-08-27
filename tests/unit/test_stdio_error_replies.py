"""The stdio parse-reply server: refusals answered, ids respected, no wedging.

test_mcp_server pins error_message_for_unreadable_line and the bounded
reader; these drive stdio_server_with_parse_replies itself over fake stdio,
which is the path a live server actually runs -- an unreadable request with
an id gets a JSON-RPC error on stdout instead of a log line, an oversized
record is drained without wedging the session, and a request nobody could
answer stays silent the way complete garbage always did.
"""

from __future__ import annotations

import io
import json
import sys
from types import SimpleNamespace
from typing import Any

import anyio
import pytest

from headless_re_mcp.mcp import stdio_errors
from headless_re_mcp.mcp.stdio_errors import (
    _MAX_STDIO_MESSAGE_BYTES,
    _read_bounded_line,
    _request_id,
    error_message_for_unreadable_line,
    stdio_server_with_parse_replies,
)


@pytest.mark.asyncio
async def test_read_bounded_line_reports_eof_as_empty() -> None:
    line, oversized = await _read_bounded_line(io.BytesIO(b""), limit=64)
    assert line == b""
    assert oversized is False


def test_request_id_refuses_shapes_nobody_could_answer() -> None:
    """No id means no reply can be correlated; a bool or fractional id is
    not a JSON-RPC id and echoing one back would invent a request."""
    assert _request_id("[1, 2, 3]") is None
    assert _request_id('{"jsonrpc": "2.0", "method": "ping"}') is None
    assert _request_id('{"id": true}') is None
    assert _request_id('{"id": 1.5}') is None
    assert _request_id('{"id": "abc"}') == "abc"
    assert _request_id('{"id": 12}') == 12


def test_non_recursion_parse_failures_answer_with_one_bounded_line() -> None:
    """A pydantic validation error is multi-line and can be huge; the reply
    carries its first line, capped, so the envelope stays readable."""
    line = '{"jsonrpc": "1.0", "id": 3, "method": "ping"}'
    reply = error_message_for_unreadable_line(line)
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 3
    assert dumped["error"]["code"] == -32600
    message = dumped["error"]["message"]
    assert "\n" not in message
    assert 0 < len(message) <= 2048
    assert "nested too deeply" not in message


class _KeepOpen(io.BytesIO):
    """The server's TextIOWrapper closes its buffer on GC; keep ours readable."""

    def close(self) -> None:
        pass


def _fake_stdio(
    monkeypatch: pytest.MonkeyPatch, payload: bytes, raw_out: io.BytesIO | None = None
) -> io.BytesIO:
    out = raw_out if raw_out is not None else _KeepOpen()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(payload)))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=out))
    return out


@pytest.mark.asyncio
async def test_server_answers_unreadable_requests_and_still_forwards_valid_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCMessage, JSONRPCResponse

    cap = _MAX_STDIO_MESSAGE_BYTES
    oversized_with_id = b'{"id": 9, "method": "big"}' + b" " * cap + b"\n"
    oversized_garbage = b"x" * (cap + 2) + b"\n"
    payload = (
        b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n'
        b'{"jsonrpc": "1.0", "id": 7, "method": "ping"}\n'
        b"{not-json\n"
        + oversized_with_id
        + oversized_garbage
        + b'{"jsonrpc": "2.0", "id": 2, "method": "ping"}\n'
    )
    out = _fake_stdio(monkeypatch, payload)

    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        first = await read_stream.receive()
        assert first.message.root.id == 1
        # The oversized records in between were drained, not accumulated:
        # the next forwarded message is the valid request after them.
        second = await read_stream.receive()
        assert second.message.root.id == 2
        with pytest.raises(anyio.EndOfStream):
            await read_stream.receive()
        response = JSONRPCMessage(JSONRPCResponse(jsonrpc="2.0", id=1, result={"pong": True}))
        await write_stream.send(SessionMessage(response))
        await write_stream.aclose()

    lines = [json.loads(line) for line in out.getvalue().decode("utf-8").splitlines()]
    by_id = {entry["id"]: entry for entry in lines}
    # The malformed request with an id was answered, not logged and dropped.
    assert by_id[7]["error"]["code"] == -32600
    # The oversized request with a readable id names the byte cap.
    assert f"exceeds {cap} bytes" in by_id[9]["error"]["message"]
    # Our own response went out on the same stdout path.
    assert by_id[1]["result"] == {"pong": True}
    # Garbage without an id stayed silent: three lines, no more.
    assert len(lines) == 3


@pytest.mark.asyncio
async def test_server_treats_a_closed_stdin_as_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stdin that closes under the reader is how the host process exits;
    that must end the session, not escape as a crash."""
    _fake_stdio(monkeypatch, b"")

    async def _closed(stream: Any, *, limit: int = 0) -> tuple[bytes, bool]:
        raise anyio.ClosedResourceError

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", _closed)
    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        with pytest.raises(anyio.EndOfStream):
            await read_stream.receive()
        await write_stream.aclose()


@pytest.mark.asyncio
async def test_server_treats_a_closed_stdout_as_shutdown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ClosedRaw(io.BytesIO):
        def write(self, data: Any) -> int:
            raise anyio.ClosedResourceError

    _fake_stdio(
        monkeypatch,
        b'{"jsonrpc": "1.0", "id": 4, "method": "ping"}\n',
        raw_out=_ClosedRaw(),
    )
    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        with pytest.raises(anyio.EndOfStream):
            await read_stream.receive()
        await write_stream.aclose()
