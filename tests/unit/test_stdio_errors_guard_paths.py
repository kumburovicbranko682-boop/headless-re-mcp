"""Guard paths for the stdio parse-reply shim.

The SDK reader forwards a parse failure inward, so a request the SDK cannot
validate produces an "Internal Server Error" log and no JSON-RPC response at
all. ``stdio_server_with_parse_replies`` wraps the SDK transport so an
unreadable request that still carries an id gets an error reply on the write
stream. The happy-path helper (``error_message_for_unreadable_line``) and the
oversized-drain reader are pinned elsewhere; this file drives the wrapped
transport's own reader/writer tasks, the id-extraction guards, the recursion
vs. plain error text split, and the two ``ClosedResourceError`` unwinds that a
downstream close triggers.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
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


class _Std:
    """A minimal ``sys.stdin`` / ``sys.stdout`` stand-in exposing ``.buffer``."""

    def __init__(self, buffer: Any) -> None:
        self.buffer = buffer


class _BoomBuffer(io.BytesIO):
    """A stdout buffer whose write path fails as if the peer had gone away."""

    def write(self, data: Any) -> int:
        raise anyio.ClosedResourceError


class _CaptureBuffer(io.BytesIO):
    """A stdout buffer that survives the TextIOWrapper closing it on teardown."""

    def close(self) -> None:
        # The wrapper closes its buffer when the transport unwinds; keep the
        # written bytes readable so the test can inspect the replies after.
        pass


def _set_std(monkeypatch: pytest.MonkeyPatch, *, stdin: Any, stdout: Any) -> None:
    monkeypatch.setattr(sys, "stdin", _Std(stdin))
    monkeypatch.setattr(sys, "stdout", _Std(stdout))


# --------------------------------------------------------------------------
# _read_bounded_line EOF
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_bounded_line_returns_empty_at_eof() -> None:
    """An empty read is reported as end-of-stream, not an oversized record."""
    encoded, oversized = await _read_bounded_line(io.BytesIO(b""), limit=64)
    assert encoded == b""
    assert oversized is False


@pytest.mark.asyncio
async def test_read_bounded_line_drains_an_oversized_record() -> None:
    """An oversized record is flagged and its remainder drained, not buffered.

    The bounded prefix is returned with the oversized flag, and the reader
    advances past the rest of that line so the next call sees the following
    record intact rather than a mid-line fragment.
    """
    valid = b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    stream = io.BytesIO(b'{"padding":"' + b"x" * 256 + b'"}\n' + valid)
    oversized, was_oversized = await _read_bounded_line(stream, limit=64)
    following, following_oversized = await _read_bounded_line(stream, limit=64)
    assert was_oversized is True
    assert len(oversized) == 65
    assert following == valid
    assert following_oversized is False


# --------------------------------------------------------------------------
# _request_id guards
# --------------------------------------------------------------------------


def test_request_id_none_for_a_non_object_payload() -> None:
    """A JSON array has no request id to answer."""
    assert _request_id("[1, 2, 3]") is None


def test_request_id_none_when_the_id_key_is_absent() -> None:
    """An object without an ``id`` field has no id to answer."""
    assert _request_id('{"jsonrpc": "2.0", "method": "ping"}') is None


def test_request_id_rejects_a_boolean_id() -> None:
    """A boolean id is not a valid JSON-RPC id and is refused."""
    assert _request_id('{"id": true}') is None


def test_request_id_rejects_a_non_string_non_int_id() -> None:
    """A float (or any non str/int) id is refused rather than coerced."""
    assert _request_id('{"id": 1.5}') is None


def test_request_id_accepts_a_string_or_int_id() -> None:
    """A plain string or integer id is returned verbatim."""
    assert _request_id('{"id": 42}') == 42
    assert _request_id('{"id": "abc"}') == "abc"


# --------------------------------------------------------------------------
# _error_for_parse_failure text shaping (via the public helper)
# --------------------------------------------------------------------------


def test_plain_validation_error_keeps_its_first_line() -> None:
    """A non-recursion parse failure carries the validation error's first line.

    ``{jsonrpc, id}`` with neither ``method`` nor ``result`` matches no
    JSON-RPC shape, so the SDK model rejects it -- but it still has an id, so
    the caller gets an INVALID_REQUEST reply naming that id instead of silence.
    """
    reply = error_message_for_unreadable_line('{"jsonrpc":"2.0","id":9}')
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 9
    assert dumped["error"]["code"] == -32600
    assert "nested too deeply" not in dumped["error"]["message"]


def test_a_recursion_failure_is_reported_as_too_deeply_nested() -> None:
    """A request that only failed by nesting too deep gets a legible message.

    pydantic gives up around 200 levels while json.loads still finds the id, so
    a deeply nested tools/call is answered with a "nested too deeply" reply
    naming the request rather than an opaque validation dump.
    """
    nested = '{"a":' * 200 + "1" + "}" * 200
    line = (
        '{"jsonrpc":"2.0","id":7,"method":"tools/call",'
        '"params":{"name":"session.get","arguments":' + nested + "}}"
    )
    reply = error_message_for_unreadable_line(line)
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 7
    assert dumped["error"]["message"] == "request is nested too deeply to parse"


def test_a_valid_line_yields_no_error() -> None:
    """A well-formed request is not turned into an error reply."""
    assert error_message_for_unreadable_line('{"jsonrpc":"2.0","id":1,"method":"ping"}') is None


def test_garbage_without_an_id_stays_silent() -> None:
    """Unparseable input with no recoverable id produces no reply."""
    assert error_message_for_unreadable_line("{not json") is None


# --------------------------------------------------------------------------
# stdio_server_with_parse_replies: reader/writer tasks
# --------------------------------------------------------------------------


def _install_reader(monkeypatch: pytest.MonkeyPatch, records: list[tuple[bytes, bool]]) -> None:
    """Drive stdin_reader with canned (bytes, oversized) records, then EOF."""
    iterator = iter(records)

    async def fake_read(
        stream: Any, *, limit: int = _MAX_STDIO_MESSAGE_BYTES
    ) -> tuple[bytes, bool]:
        del stream, limit
        try:
            return next(iterator)
        except StopIteration:
            return b"", False

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", fake_read)


@pytest.mark.asyncio
async def test_server_forwards_valid_and_replies_to_unreadable_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid line is forwarded; oversized and unparseable lines get replies.

    The oversized record (flagged by the reader) and the structurally invalid
    record both carry an id, so each yields an INVALID_REQUEST reply on the
    write stream, while the well-formed request is delivered to the read stream.
    """
    records = [
        (b'{"jsonrpc":"2.0","id":1,"method":"ping"}', False),
        (b'{"jsonrpc":"2.0","id":2,"method":"ping"}', True),
        (b'{"jsonrpc":"2.0","id":3,"method":123}', False),
        # Oversized but id-less, and unparseable but id-less: each has nothing
        # to answer, so neither adds a reply to the write stream.
        (b'{"jsonrpc":"2.0","method":"ping"}', True),
        (b'{"method":123}', False),
    ]
    _install_reader(monkeypatch, records)
    out_buffer = _CaptureBuffer()
    _set_std(monkeypatch, stdin=io.BytesIO(b""), stdout=out_buffer)

    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        session_message = await read_stream.receive()
        with contextlib.suppress(Exception):
            await write_stream.aclose()

    delivered = json.loads(session_message.message.model_dump_json(by_alias=True))
    assert delivered["id"] == 1

    replies = [json.loads(line) for line in out_buffer.getvalue().decode().splitlines() if line]
    ids = {reply["id"] for reply in replies}
    assert ids == {2, 3}
    assert all(reply["error"]["code"] == -32600 for reply in replies)
    # The oversized reply names the byte ceiling it tripped.
    oversized_reply = next(reply for reply in replies if reply["id"] == 2)
    assert "exceeds" in oversized_reply["error"]["message"]


@pytest.mark.asyncio
async def test_server_reader_unwinds_on_a_closed_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ClosedResourceError from the reader unwinds the stdin task cleanly."""

    async def closed_read(
        stream: Any, *, limit: int = _MAX_STDIO_MESSAGE_BYTES
    ) -> tuple[bytes, bool]:
        del stream, limit
        raise anyio.ClosedResourceError

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", closed_read)
    _set_std(monkeypatch, stdin=io.BytesIO(b""), stdout=io.BytesIO())

    async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
        with contextlib.suppress(Exception):
            await write_stream.aclose()
        await anyio.sleep(0.05)
    # Reaching here means the reader task caught the close and the group exited.


@pytest.mark.asyncio
async def test_server_writer_unwinds_when_stdout_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ClosedResourceError while writing a reply unwinds the stdout task."""
    _install_reader(monkeypatch, [(b'{"jsonrpc":"2.0","id":5,"method":123}', False)])
    _set_std(monkeypatch, stdin=io.BytesIO(b""), stdout=_BoomBuffer())

    async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
        # No valid line to receive; let the reply reach the failing writer.
        await anyio.sleep(0.05)
        with contextlib.suppress(Exception):
            await write_stream.aclose()
    # Reaching here means the writer task caught the close and the group exited.
