"""Coverage for the stdio parse-error boundary that fronts the MCP SDK reader.

``test_mcp_server.py`` pins the recursion reply and the oversized-record drain.
This file fills in the rest of ``mcp/stdio_errors.py``: the request-id extractor
refusing a non-object / non-scalar id, a plain (non-recursion) parse failure
still earning a named error, EOF on the bounded reader, and -- the bulk -- the
``stdio_server_with_parse_replies`` context manager itself, driven with a faked
stdin/stdout so a valid line is forwarded, an unreadable line that carries an id
is answered on the write stream, an id-less line stays silent, and an oversized
record with a recoverable id is refused.
"""

from __future__ import annotations

import json
import sys
import types
from io import BytesIO
from typing import Any

import pytest

import headless_re_mcp.mcp.stdio_errors as stdio_errors
from headless_re_mcp.mcp.stdio_errors import (
    _read_bounded_line,
    error_message_for_unreadable_line,
    stdio_server_with_parse_replies,
)


# --------------------------------------------------------------------------- #
# request-id extraction and the plain parse-failure reply                     #
# --------------------------------------------------------------------------- #
def test_a_json_value_that_is_not_an_object_stays_silent() -> None:
    """Valid JSON, but a bare array has no id to correlate a reply to."""
    assert error_message_for_unreadable_line("[1, 2, 3]") is None


@pytest.mark.parametrize("line", ['{"id": true}', '{"id": 1.5}', '{"id": [1]}'])
def test_a_non_scalar_or_boolean_id_stays_silent(line: str) -> None:
    """JSON-RPC ids are strings or integers; anything else cannot be echoed."""
    assert error_message_for_unreadable_line(line) is None


def test_a_plain_parse_failure_with_an_id_earns_a_named_error() -> None:
    """A well-formed id on an otherwise invalid message still gets an error.

    This is the non-recursion arm: the message is not nested too deep, so the
    reply carries the first line of the validation error rather than the
    "nested too deeply" text, keyed to the request id.
    """
    reply = error_message_for_unreadable_line('{"jsonrpc":"2.0","id":5}')
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 5
    assert dumped["error"]["code"] == -32600
    assert "nested too deeply" not in dumped["error"]["message"]


@pytest.mark.asyncio
async def test_the_bounded_reader_reports_eof_as_an_empty_record() -> None:
    line, oversized = await _read_bounded_line(BytesIO(), limit=64)
    assert line == b""
    assert oversized is False


# --------------------------------------------------------------------------- #
# stdio_server_with_parse_replies                                             #
# --------------------------------------------------------------------------- #
class _KeepOpenBytesIO(BytesIO):
    """A stdout buffer the test can still read after the server tears down.

    ``stdio_server_with_parse_replies`` wraps ``sys.stdout.buffer`` in a
    ``TextIOWrapper`` that closes the underlying buffer when the context manager
    exits (and on finalization). A real BytesIO would then raise on getvalue();
    making close a no-op keeps the written bytes inspectable.
    """

    def close(self) -> None:
        pass


def _fake_std(monkeypatch: pytest.MonkeyPatch, stdin_bytes: bytes) -> BytesIO:
    stdout_buf = _KeepOpenBytesIO()
    monkeypatch.setattr(sys, "stdin", types.SimpleNamespace(buffer=BytesIO(stdin_bytes)))
    monkeypatch.setattr(sys, "stdout", types.SimpleNamespace(buffer=stdout_buf))
    return stdout_buf


def _replies(stdout_buf: BytesIO) -> list[dict[str, Any]]:
    text = stdout_buf.getvalue().decode("utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


@pytest.mark.asyncio
async def test_server_forwards_valid_lines_and_answers_unreadable_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid request reaches the read stream; a bad one with an id is answered.

    The id-less garbage produces no reply, matching the silence a complete
    parse failure already gave, so the only thing written back is the refusal
    for the line that could actually be correlated.
    """
    stdout_buf = _fake_std(
        monkeypatch,
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"id":5}\n{oops-no-id\n',
    )

    received = []
    async with stdio_server_with_parse_replies() as (read_stream, write_stream), write_stream:
        async for session_message in read_stream:
            received.append(session_message.message)

    assert len(received) == 1
    forwarded = json.loads(received[0].model_dump_json(by_alias=True, exclude_none=True))
    assert forwarded["id"] == 1
    assert forwarded["method"] == "ping"

    replies = _replies(stdout_buf)
    assert len(replies) == 1
    assert replies[0]["id"] == 5
    assert replies[0]["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_server_refuses_an_oversized_record_that_still_has_an_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An oversized record whose id can be recovered is refused, not dropped.

    The reader is scripted to report one oversized record (carrying a readable
    id) then EOF, so the oversize branch of the reader loop runs and its reply
    lands on stdout keyed to that id.
    """
    stdout_buf = _fake_std(monkeypatch, b"")

    scripted = iter(
        [
            (b'{"jsonrpc":"2.0","id":8,"method":"ping"}\n', True),
            # A truncated prefix whose id cannot be recovered stays silent.
            (b'{"jsonrpc":"2.0","id', True),
            (b"", False),
        ]
    )

    async def fake_read_bounded_line(stream: Any, *, limit: int = 0) -> tuple[bytes, bool]:
        return next(scripted)

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", fake_read_bounded_line)

    received = []
    async with stdio_server_with_parse_replies() as (read_stream, write_stream), write_stream:
        async for session_message in read_stream:
            received.append(session_message.message)

    assert received == []
    replies = _replies(stdout_buf)
    assert len(replies) == 1
    assert replies[0]["id"] == 8
    assert "exceeds" in replies[0]["error"]["message"].lower()


@pytest.mark.asyncio
async def test_closing_the_read_stream_mid_handoff_shuts_down_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session that stops reading with a request still pending must not crash.

    The client pipelines two requests; the session takes the first and closes
    its read stream (shutdown). The reader is then handing over the second
    request into a rendezvous stream whose receiver just went away, which
    breaks the send with BrokenResourceError. That used to escape the task
    group, so the whole stdio server raised an ExceptionGroup on exit instead
    of shutting down quietly.
    """
    _fake_std(
        monkeypatch,
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
    )

    async with stdio_server_with_parse_replies() as (read_stream, write_stream), write_stream:
        first = await read_stream.receive()
        await read_stream.aclose()

    forwarded = json.loads(first.message.model_dump_json(by_alias=True, exclude_none=True))
    assert forwarded["id"] == 1
