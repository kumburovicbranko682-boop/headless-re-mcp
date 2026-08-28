"""The stdio byte ceiling must answer, and a closed stream must end quietly.

``stdio_server_with_parse_replies`` caps a request at 8 MiB so one hostile or
buggy caller cannot make the server buffer an unbounded line. The cap has the
same honesty contract as a parse failure: a capped request whose prefix still
carries an id gets a JSON-RPC error naming that id, one that does not stays
silent, and either way the remainder is drained so the *next* request on the
stream is read from a record boundary rather than from the middle of the
oversized one. Separately, both stream tasks treat ``ClosedResourceError`` as
shutdown, not a crash -- stdin or stdout going away mid-serve is how every
stdio session ends, and it must not surface as an error to the task group.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO
from types import SimpleNamespace
from typing import Any

import anyio
import pytest

from headless_re_mcp.mcp import stdio_errors
from headless_re_mcp.mcp.stdio_errors import (
    _MAX_STDIO_MESSAGE_BYTES,
    _read_bounded_line,
    stdio_server_with_parse_replies,
)

INVALID_REQUEST_CODE = -32600


class _CapturingBytesIO(BytesIO):
    """Survives the wrapper's close so the test can read what was written."""

    def close(self) -> None:
        pass


def _oversized_json_line(request_id: int) -> bytes:
    """A complete JSON request padded to exactly one byte over the cap.

    ``readline(cap + 1)`` returns the whole line including the newline, so the
    prefix the error path parses is valid JSON and still names the id -- the
    smallest request the cap rejects while an answer is still possible.
    """
    head = b'{"jsonrpc":"2.0","id":%d,"method":"ping","params":{"pad":"' % request_id
    tail = b'"}}\n'
    padding = _MAX_STDIO_MESSAGE_BYTES + 1 - len(head) - len(tail)
    return head + b"a" * padding + tail


# ---------------------------------------------------------------------------
# _read_bounded_line: the drain loop around the cap.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_an_oversized_line_is_drained_to_its_newline() -> None:
    stream = BytesIO(b"x" * 40 + b"\n" + b'{"id":1}\n')
    line, oversized = await _read_bounded_line(stream, limit=10)
    assert oversized is True
    assert len(line) == 11  # the prefix readline returned, nothing more
    # The remainder up to the newline was consumed: the next read starts at
    # the following record, not inside the oversized one.
    follow, follow_oversized = await _read_bounded_line(stream, limit=10)
    assert follow == b'{"id":1}\n'
    assert follow_oversized is False


@pytest.mark.asyncio
async def test_an_oversized_line_hitting_eof_stops_draining() -> None:
    # No terminating newline anywhere: the drain loop must stop at EOF rather
    # than spin on empty reads.
    stream = BytesIO(b"y" * 30)
    line, oversized = await _read_bounded_line(stream, limit=10)
    assert oversized is True
    assert len(line) == 11
    follow, _ = await _read_bounded_line(stream, limit=10)
    assert follow == b""


# ---------------------------------------------------------------------------
# The wrapper: a capped request is answered when it can be, and never
# poisons the stream for the request after it.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_a_capped_request_with_an_id_gets_an_error_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_after = b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    stdin_buffer = BytesIO(_oversized_json_line(7) + valid_after)
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=stdin_buffer))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    forwarded_ids: list[object] = []
    with anyio.fail_after(30):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            message = await read_stream.receive()
            forwarded_ids.append(json.loads(message.message.model_dump_json())["id"])
            await write_stream.aclose()

    # The request after the oversized one still arrived intact.
    assert forwarded_ids == [2]
    replies = [
        json.loads(row)
        for row in stdout_buffer.getvalue().decode("utf-8").splitlines()
        if row.strip()
    ]
    assert len(replies) == 1
    assert replies[0]["id"] == 7
    assert replies[0]["error"]["code"] == INVALID_REQUEST_CODE
    assert "exceeds" in replies[0]["error"]["message"]


@pytest.mark.asyncio
async def test_a_capped_request_without_a_usable_id_stays_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The prefix of this oversized line is truncated garbage: no id can be
    # recovered, so no reply is owed -- but the stream still recovers.
    oversized_garbage = b"g" * (_MAX_STDIO_MESSAGE_BYTES + 64) + b"\n"
    valid_after = b'{"jsonrpc":"2.0","id":3,"method":"ping"}\n'
    stdin_buffer = BytesIO(oversized_garbage + valid_after)
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=stdin_buffer))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    forwarded_ids: list[object] = []
    with anyio.fail_after(30):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            message = await read_stream.receive()
            forwarded_ids.append(json.loads(message.message.model_dump_json())["id"])
            await write_stream.aclose()

    assert forwarded_ids == [3]
    assert stdout_buffer.getvalue() == b""


# ---------------------------------------------------------------------------
# ClosedResourceError is shutdown, not a crash.
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_stdin_closing_mid_read_ends_the_reader_quietly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ClosedResourceError from the stdin side ends the session, silently.

    anyio raises it when the resource a task is blocked on is closed out from
    under it -- the normal way a stdio session dies. If the reader let it
    escape, the task group would re-raise it out of the server's main loop.
    """

    async def _closed(stream: Any, **kwargs: Any) -> tuple[bytes, bool]:
        raise anyio.ClosedResourceError

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", _closed)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(b"")))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=_CapturingBytesIO()))

    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
            await write_stream.aclose()
    # Reaching here is the assertion: the task group exited without an error.


@pytest.mark.asyncio
async def test_stdout_closing_mid_write_ends_the_writer_quietly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ClosedFile:
        async def write(self, _payload: str) -> None:
            raise anyio.ClosedResourceError

        async def flush(self) -> None:
            raise anyio.ClosedResourceError

    monkeypatch.setattr(anyio, "wrap_file", lambda file: _ClosedFile())
    # One invalid-with-id line makes the reader send a reply; the writer's
    # attempt to put it on the closed stdout must end the writer, not the run.
    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(buffer=BytesIO(b'{"jsonrpc":"2.0","id":9,"method":1}\n')),
    )
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=_CapturingBytesIO()))

    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
            await write_stream.aclose()
    # Reaching here is the assertion: the writer swallowed the closed stdout.
