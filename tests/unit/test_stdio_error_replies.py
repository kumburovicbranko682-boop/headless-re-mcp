"""stdio parse-error replies: the id-extraction edges and the server that uses them.

`test_mcp_server.py` already pins the public helper on a recursion-deep request,
a clean line and id-less garbage, plus the oversized drain. These cover the
paths that decide *whether* a bad line can be answered -- a non-object id, a
boolean or float id, end of stream, a validation failure that is not recursion
-- and the async server that turns those decisions into JSON-RPC replies on the
write stream, which nothing else exercises end to end.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO

import anyio
import pytest

from headless_re_mcp.mcp import stdio_errors
from headless_re_mcp.mcp.stdio_errors import (
    _read_bounded_line,
    _request_id,
    error_message_for_unreadable_line,
)


def test_a_top_level_array_has_no_request_id() -> None:
    # Valid JSON that is not an object cannot carry an id to answer.
    assert _request_id("[1, 2, 3]") is None


def test_a_bare_number_has_no_request_id() -> None:
    assert _request_id("5") is None


def test_a_boolean_id_is_refused() -> None:
    # JSON true parses to Python True, which is an int subclass; a boolean is
    # not a usable JSON-RPC id and must not be mistaken for one.
    assert _request_id('{"id": true}') is None


def test_a_float_id_is_refused() -> None:
    assert _request_id('{"id": 1.5}') is None


def test_a_string_and_an_integer_id_are_both_kept() -> None:
    assert _request_id('{"id": "abc"}') == "abc"
    assert _request_id('{"id": 42}') == 42


@pytest.mark.asyncio
async def test_end_of_stream_reads_as_empty_not_oversized() -> None:
    empty, oversized = await _read_bounded_line(BytesIO(b""), limit=64)
    assert empty == b""
    assert oversized is False


def test_a_non_recursion_validation_error_is_answered_with_its_first_line() -> None:
    # A structurally valid object with an id that still fails JSON-RPC validation
    # (method must be a string) takes the branch that is not the recursion
    # rewrite: the reply carries the first line of the validation message.
    line = '{"jsonrpc":"2.0","id":9,"method":123}'
    reply = error_message_for_unreadable_line(line)
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 9
    assert dumped["error"]["code"] == -32600
    assert "nested too deeply" not in dumped["error"]["message"]
    assert dumped["error"]["message"]


class _FakeStd:
    """Stand-in for sys.stdin / sys.stdout exposing only the binary buffer."""

    def __init__(self, buffer: BytesIO) -> None:
        self.buffer = buffer


@pytest.mark.asyncio
async def test_the_server_forwards_a_good_line_and_answers_a_bad_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    bad = b'{"jsonrpc":"2.0","id":2,"method":123}\n'
    monkeypatch.setattr(sys, "stdin", _FakeStd(BytesIO(good + bad)))
    out = BytesIO()
    monkeypatch.setattr(sys, "stdout", _FakeStd(out))

    with anyio.fail_after(5):
        async with stdio_errors.stdio_server_with_parse_replies() as (
            read_stream,
            write_stream,
        ):
            forwarded = await read_stream.receive()
            # The bad line's reply is written to stdout by the writer task; wait
            # for it, capture it before the wrapper closes the buffer, then close
            # the write stream so the writer task can finish and the group exit.
            while out.getvalue() == b"":
                await anyio.sleep(0.01)
            written = out.getvalue()
            await write_stream.aclose()

    forwarded_id = json.loads(forwarded.message.model_dump_json())["id"]
    assert forwarded_id == 1
    reply = json.loads(written.decode().strip())
    assert reply["id"] == 2
    assert reply["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_the_server_drops_an_unanswerable_line_and_keeps_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A line that fails validation and carries no id cannot be answered, so the
    # reader drops it in silence and moves on -- the next valid line must still
    # be forwarded rather than the reader wedging on the bad one.
    unanswerable = b'{"not":"a jsonrpc message"}\n'
    good = b'{"jsonrpc":"2.0","id":7,"method":"ping"}\n'
    monkeypatch.setattr(sys, "stdin", _FakeStd(BytesIO(unanswerable + good)))
    out = BytesIO()
    monkeypatch.setattr(sys, "stdout", _FakeStd(out))

    with anyio.fail_after(5):
        async with stdio_errors.stdio_server_with_parse_replies() as (
            read_stream,
            write_stream,
        ):
            forwarded = await read_stream.receive()
            await write_stream.aclose()

    assert json.loads(forwarded.message.model_dump_json())["id"] == 7


@pytest.mark.asyncio
async def test_the_server_drops_an_oversized_record_and_keeps_reading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Drive the server's oversized branch without allocating a multi-megabyte
    # line: stub the reader (its own drain logic is covered elsewhere) to report
    # the first record oversized. The server builds the size-limit error, finds
    # no id in the truncated prefix, drops it in silence, and reads on to the
    # next valid line.
    records: list[tuple[bytes, bool]] = [
        (b'{"jsonrpc":"2.0","id":3,"meth', True),
        (b'{"jsonrpc":"2.0","id":4,"method":"ping"}\n', False),
        (b"", False),
    ]

    async def fake_read(stream: object, *, limit: int = 0) -> tuple[bytes, bool]:
        return records.pop(0)

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", fake_read)
    monkeypatch.setattr(sys, "stdin", _FakeStd(BytesIO()))
    out = BytesIO()
    monkeypatch.setattr(sys, "stdout", _FakeStd(out))

    with anyio.fail_after(5):
        async with stdio_errors.stdio_server_with_parse_replies() as (
            read_stream,
            write_stream,
        ):
            forwarded = await read_stream.receive()
            await write_stream.aclose()

    assert json.loads(forwarded.message.model_dump_json())["id"] == 4
