"""The stdio parse-reply shim must answer an unreadable request that still has
an id, and stay silent when there is no id to correlate a reply to.

The MCP SDK forwards a parse failure inward and never writes a JSON-RPC
response, so an unattended caller sees nothing. ``stdio_server_with_parse_replies``
wraps the SDK streams to turn a parseable-id-but-invalid line into an error on
the write stream. These pin the id-extraction branches and drive the wrapper
end to end so a regression that swallows the reply, or invents one for id-less
garbage, fails here.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO, TextIOWrapper
from types import SimpleNamespace

import anyio
import pytest

from headless_re_mcp.mcp.stdio_errors import (
    _read_bounded_line,
    error_message_for_unreadable_line,
    stdio_server_with_parse_replies,
)

INVALID_REQUEST_CODE = -32600


class _CapturingBytesIO(BytesIO):
    """A stdout buffer that survives TextIOWrapper finalization.

    ``stdio_server_with_parse_replies`` wraps ``sys.stdout.buffer`` in a
    TextIOWrapper, which closes the underlying buffer when it is finalized --
    so a plain BytesIO is unreadable by the time the test inspects it. Snapshot
    the bytes on close and keep the buffer open instead.
    """

    captured: bytes = b""

    def close(self) -> None:  # noqa: D401 - see class docstring
        self.captured = self.getvalue()
        # Deliberately not calling super().close(): keep it readable.


@pytest.mark.asyncio
async def test_reading_an_empty_stream_reports_eof() -> None:
    line, oversized = await _read_bounded_line(BytesIO(b""))
    assert line == b""
    assert oversized is False


@pytest.mark.parametrize(
    "line",
    [
        "[1,2,3]",  # valid JSON, but not an object -> no id
        '{"foo":"bar"}',  # object without an id
        '{"id":true,"method":"x"}',  # a bool id is not a usable correlation id
        '{"id":1.5,"method":"x"}',  # a float id is neither str nor int
    ],
)
def test_a_line_without_a_usable_id_stays_silent(line: str) -> None:
    # No id means the caller cannot match a reply, so silence is the contract --
    # exactly what parsing complete garbage already did.
    assert error_message_for_unreadable_line(line) is None


def test_a_with_id_validation_failure_is_reported_verbatim_first_line() -> None:
    # A non-recursion validation failure keeps the first line of the real error
    # (truncated), not the friendly recursion message, so the caller can see why.
    line = '{"jsonrpc":"2.0","id":5,"method":123}'
    reply = error_message_for_unreadable_line(line)
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 5
    assert dumped["error"]["code"] == INVALID_REQUEST_CODE
    assert "nested too deeply" not in dumped["error"]["message"]
    assert "\n" not in dumped["error"]["message"]


@pytest.mark.asyncio
async def test_wrapper_forwards_valid_and_replies_to_invalid_with_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    invalid_with_id = b'{"jsonrpc":"2.0","id":99,"method":123}\n'
    # A trailing id-less garbage line must not produce a reply of its own.
    garbage_no_id = b"{not-json\n"

    stdin_buffer = BytesIO(valid + invalid_with_id + garbage_no_id)
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=stdin_buffer))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    received_ids: list[object] = []
    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            # The one valid line arrives as a parsed message on the read stream.
            message = await read_stream.receive()
            received_ids.append(
                json.loads(message.message.model_dump_json())["id"]
            )
            # Closing our write handle lets the writer task drain and exit once
            # the reader closes its own error clone at EOF.
            await write_stream.aclose()

    assert received_ids == [1]

    written = stdout_buffer.captured.decode("utf-8")
    replies = [json.loads(row) for row in written.splitlines() if row.strip()]
    # Exactly one reply: the invalid line that carried an id. The valid line
    # went to the read stream, and the id-less garbage produced nothing.
    assert len(replies) == 1
    assert replies[0]["id"] == 99
    assert replies[0]["error"]["code"] == INVALID_REQUEST_CODE


@pytest.mark.asyncio
async def test_wrapper_writes_a_reply_for_each_addressed_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two id-carrying invalid lines each get their own reply, keyed by id, so a
    # batch of malformed calls is answered one-for-one rather than collapsed.
    lines = b'{"jsonrpc":"2.0","id":"a","method":1}\n{"jsonrpc":"2.0","id":"b","method":2}\n'
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(lines)))
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
            await write_stream.aclose()

    written = stdout_buffer.captured.decode("utf-8")
    replies = [json.loads(row) for row in written.splitlines() if row.strip()]
    assert [r["id"] for r in replies] == ["a", "b"]
    assert all(r["error"]["code"] == INVALID_REQUEST_CODE for r in replies)


def test_textiowrapper_smoke_is_not_left_open() -> None:
    # Guard the test's own assumption that a BytesIO survives TextIOWrapper use
    # (the wrapper must not detach/close the underlying buffer we read back).
    buf = BytesIO()
    wrapper = TextIOWrapper(buf, encoding="utf-8")
    wrapper.write("x")
    wrapper.flush()
    assert buf.getvalue() == b"x"
