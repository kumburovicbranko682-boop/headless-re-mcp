"""Lock in the stdio parse-reply shim's hostile-input handling.

The SDK forwards an unreadable stdin record inward as an exception; the
server then logs "Internal Server Error" and never writes a JSON-RPC
response, so an unattended caller waits forever. This module answers such
records with an error named after the request id. The request-id sniffing,
the empty-stream stop, the non-recursion error message, and the whole
``stdio_server_with_parse_replies`` wiring were untested.
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
    _read_bounded_line,
    _request_id,
    error_message_for_unreadable_line,
)


@pytest.mark.parametrize(
    "line",
    [
        pytest.param("[1, 2, 3]", id="not-an-object"),
        pytest.param('{"method": "ping"}', id="no-id-key"),
        pytest.param('{"id": true}', id="bool-id"),
        pytest.param('{"id": 1.5}', id="float-id"),
        pytest.param('{"id": null}', id="null-id"),
        pytest.param("{not json", id="undecodable"),
    ],
)
def test_request_id_declines_when_there_is_no_answerable_id(line: str) -> None:
    assert _request_id(line) is None


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        pytest.param('{"id": 7}', 7, id="int"),
        pytest.param('{"id": "abc"}', "abc", id="string"),
    ],
)
def test_request_id_accepts_a_string_or_int_id(line: str, expected: str | int) -> None:
    assert _request_id(line) == expected


@pytest.mark.asyncio
async def test_read_bounded_line_stops_on_an_empty_stream() -> None:
    encoded, oversized = await _read_bounded_line(BytesIO(b""), limit=64)
    assert encoded == b""
    assert oversized is False


def test_a_schema_valid_json_with_an_id_gets_a_named_error_reply() -> None:
    # Valid JSON so the id is recoverable, but not a valid JSON-RPC message
    # (method must be a string). The reply must carry the id and the first
    # line of the validation error -- the non-recursion message branch.
    line = '{"jsonrpc": "2.0", "id": 11, "method": 123}'
    reply = error_message_for_unreadable_line(line)
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 11
    assert dumped["error"]["code"] == -32600
    assert "nested too deeply" not in dumped["error"]["message"]
    assert "\n" not in dumped["error"]["message"]


class _KeepOpenBytes(BytesIO):
    """A stdout buffer whose close is ignored so captured replies survive.

    ``stdio_server_with_parse_replies`` wraps ``sys.stdout.buffer`` in a
    TextIOWrapper; when that wrapper finalizes it closes the underlying
    buffer, which would make ``getvalue`` raise after the context exits.
    """

    def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_stdio_shim_forwards_valid_records_and_answers_unreadable_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records: list[tuple[bytes, bool]] = [
        (b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n', False),
        (b'{"jsonrpc":"2.0","id":2,"method":123}\n', False),
        # An oversized record whose drained prefix still exposes an id: the
        # reader answers it with the size-limit refusal instead of silence.
        (b'{"id":3}', True),
        # An oversized record whose prefix has no recoverable id stays silent,
        # the way an oversized blob of junk cannot be answered.
        (b"xxxxxxxx", True),
        # Garbage with no recoverable id stays silent, the way a parse of
        # complete junk already did.
        (b"{no-id-garbage", False),
        (b"", False),
    ]
    pending = iter(records)

    async def fake_read(stream: Any, *, limit: int = stdio_errors._MAX_STDIO_MESSAGE_BYTES) -> Any:
        del stream, limit
        return next(pending)

    out_buf = _KeepOpenBytes()
    monkeypatch.setattr(stdio_errors, "_read_bounded_line", fake_read)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(b"")))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=out_buf))

    forwarded: list[Any] = []
    with anyio.fail_after(5):
        async with stdio_errors.stdio_server_with_parse_replies() as (read_stream, write_stream):
            async for message in read_stream:
                forwarded.append(message)
            await write_stream.aclose()

    assert len(forwarded) == 1
    valid = json.loads(forwarded[0].message.model_dump_json())
    assert valid["id"] == 1
    assert valid["method"] == "ping"

    replies = [
        json.loads(line) for line in out_buf.getvalue().decode("utf-8").splitlines() if line.strip()
    ]
    assert [reply["id"] for reply in replies] == [2, 3]
    assert all(reply["error"]["code"] == -32600 for reply in replies)
    assert "exceeds" in replies[1]["error"]["message"]
