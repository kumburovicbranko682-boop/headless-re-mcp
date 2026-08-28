"""Edge-path coverage for mcp/stdio_errors.py.

Targets the closure arms of ``stdio_server_with_parse_replies``: the oversized
NDJSON record that still carries a parseable id, and the ClosedResourceError
handlers in both the reader and the writer tasks.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from test_stdio_errors import _CapturingBytesIO

from headless_re_mcp.mcp.stdio_errors import (
    _MAX_STDIO_MESSAGE_BYTES,
    stdio_server_with_parse_replies,
)

INVALID_REQUEST_CODE = -32600


@pytest.mark.asyncio
async def test_an_oversized_request_with_an_id_is_refused_by_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A record past the byte cap gets a reply when its id fits in the prefix.

    The JSON document is complete early in the line and padded with trailing
    whitespace, so the truncated prefix still parses and yields the id.
    """
    padding = b" " * (_MAX_STDIO_MESSAGE_BYTES + 1024)
    oversized = b'{"jsonrpc":"2.0","id":7,"method":"x"}' + padding + b"\n"
    # Truncated mid-string: no id can be recovered, so no reply is owed.
    unaddressable = (
        b'{"jsonrpc":"2.0","id":8,"method":"'
        + b"y" * (_MAX_STDIO_MESSAGE_BYTES + 1024)
        + b'"}\n'
    )
    valid = b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(buffer=BytesIO(oversized + unaddressable + valid)),
    )
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    with anyio.fail_after(30):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            message = await read_stream.receive()
            forwarded = json.loads(message.message.model_dump_json())
            await write_stream.aclose()

    assert forwarded["id"] == 2, "the drain must not eat the next valid record"
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
async def test_the_reader_stops_quietly_when_its_stream_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ClosedResourceError while forwarding ends the reader, not the server."""

    class _ExplodingSessionMessage:
        def __init__(self, message: Any) -> None:
            raise anyio.ClosedResourceError

    monkeypatch.setattr("mcp.shared.message.SessionMessage", _ExplodingSessionMessage)
    valid = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(valid)))
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    with anyio.fail_after(30):
        async with stdio_server_with_parse_replies() as (read_stream, write_stream):
            with pytest.raises(anyio.EndOfStream):
                await read_stream.receive()
            await write_stream.aclose()

    assert stdout_buffer.getvalue() == b""


@pytest.mark.asyncio
async def test_the_writer_stops_quietly_when_its_stream_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ClosedResourceError while serializing ends the writer, not the server."""

    class _PoisonMessage:
        def model_dump_json(self, **kwargs: Any) -> str:
            raise anyio.ClosedResourceError

    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(b"")))
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    with anyio.fail_after(30):
        async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
            await write_stream.send(SimpleNamespace(message=_PoisonMessage()))
            await write_stream.aclose()

    assert stdout_buffer.getvalue() == b""
