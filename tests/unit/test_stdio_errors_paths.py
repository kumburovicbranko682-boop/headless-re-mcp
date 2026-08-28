"""Remaining branch coverage for the stdio parse-reply shim.

``test_stdio_errors.py`` drives the wrapper end to end for valid / invalid /
id-less lines. These pin the arms it does not reach: the oversized-request
reply and the two ``ClosedResourceError`` teardown handlers in the reader and
writer tasks.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO
from types import SimpleNamespace
from typing import Any

import anyio
import pytest

from headless_re_mcp.mcp import stdio_errors as adapter
from headless_re_mcp.mcp.stdio_errors import stdio_server_with_parse_replies

INVALID_REQUEST_CODE = -32600


class _CapturingBytesIO(BytesIO):
    """A stdout buffer that survives TextIOWrapper finalization (see test_stdio_errors)."""

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_wrapper_replies_to_an_oversized_request_with_an_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(b"")))
    stdout_buffer = _CapturingBytesIO()
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=stdout_buffer))

    calls = {"n": 0}

    async def fake_read_bounded(stream: Any, *, limit: int = 0) -> tuple[bytes, bool]:
        calls["n"] += 1
        if calls["n"] == 1:
            # An id-carrying prefix flagged oversized: the reader answers it
            # rather than forwarding a truncated body.
            return b'{"jsonrpc":"2.0","id":7,"method":"x"}', True
        if calls["n"] == 2:
            # Oversized but with no usable id: no reply is emitted (110->112).
            return b"oversized-garbage-without-id", True
        return b"", False

    monkeypatch.setattr(adapter, "_read_bounded_line", fake_read_bounded)

    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
            await write_stream.aclose()

    written = stdout_buffer.getvalue().decode("utf-8")
    replies = [json.loads(row) for row in written.splitlines() if row.strip()]
    assert len(replies) == 1
    assert replies[0]["id"] == 7
    assert replies[0]["error"]["code"] == INVALID_REQUEST_CODE
    assert "bytes" in replies[0]["error"]["message"]


@pytest.mark.asyncio
async def test_reader_task_tolerates_a_closed_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(b"")))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=_CapturingBytesIO()))

    async def closed(stream: Any, *, limit: int = 0) -> tuple[bytes, bool]:
        raise anyio.ClosedResourceError

    monkeypatch.setattr(adapter, "_read_bounded_line", closed)

    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
            await write_stream.aclose()
    # No assertion beyond a clean, non-raising teardown: the reader swallowed
    # the ClosedResourceError and checkpointed instead of propagating.


@pytest.mark.asyncio
async def test_writer_task_tolerates_a_closed_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # One invalid-with-id line produces a reply the writer will try to emit; the
    # wrapped stdout raises ClosedResourceError on write, which the writer
    # swallows via a checkpoint rather than propagating.
    invalid_with_id = b'{"jsonrpc":"2.0","id":42,"method":123}\n'
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(invalid_with_id)))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=_CapturingBytesIO()))

    class _ClosedStdout:
        async def write(self, _data: str) -> None:
            raise anyio.ClosedResourceError

        async def flush(self) -> None:
            return None

    monkeypatch.setattr(anyio, "wrap_file", lambda _f: _ClosedStdout())

    with anyio.fail_after(10):
        async with stdio_server_with_parse_replies() as (_read_stream, write_stream):
            await write_stream.aclose()
    # A clean teardown proves the writer caught the ClosedResourceError.
