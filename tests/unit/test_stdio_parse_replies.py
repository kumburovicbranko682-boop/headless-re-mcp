"""Coverage for the stdio parse-reply shim in ``mcp/stdio_errors``.

``test_mcp_server.py`` pins the pure helpers (``error_message_for_unreadable_line``
for a nested request, a valid line, and id-less garbage; ``_read_bounded_line``
draining an oversized record). What was left uncovered is the whole
``stdio_server_with_parse_replies`` context manager -- the reader/writer tasks
that turn an unreadable-but-identified request into a JSON-RPC error on the
write stream while still forwarding good messages -- plus a few guard arcs in
``_read_bounded_line``, ``_request_id`` and ``_error_for_parse_failure``. These
drive the context manager over fake stdio and hit those guards directly.
"""

from __future__ import annotations

import json
import types
from io import BytesIO, TextIOWrapper
from typing import Any

import anyio
import pytest

import headless_re_mcp.mcp.stdio_errors as stdio_errors


class _KeepOpenBytesIO(BytesIO):
    """A stdout sink that survives the wrapper closing it.

    ``stdio_server_with_parse_replies`` wraps ``sys.stdout.buffer`` in a
    ``TextIOWrapper``; when that wrapper is torn down it closes the underlying
    buffer, which would empty a plain ``BytesIO`` before the test could read the
    replies. Swallowing ``close`` keeps the written bytes inspectable.
    """

    def close(self) -> None:
        pass


@pytest.mark.asyncio
async def test_read_bounded_line_returns_empty_at_eof() -> None:
    """An exhausted stream yields the empty sentinel, not an oversized flag."""
    line, oversized = await stdio_errors._read_bounded_line(BytesIO(b""), limit=64)
    assert line == b""
    assert oversized is False


def test_valid_json_without_an_id_stays_silent() -> None:
    """A JSON value the SDK rejects but which carries no id gets no reply.

    ``[1,2,3]`` parses (so ``_request_id`` reaches the shape check) yet is not a
    request object, so there is no id to answer and the shim stays silent.
    """
    assert stdio_errors.error_message_for_unreadable_line("[1,2,3]") is None


def test_request_with_a_boolean_id_is_not_answered() -> None:
    """``true`` is a JSON id the SDK forbids; JSON-RPC ids are string or number.

    ``json`` would hand back Python ``True``, and ``isinstance(True, int)`` is
    itself true, so the bool guard is what keeps a nonsense id from being echoed
    back in an error.
    """
    line = '{"jsonrpc":"2.0","id":true,"method":123}'
    assert stdio_errors.error_message_for_unreadable_line(line) is None


def test_a_plain_parse_error_reply_uses_the_first_line_of_the_message() -> None:
    """A non-recursion failure keeps the id and the first line of the reason.

    ``{"jsonrpc":"2.0","id":9}`` is neither request, response nor error, so the
    SDK union rejects it, but it still names id 9. The reply must carry that id
    and an INVALID_REQUEST code without the recursion rewrite.
    """
    line = '{"jsonrpc":"2.0","id":9}'
    reply = stdio_errors.error_message_for_unreadable_line(line)
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 9
    assert dumped["error"]["code"] == -32600
    assert "nested too deeply" not in dumped["error"]["message"]


@pytest.mark.asyncio
async def test_stdio_server_answers_unreadable_requests_and_forwards_valid_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The context manager is the unattended path the SDK reader never covered.

    A valid ping must arrive on the read stream, while an oversized record and a
    schema-invalid record -- both carrying an id -- must come back as JSON-RPC
    errors on stdout. Garbage without an id stays silent. A small byte cap makes
    the oversized branch cheap to exercise; the oversized record pads with spaces
    so its truncated prefix still parses to an id and is actually answered.
    """
    valid = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    oversized = b'{"jsonrpc":"2.0","id":3,"method":"ping"}' + b" " * 40 + b"\n"
    # Oversized but whose truncated prefix does not parse to an id, so it has to
    # be dropped silently rather than answered.
    oversized_no_id = b"x" * 100 + b"\n"
    bad_with_id = b'{"jsonrpc":"2.0","id":4,"method":[1,2,3]}\n'
    bad_without_id = b'{"method":"noid"}\n'
    stdin_bytes = valid + oversized + oversized_no_id + bad_with_id + bad_without_id

    stdout_buffer = _KeepOpenBytesIO()
    monkeypatch.setattr(
        "sys.stdin", types.SimpleNamespace(buffer=BytesIO(stdin_bytes)), raising=False
    )
    monkeypatch.setattr(
        "sys.stdout", types.SimpleNamespace(buffer=stdout_buffer), raising=False
    )

    real_read = stdio_errors._read_bounded_line

    async def small_cap(stream: Any, *, limit: int = 64) -> tuple[bytes, bool]:
        return await real_read(stream, limit=64)

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", small_cap)
    monkeypatch.setattr(stdio_errors, "_MAX_STDIO_MESSAGE_BYTES", 64)

    received: list[Any] = []
    async with stdio_errors.stdio_server_with_parse_replies() as (
        read_stream,
        write_stream,
    ):
        async with read_stream:
            async for message in read_stream:
                received.append(message)
        await write_stream.aclose()

    assert len(received) == 1
    forwarded = json.loads(received[0].message.model_dump_json())
    assert forwarded["id"] == 1
    assert forwarded["method"] == "ping"

    replies = [
        json.loads(entry)
        for entry in TextIOWrapper(BytesIO(stdout_buffer.getvalue()), encoding="utf-8")
        if entry.strip()
    ]
    answered = {reply["id"]: reply for reply in replies}
    assert set(answered) == {3, 4}
    assert answered[3]["error"]["code"] == -32600
    assert answered[4]["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_stdin_reader_swallows_a_closed_stream_during_teardown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stream closed under the reader is shutdown, not an error to surface.

    When the surrounding task group is torn down the read side can be closed
    while the reader is mid-record; the SDK pattern swallows that
    ``ClosedResourceError`` and checkpoints instead of crashing the group. A
    read helper that raises it stands in for that race.
    """
    async def closed_read(stream: Any, *, limit: int = 64) -> tuple[bytes, bool]:
        raise anyio.ClosedResourceError

    monkeypatch.setattr(stdio_errors, "_read_bounded_line", closed_read)
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(buffer=BytesIO()), raising=False)
    monkeypatch.setattr(
        "sys.stdout", types.SimpleNamespace(buffer=_KeepOpenBytesIO()), raising=False
    )

    received: list[Any] = []
    async with stdio_errors.stdio_server_with_parse_replies() as (
        read_stream,
        write_stream,
    ):
        async with read_stream:
            async for message in read_stream:
                received.append(message)
        await write_stream.aclose()

    assert received == []


@pytest.mark.asyncio
async def test_stdout_writer_swallows_a_closed_stream_during_teardown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stdout closed mid-reply is teardown, so the writer exits quietly.

    The writer wraps its drain loop the same way the reader does. Feeding one
    unreadable-but-identified request produces a reply the writer tries to emit;
    a stdout whose write raises ``ClosedResourceError`` makes the writer take its
    swallow-and-checkpoint arc rather than escaping the task group.
    """
    class _RaiseOnWrite(BytesIO):
        def write(self, data: Any) -> int:
            raise anyio.ClosedResourceError

    monkeypatch.setattr(
        "sys.stdin",
        types.SimpleNamespace(buffer=BytesIO(b'{"jsonrpc":"2.0","id":8,"method":[1]}\n')),
        raising=False,
    )
    monkeypatch.setattr(
        "sys.stdout", types.SimpleNamespace(buffer=_RaiseOnWrite()), raising=False
    )

    received: list[Any] = []
    async with stdio_errors.stdio_server_with_parse_replies() as (
        read_stream,
        write_stream,
    ):
        async with read_stream:
            async for message in read_stream:
                received.append(message)
        await write_stream.aclose()

    assert received == []
