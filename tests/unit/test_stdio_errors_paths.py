"""Cover the stdio parse-reply seams: request-id extraction, oversized and
malformed NDJSON handling, and the reader/writer task pair."""

from __future__ import annotations

from io import BytesIO
from typing import Any

import anyio
import pytest

import headless_re_mcp.mcp.stdio_errors as se


class _Uncloseable(BytesIO):
    """A BytesIO whose contents survive TextIOWrapper teardown."""

    def close(self) -> None:  # pragma: no cover - trivial override
        pass


def test_request_id_rejects_non_object_and_missing_id() -> None:
    assert se._request_id("[1, 2, 3]") is None
    assert se._request_id('{"method": "ping"}') is None


def test_request_id_rejects_bool_and_non_scalar_ids() -> None:
    assert se._request_id('{"id": true}') is None
    assert se._request_id('{"id": [1]}') is None


def test_request_id_accepts_string_and_integer_ids() -> None:
    assert se._request_id('{"id": 4}') == 4
    assert se._request_id('{"id": "abc"}') == "abc"


def test_parse_failure_without_an_id_stays_silent() -> None:
    assert se._error_for_parse_failure("{not-json", ValueError("boom")) is None


def test_unreadable_request_with_an_id_gets_a_trimmed_first_line() -> None:
    import json

    # Structurally valid JSON with an id, but not a valid JSON-RPC message.
    line = '{"jsonrpc":"2.0","id":5,"method":123}'
    reply = se.error_message_for_unreadable_line(line)
    assert reply is not None
    dumped = json.loads(reply.model_dump_json())
    assert dumped["id"] == 5
    assert dumped["error"]["code"] == -32600
    assert "nested too deeply" not in dumped["error"]["message"]


@pytest.mark.asyncio
async def test_read_bounded_line_reports_eof() -> None:
    line, oversized = await se._read_bounded_line(BytesIO(b""))
    assert line == b""
    assert oversized is False


@pytest.mark.asyncio
async def test_stdio_server_answers_bad_lines_and_forwards_good_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCMessage, JSONRPCResponse

    records: list[tuple[bytes, bool]] = [
        # Oversized but with an id -> an error reply is written.
        (b'{"jsonrpc":"2.0","id":10,"method":"ping"}', True),
        # Well-formed request -> forwarded to the read stream.
        (b'{"jsonrpc":"2.0","id":1,"method":"ping"}', False),
        # Valid JSON with an id but invalid JSON-RPC -> an error reply.
        (b'{"jsonrpc":"2.0","id":2,"method":123}', False),
        # EOF.
        (b"", False),
    ]
    pending = iter(records)

    async def fake_read(_stream: Any, **_kwargs: Any) -> tuple[bytes, bool]:
        return next(pending)

    monkeypatch.setattr(se, "_read_bounded_line", fake_read)

    captured = _Uncloseable()

    class _FakeStdin:
        buffer = BytesIO()

    class _FakeStdout:
        buffer = captured

    monkeypatch.setattr("sys.stdin", _FakeStdin())
    monkeypatch.setattr("sys.stdout", _FakeStdout())

    received_ids: list[Any] = []
    with anyio.fail_after(10):
        async with se.stdio_server_with_parse_replies() as (read, write):
            message = await read.receive()
            received_ids.append(message.message.root.id)
            outbound = JSONRPCMessage(
                JSONRPCResponse(jsonrpc="2.0", id=1, result={})
            )
            await write.send(SessionMessage(outbound))
            await write.aclose()

    payload = captured.getvalue().decode("utf-8")
    lines = [line for line in payload.splitlines() if line]

    assert received_ids == [1]
    # Two error replies (oversized id 10, malformed id 2) plus the response.
    ids = []
    import json

    for line in lines:
        ids.append(json.loads(line).get("id"))
    assert 10 in ids
    assert 2 in ids
    assert 1 in ids


def _install_fake_std(monkeypatch: pytest.MonkeyPatch) -> _Uncloseable:
    captured = _Uncloseable()

    class _FakeStdin:
        buffer = BytesIO()

    class _FakeStdout:
        buffer = captured

    monkeypatch.setattr("sys.stdin", _FakeStdin())
    monkeypatch.setattr("sys.stdout", _FakeStdout())
    return captured


@pytest.mark.asyncio
async def test_stdio_server_stays_silent_for_bad_lines_without_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records: list[tuple[bytes, bool]] = [
        (b'{"method":"ping"}', True),  # oversized but no id -> no reply
        (b"garbage", False),  # unparseable and no id -> no reply
        (b"", False),
    ]
    pending = iter(records)

    async def fake_read(_stream: Any, **_kwargs: Any) -> tuple[bytes, bool]:
        return next(pending)

    monkeypatch.setattr(se, "_read_bounded_line", fake_read)
    captured = _install_fake_std(monkeypatch)

    with anyio.fail_after(10):
        async with se.stdio_server_with_parse_replies() as (_read, write):
            await write.aclose()

    assert captured.getvalue() == b""


@pytest.mark.asyncio
async def test_stdin_reader_exits_quietly_when_its_stream_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp.shared.message as message_mod

    records: list[tuple[bytes, bool]] = [
        (b'{"jsonrpc":"2.0","id":9,"method":"ping"}', True),
        (b"", False),
    ]
    pending = iter(records)

    async def fake_read(_stream: Any, **_kwargs: Any) -> tuple[bytes, bool]:
        return next(pending)

    def _closed(*_args: Any, **_kwargs: Any) -> Any:
        raise anyio.ClosedResourceError

    monkeypatch.setattr(se, "_read_bounded_line", fake_read)
    monkeypatch.setattr(message_mod, "SessionMessage", _closed)
    _install_fake_std(monkeypatch)

    with anyio.fail_after(10):
        async with se.stdio_server_with_parse_replies() as (_read, write):
            await write.aclose()


@pytest.mark.asyncio
async def test_stdout_writer_exits_quietly_when_its_stream_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_read(_stream: Any, **_kwargs: Any) -> tuple[bytes, bool]:
        return b"", False

    monkeypatch.setattr(se, "_read_bounded_line", fake_read)
    _install_fake_std(monkeypatch)

    class _Boom:
        def model_dump_json(self, **_kwargs: Any) -> str:
            raise anyio.ClosedResourceError

    class _FakeSessionMessage:
        message = _Boom()

    with anyio.fail_after(10):
        async with se.stdio_server_with_parse_replies() as (_read, write):
            await write.send(_FakeSessionMessage())
            await write.aclose()
