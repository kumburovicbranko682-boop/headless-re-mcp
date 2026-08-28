"""The production stdio transport must answer unreadable requests, not drop them.

``stdio_server_with_parse_replies`` is what ``server.py`` runs the whole MCP
server on, yet the coroutine itself had no test at all: measured 45% module
coverage with the entire context manager unexecuted. Writing the missing
end-to-end test surfaced a real defect: an oversized record is truncated at
the 8 MiB cap, so ``json.loads`` could never parse the fragment, ``_request_id``
always came back ``None``, and the "reply with the id" arm of the oversized
branch was dead code -- a caller that sent an 8 MiB tools/call got silence and
hung, the exact unattended failure this module exists to prevent. The fix
recovers the id with a bounded scan of the record's head; these tests pin the
whole contract: a valid line reaches the read stream untouched, an unparseable
or oversized line that names an id gets a JSON-RPC INVALID_REQUEST reply on
stdout, garbage without an id stays silent, ids that are bools or containers
are refused (a bool would round-trip as 0/1 and mis-correlate), and pydantic's
multi-line recursion wall of text is swapped for one calm sentence.
"""

from __future__ import annotations

import json
import sys
from io import BytesIO
from types import SimpleNamespace

import pytest
from mcp.types import JSONRPCError, JSONRPCRequest

from headless_re_mcp.mcp.stdio_errors import (
    _error_for_parse_failure,
    _read_bounded_line,
    _request_id,
    _request_id_from_fragment,
    stdio_server_with_parse_replies,
)


class _CapturedStdout(BytesIO):
    """The transport wraps stdout in a TextIOWrapper, and dropping that wrapper
    closes the underlying buffer; ignoring close() keeps the capture readable."""

    def close(self) -> None:
        pass


def _wire_stdio(monkeypatch: pytest.MonkeyPatch, stdin_payload: bytes) -> _CapturedStdout:
    fake_stdout = _CapturedStdout()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=BytesIO(stdin_payload)))
    monkeypatch.setattr(sys, "stdout", SimpleNamespace(buffer=fake_stdout))
    return fake_stdout


def _replies(fake_stdout: _CapturedStdout) -> list[dict[str, object]]:
    return [json.loads(line) for line in fake_stdout.getvalue().decode().splitlines() if line]


# ---- end-to-end transport ----------------------------------------------------


@pytest.mark.asyncio
async def test_transport_answers_bad_requests_and_passes_good_ones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One valid, one broken-with-id, one broken-without-id line over stdio.

    The valid request must arrive on the read stream exactly as sent; the
    broken request that still has an id must produce a JSON-RPC error on
    stdout (the whole point of this transport over the SDK's, which logs and
    stays silent); the id-less garbage must produce nothing.
    """
    valid = '{"jsonrpc":"2.0","id":1,"method":"ping"}'
    broken_with_id = '{"jsonrpc":"2.0","id":2}'  # neither request nor response
    broken_no_id = "{this is not json"
    payload = "\n".join([valid, broken_with_id, broken_no_id]) + "\n"
    fake_stdout = _wire_stdio(monkeypatch, payload.encode())

    received = []
    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        # The test plays the server side but sends nothing back; closing our
        # write handle lets the stdout task finish once stdin hits EOF.
        await write_stream.aclose()
        async for session_message in read_stream:
            received.append(session_message)

    assert len(received) == 1
    request = received[0].message.root
    assert isinstance(request, JSONRPCRequest)
    assert request.method == "ping"
    assert request.id == 1

    replies = _replies(fake_stdout)
    assert len(replies) == 1, "exactly one reply: the broken request that had an id"
    assert replies[0]["id"] == 2
    assert replies[0]["error"]["code"] == -32600  # type: ignore[index]


@pytest.mark.asyncio
async def test_transport_answers_an_oversized_request_that_names_an_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A record past the 8 MiB cap is drained, refused by id, and the next
    request on the wire is still served -- the flood cannot wedge the reader.

    Before the fragment-id fix this produced no reply at all: the truncated
    record never parsed, so the refusal had no id to ride on and the caller
    hung waiting for a response that would never come.
    """
    oversized = '{"jsonrpc":"2.0","id":"big","params":"' + "A" * (8 * 1024 * 1024) + '"}'
    valid = '{"jsonrpc":"2.0","id":4,"method":"ping"}'
    fake_stdout = _wire_stdio(monkeypatch, f"{oversized}\n{valid}\n".encode())

    received = []
    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        await write_stream.aclose()
        async for session_message in read_stream:
            received.append(session_message)

    assert len(received) == 1
    request = received[0].message.root
    assert isinstance(request, JSONRPCRequest)
    assert request.id == 4

    replies = _replies(fake_stdout)
    assert len(replies) == 1
    assert replies[0]["id"] == "big"
    error = replies[0]["error"]
    assert error["code"] == -32600  # type: ignore[index]
    assert "exceeds" in error["message"]  # type: ignore[index]


@pytest.mark.asyncio
async def test_transport_forwards_server_replies_to_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What the server sends on the write stream must land on stdout as NDJSON."""
    from mcp.shared.message import SessionMessage
    from mcp.types import JSONRPCMessage

    fake_stdout = _wire_stdio(monkeypatch, b"")

    reply = JSONRPCMessage.model_validate({"jsonrpc": "2.0", "id": 9, "result": {"ok": True}})
    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        async with write_stream:
            await write_stream.send(SessionMessage(reply))
        async for _message in read_stream:  # pragma: no cover - stdin is empty
            raise AssertionError("empty stdin must deliver no messages")

    assert _replies(fake_stdout) == [{"jsonrpc": "2.0", "id": 9, "result": {"ok": True}}]


# ---- bounded reader ------------------------------------------------------------


@pytest.mark.asyncio
async def test_bounded_reader_reports_eof_as_empty_not_oversized() -> None:
    """EOF must read as (b"", False): reporting it oversized would make the
    reader synthesize an error reply for a connection that simply closed."""
    line, oversized = await _read_bounded_line(BytesIO(b""))
    assert line == b""
    assert oversized is False


# ---- id extraction -------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "[1, 2, 3]",  # parses, but not an object
        '"just a string"',
        '{"jsonrpc": "2.0", "method": "ping"}',  # object without an id
        '{"id": true}',  # bool would round-trip as 1 and mis-correlate
        '{"id": [5]}',  # containers are not JSON-RPC ids
        '{"id": 1.5}',  # floats are not str|int
    ],
)
def test_lines_without_a_usable_id_get_no_reply(line: str) -> None:
    assert _request_id(line) is None
    assert _error_for_parse_failure(line, ValueError("broken")) is None


def test_string_and_int_ids_are_extracted() -> None:
    assert _request_id('{"id": 7}') == 7
    assert _request_id('{"id": "abc"}') == "abc"
    assert _request_id('{"id": 0}') == 0  # falsy but valid


def test_fragment_ids_are_only_used_for_oversized_records() -> None:
    """Ordinary parse failures keep the strict extractor: a fragment match on
    complete-but-invalid JSON must not start answering garbage it never did."""
    truncated = '{"jsonrpc":"2.0","id":42,"params":"' + "A" * 64  # no closing quote
    assert _request_id(truncated) is None
    assert _error_for_parse_failure(truncated, ValueError("x")) is None
    reply = _error_for_parse_failure(truncated, ValueError("x"), allow_fragment_id=True)
    assert reply is not None
    error = reply.root
    assert isinstance(error, JSONRPCError)
    assert error.id == 42


def test_fragment_scan_recovers_string_ids_with_escapes() -> None:
    assert _request_id_from_fragment('{"id":"a\\"b","params":"' + "A" * 64) == 'a"b'


def test_fragment_scan_refuses_ids_with_invalid_escapes() -> None:
    """The regex tolerates any backslash pair, but JSON does not; a \\x escape
    must fail the decode quietly instead of raising out of the reader."""
    assert _request_id_from_fragment('{"id":"a\\xb","params":"' + "A" * 64) is None


def test_fragment_scan_stays_silent_without_an_id_in_the_head() -> None:
    assert _request_id_from_fragment('{"params":"' + "A" * 8192 + '","id":7}') is None
    assert _request_id_from_fragment("A" * 64) is None


# ---- parse-failure message shaping ----------------------------------------------


def test_recursion_failures_get_one_calm_sentence() -> None:
    reply = _error_for_parse_failure(
        '{"id": 3}', ValueError("recursion limit exceeded at depth 200")
    )
    assert reply is not None
    error = reply.root
    assert isinstance(error, JSONRPCError)
    assert error.id == 3
    assert error.error.message == "request is nested too deeply to parse"


def test_ordinary_failures_keep_only_the_first_line_capped() -> None:
    """A pydantic ValidationError spans many lines and can quote the hostile
    input; only the first line, capped at 2048 chars, may reach the reply."""
    exc = ValueError(("F" * 5000) + "\nsecond line quoting the whole payload")
    reply = _error_for_parse_failure('{"id": "req-1"}', exc)
    assert reply is not None
    error = reply.root
    assert isinstance(error, JSONRPCError)
    assert error.id == "req-1"
    assert error.error.message == "F" * 2048
    assert "\n" not in error.error.message
