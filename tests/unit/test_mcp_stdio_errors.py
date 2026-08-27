"""The stdio parse-reply shim: a bad request with an id gets an answer, not silence.

``mcp/stdio_errors.py`` exists for one measured failure: the SDK's stdio reader
forwards an unparseable request inward, the server logs "Internal Server Error"
and never writes a JSON-RPC response, so a caller waits forever for a reply that
correlates to its request id. The shim parses the id out with ``json.loads``
(which tolerates deeper nesting than pydantic's validator) and answers with a
JSON-RPC error carrying that id, while staying silent for genuine garbage that
has no id to answer.

This module had no dedicated test: the whole ``_error_for_parse_failure``
non-recursion arm (line 150 -- the common malformed-but-id-bearing request, the
module's entire reason for existing), the ``_request_id`` reject branches, and
the empty/oversized paths of ``_read_bounded_line`` were unexercised. These pin
the observable contract so a later edit cannot quietly turn a refusal back into
the silent hang the shim was written to remove.
"""

from __future__ import annotations

import io

import anyio
import pytest
from mcp.types import INVALID_REQUEST, JSONRPCError

from headless_re_mcp.mcp.stdio_errors import (
    _MAX_STDIO_MESSAGE_BYTES,
    _read_bounded_line,
    _request_id,
    error_message_for_unreadable_line,
)


def _error(line: str) -> JSONRPCError:
    """Assert the shim answered ``line`` and return the JSON-RPC error body."""
    message = error_message_for_unreadable_line(line)
    assert message is not None, "a request with an id must be answered, not dropped"
    body = message.root
    assert isinstance(body, JSONRPCError)
    return body


# --- error_message_for_unreadable_line ----------------------------------------


def test_a_well_formed_request_is_not_answered_with_an_error() -> None:
    # Valid JSON-RPC parses cleanly, so there is nothing for the shim to answer;
    # returning None hands the message on to the real SDK path untouched.
    good = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
    assert error_message_for_unreadable_line(good) is None


def test_complete_garbage_without_an_id_stays_silent() -> None:
    # No id means no reply can be correlated, so the shim stays silent exactly
    # as an ordinary parse of garbage already did -- answering would invent a
    # response the caller cannot match to any request.
    assert error_message_for_unreadable_line("not json at all") is None
    assert error_message_for_unreadable_line('{"method":"x"}') is None


def test_a_malformed_request_with_an_id_is_answered_with_that_id() -> None:
    # method is the wrong type: valid JSON (so json.loads yields the id) but
    # invalid JSON-RPC (so pydantic rejects it). This is the module's core case
    # and the previously uncovered non-recursion arm of _error_for_parse_failure.
    body = _error('{"jsonrpc":"2.0","id":7,"method":123}')

    assert body.id == 7
    assert body.error.code == INVALID_REQUEST
    # The message is the first line of the validation error, never empty and
    # never multi-line, and bounded so a huge error cannot bloat the reply.
    assert body.error.message
    assert "\n" not in body.error.message
    assert len(body.error.message) <= 2048


def test_a_string_id_is_preserved_on_the_error_reply() -> None:
    body = _error('{"jsonrpc":"2.0","id":"req-abc","method":42}')
    assert body.id == "req-abc"


def test_a_request_nested_too_deeply_is_answered_with_its_id() -> None:
    # pydantic's JSON parser gives up around 200 levels while json.loads goes
    # deeper, so the shim can still recover the id and name the real reason.
    # This is the exact scenario the module's header docstring measured.
    depth = 260
    line = (
        '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":'
        + "[" * depth
        + "]" * depth
        + "}"
    )
    body = _error(line)

    assert body.id == 9
    assert body.error.code == INVALID_REQUEST
    assert body.error.message == "request is nested too deeply to parse"


# --- _request_id branches -----------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "not json at all",  # json.loads raises -> None
        "[1, 2, 3]",  # valid JSON but not an object -> None
        '{"method":"x"}',  # object with no id -> None
        '{"id":true}',  # a bool is not a usable id (and bool is an int subclass)
        '{"id":false}',
        '{"id":1.5}',  # a float is not a str/int id
        '{"id":null}',
        '{"id":[1]}',  # containers are not ids
    ],
)
def test_request_id_rejects_everything_that_cannot_correlate_a_reply(line: str) -> None:
    assert _request_id(line) is None


def test_request_id_accepts_string_and_integer_ids() -> None:
    assert _request_id('{"id":"abc"}') == "abc"
    assert _request_id('{"id":42}') == 42
    assert _request_id('{"id":0}') == 0


# --- _read_bounded_line -------------------------------------------------------


def _read_once(data: bytes, *, limit: int) -> tuple[bytes, bool]:
    async def go() -> tuple[bytes, bool]:
        return await _read_bounded_line(io.BytesIO(data), limit=limit)

    return anyio.run(go)


def test_a_line_within_the_cap_is_returned_whole_and_not_flagged() -> None:
    assert _read_once(b'{"a":1}\n', limit=100) == (b'{"a":1}\n', False)


def test_an_empty_stream_reports_end_without_flagging_it_oversized() -> None:
    assert _read_once(b"", limit=100) == (b"", False)


def test_an_oversized_line_is_flagged_and_the_rest_of_it_is_drained() -> None:
    # The first record blows the cap; the reader must report it oversized *and*
    # consume the remainder so the next readline resyncs to the following record
    # instead of parsing its tail as a fresh (and also broken) message.
    async def go() -> tuple[bytes, bool, bytes]:
        stream = io.BytesIO(b"x" * 50 + b"\n" + b"next\n")
        prefix, oversized = await _read_bounded_line(stream, limit=10)
        return prefix, oversized, stream.readline()

    prefix, oversized, remainder = anyio.run(go)

    assert oversized is True
    assert len(prefix) == 11  # cap + 1: enough to know it overflowed
    assert remainder == b"next\n"  # the drain landed exactly on the next record


def test_an_oversized_line_that_never_terminates_still_returns() -> None:
    # A giant record with no trailing newline at EOF must not spin forever
    # draining: the drain loop stops on the empty read.
    prefix, oversized = _read_once(b"x" * 50, limit=10)
    assert oversized is True
    assert prefix == b"x" * 11


def test_the_default_cap_is_the_documented_eight_mebibytes() -> None:
    assert _MAX_STDIO_MESSAGE_BYTES == 8 * 1024 * 1024
