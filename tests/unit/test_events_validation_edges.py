"""Validation branches of the debug-event protocol not hit by test_events.py.

The main suite drives whole consistent batches and single-field corruption,
which leaves a handful of guards unexercised: a non-object batch, a cursor
that runs ahead of latest_sequence, a batch whose count does not match the
sequence window it should contain, a non-object event element, and the
per-field type/range checks in _parse_event_data (an out-of-range integer, an
over-long or non-string text field, and the valid-boolean path). These pin
each one directly.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.core.events import (
    DEBUG_EVENT_CAPACITY,
    DebugEventProtocolError,
    _parse_event,
    parse_debug_event_batch,
)

JsonObject = dict[str, Any]


def _event(sequence: int, kind: str = "debug.paused", data: JsonObject | None = None) -> JsonObject:
    return {
        "sequence": sequence,
        "timestamp_unix_ms": 1_700_000_000_000 + sequence,
        "source": "x64dbg.plugin_callback",
        "kind": kind,
        "data": data or {},
    }


def _parse(payload: object, *, cursor: int = 0, limit: int = 10) -> Any:
    return parse_debug_event_batch(payload, requested_cursor=cursor, requested_limit=limit)


# --------------------------------------------------------------------------- #
# parse_debug_event_batch structural guards                                   #
# --------------------------------------------------------------------------- #
def test_a_non_object_batch_is_rejected() -> None:
    with pytest.raises(DebugEventProtocolError, match="must be an object"):
        _parse(["not", "a", "batch"])


def test_a_cursor_ahead_of_latest_is_rejected() -> None:
    """cursor may equal the request yet still point past the newest sequence."""
    payload = {
        "events": [],
        "count": 0,
        "cursor": 5,
        "next_cursor": 5,
        "oldest_sequence": 1,
        "latest_sequence": 3,
        "dropped": 0,
        "dropped_total": 0,
        "has_more": False,
        "capacity": DEBUG_EVENT_CAPACITY,
    }
    with pytest.raises(DebugEventProtocolError, match="ahead of latest_sequence"):
        _parse(payload, cursor=5)


def test_a_batch_short_of_its_sequence_window_is_rejected() -> None:
    """Every prior invariant holds, but two events cannot be the whole 1..5 window."""
    payload = {
        "events": [_event(1), _event(2)],
        "count": 2,
        "cursor": 0,
        "next_cursor": 2,
        "oldest_sequence": 1,
        "latest_sequence": 5,
        "dropped": 0,
        "dropped_total": 0,
        "has_more": True,
        "capacity": DEBUG_EVENT_CAPACITY,
    }
    with pytest.raises(DebugEventProtocolError, match="expected sequence window"):
        _parse(payload, cursor=0, limit=5)


def test_a_non_object_event_element_is_rejected() -> None:
    payload = {
        "events": ["not-an-event"],
        "count": 1,
        "cursor": 0,
        "next_cursor": 1,
        "oldest_sequence": 1,
        "latest_sequence": 1,
        "dropped": 0,
        "dropped_total": 0,
        "has_more": False,
        "capacity": DEBUG_EVENT_CAPACITY,
    }
    with pytest.raises(DebugEventProtocolError, match="event must be an object"):
        _parse(payload, cursor=0, limit=1)


# --------------------------------------------------------------------------- #
# _parse_event_data per-field validation                                      #
# --------------------------------------------------------------------------- #
def test_an_out_of_range_integer_field_is_rejected() -> None:
    with pytest.raises(DebugEventProtocolError, match="exit_code must be"):
        _parse_event(_event(1, "process.exited", {"exit_code": -1}))


@pytest.mark.parametrize("bad_name", ["a" * 600, 123, b"bytes"])
def test_an_invalid_text_field_is_rejected(bad_name: object) -> None:
    with pytest.raises(DebugEventProtocolError, match="name is invalid"):
        _parse_event(_event(1, "module.loaded", {"base": 0x1000, "size": 0x2000, "name": bad_name}))


def test_a_valid_boolean_field_is_accepted() -> None:
    event = _parse_event(
        _event(1, "exception", {"code": 5, "address": 0x401000, "first_chance": True})
    )
    assert event.data["first_chance"] is True
    assert event.kind == "exception"


def test_a_non_boolean_boolean_field_is_rejected() -> None:
    with pytest.raises(DebugEventProtocolError, match="first_chance must be a boolean"):
        _parse_event(
            _event(1, "exception", {"code": 5, "address": 0x401000, "first_chance": "yes"})
        )
