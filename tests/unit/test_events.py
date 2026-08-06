from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core.events import (
    DEBUG_EVENT_CAPACITY,
    MAX_DEBUG_EVENT_BATCH,
    DebugEventCursor,
    DebugEventProtocolError,
    parse_debug_event_batch,
)

JsonObject = dict[str, Any]
_MAX_JSON_INTEGER = (1 << 63) - 1


def _event(
    sequence: int,
    kind: str = "debug.paused",
    data: JsonObject | None = None,
) -> JsonObject:
    return {
        "sequence": sequence,
        "timestamp_unix_ms": 1_700_000_000_000 + sequence,
        "source": "x64dbg.plugin_callback",
        "kind": kind,
        "data": data or {},
    }


def _batch(
    *,
    cursor: int = 0,
    latest: int = 2,
    events: list[JsonObject] | None = None,
    capacity: int = DEBUG_EVENT_CAPACITY,
) -> JsonObject:
    oldest = 0 if latest == 0 else max(1, latest - capacity + 1)
    dropped = max(0, oldest - cursor - 1) if oldest else 0
    if events is None:
        first_sequence = max(cursor + 1, oldest) if oldest else 1
        events = [_event(sequence) for sequence in range(first_sequence, latest + 1)]
    next_cursor = int(events[-1]["sequence"]) if events else cursor + dropped
    return {
        "events": events,
        "count": len(events),
        "cursor": cursor,
        "next_cursor": next_cursor,
        "oldest_sequence": oldest,
        "latest_sequence": latest,
        "dropped": dropped,
        "dropped_total": max(0, latest - capacity),
        "has_more": next_cursor < latest,
        "capacity": capacity,
    }


def _parse(
    payload: object,
    *,
    cursor: int = 0,
    limit: int = MAX_DEBUG_EVENT_BATCH,
):
    return parse_debug_event_batch(
        payload,
        requested_cursor=cursor,
        requested_limit=limit,
    )


def test_parse_event_batch_and_advance_cursor() -> None:
    payload = _batch(
        events=[
            _event(
                1,
                "process.created",
                {
                    "process_id": 71,
                    "thread_id": 72,
                    "image_base": 0x140000000,
                    "start_address": 0x140001000,
                    "path": "fixture.exe",
                },
            ),
            _event(2, "debug.paused"),
        ]
    )
    batch = _parse(payload)
    cursor = DebugEventCursor()

    cursor.advance(batch)

    assert cursor.value == 2
    assert [event.sequence for event in batch.events] == [1, 2]
    assert batch.events[0].data["process_id"] == 71
    assert batch.to_dict()["count"] == 2


def test_parse_empty_initial_batch() -> None:
    batch = _parse(_batch(latest=0, events=[]))

    assert batch.events == ()
    assert batch.next_cursor == 0
    assert batch.oldest_sequence == 0
    assert batch.has_more is False


def test_parse_overwritten_window_reports_exact_loss() -> None:
    latest = DEBUG_EVENT_CAPACITY + 2
    payload = _batch(
        cursor=0,
        latest=latest,
        events=[_event(3), _event(4)],
    )
    batch = _parse(payload, limit=2)

    assert batch.oldest_sequence == 3
    assert batch.dropped == 2
    assert batch.dropped_total == 2
    assert batch.next_cursor == 4
    assert batch.has_more is True


def test_parse_truncated_text_marker() -> None:
    batch = _parse(
        _batch(
            latest=1,
            events=[
                _event(
                    1,
                    "module.loaded",
                    {"base": 0x1000, "size": 0x2000, "name": "a.dll", "name_truncated": True},
                )
            ],
        )
    )

    assert batch.events[0].data["name_truncated"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cursor", 1),
        ("count", 1),
        ("next_cursor", 1),
        ("oldest_sequence", 0),
        ("dropped", 1),
        ("dropped_total", 1),
        ("has_more", True),
        ("capacity", DEBUG_EVENT_CAPACITY + 1),
    ],
)
def test_inconsistent_batch_is_rejected(field: str, value: object) -> None:
    payload = _batch()
    payload[field] = value

    with pytest.raises(DebugEventProtocolError):
        _parse(payload)


@pytest.mark.parametrize(
    "field",
    [
        "events",
        "count",
        "cursor",
        "next_cursor",
        "oldest_sequence",
        "latest_sequence",
        "dropped",
        "dropped_total",
        "has_more",
        "capacity",
    ],
)
def test_missing_batch_field_is_rejected(field: str) -> None:
    payload = _batch()
    del payload[field]

    with pytest.raises(DebugEventProtocolError):
        _parse(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("count", True),
        ("cursor", -1),
        ("next_cursor", _MAX_JSON_INTEGER + 1),
        ("oldest_sequence", "1"),
        ("latest_sequence", None),
        ("dropped", -1),
        ("dropped_total", 1.0),
        ("has_more", 0),
        ("capacity", 0),
    ],
)
def test_malformed_batch_field_type_or_range_is_rejected(
    field: str,
    value: object,
) -> None:
    payload = _batch()
    payload[field] = value

    with pytest.raises(DebugEventProtocolError):
        _parse(payload)


def test_event_sequence_source_kind_and_data_are_defensive() -> None:
    invalid_events = [
        [_event(1), _event(1)],
        [{**_event(1), "source": "derived.state"}, _event(2)],
        [{**_event(1), "kind": "arbitrary.command"}, _event(2)],
        [{**_event(1), "data": []}, _event(2)],
        [_event(1, "debug.paused", {"unexpected": 1}), _event(2)],
        [_event(1, "exception", {"first_chance": 1}), _event(2)],
        [{**_event(1), "timestamp_unix_ms": 0}, _event(2)],
    ]

    for events in invalid_events:
        with pytest.raises(DebugEventProtocolError):
            _parse(_batch(events=deepcopy(events)))


def test_truncation_marker_requires_present_text() -> None:
    payload = _batch(
        latest=1,
        events=[_event(1, "module.loaded", {"name_truncated": True})],
    )

    with pytest.raises(DebugEventProtocolError):
        _parse(payload)


@pytest.mark.parametrize(
    ("cursor", "limit"),
    [
        (True, 1),
        (-1, 1),
        (_MAX_JSON_INTEGER + 1, 1),
        (0, False),
        (0, 0),
        (0, MAX_DEBUG_EVENT_BATCH + 1),
    ],
)
def test_invalid_requested_bounds_are_rejected(cursor: object, limit: object) -> None:
    with pytest.raises(ValueError):
        parse_debug_event_batch(
            _batch(latest=0, events=[]),
            requested_cursor=cursor,  # type: ignore[arg-type]
            requested_limit=limit,  # type: ignore[arg-type]
        )


def test_cursor_refuses_batch_from_another_stream_position() -> None:
    cursor = DebugEventCursor(value=8)
    batch = _parse(_batch())

    with pytest.raises(DebugEventProtocolError, match="does not match"):
        cursor.advance(batch)


def test_persistent_log_replays_after_consumer_lag(tmp_path: Path) -> None:
    from headless_re_mcp.core.event_log import PersistentDebugEventLog
    from headless_re_mcp.core.events import DebugEvent

    log = PersistentDebugEventLog(tmp_path / "events.sqlite3")
    events = tuple(
        DebugEvent(
            sequence=i,
            timestamp_unix_ms=1_700_000_000_000 + i,
            source="x64dbg.plugin_callback",
            kind="debug.paused",
            data={},
        )
        for i in range(1, 6)
    )
    log.append_events(events)

    first = log.read_after(0, limit=2)
    assert [event.sequence for event in first.batch.events] == [1, 2]
    assert first.batch.dropped == 0

    # Consumer lagged; store still has 3..5 for true replay.
    second = log.read_after(2, limit=10)
    assert [event.sequence for event in second.batch.events] == [3, 4, 5]
    assert second.batch.dropped == 0
    assert second.unrecovered_gap is False
    log.close()


def test_persistent_log_reports_unrecovered_gap(tmp_path: Path) -> None:
    from headless_re_mcp.core.event_log import PersistentDebugEventLog
    from headless_re_mcp.core.events import DebugEvent

    log = PersistentDebugEventLog(tmp_path / "events.sqlite3")
    log.note_unrecovered_gap(1, 2)
    log.append_events(
        [
            DebugEvent(
                sequence=3,
                timestamp_unix_ms=1,
                source="x64dbg.plugin_callback",
                kind="debug.paused",
                data={},
            )
        ]
    )
    served = log.read_after(0, limit=10)
    assert served.batch.dropped == 2
    assert served.unrecovered_gap is True
    assert [event.sequence for event in served.batch.events] == [3]
    log.close()


def test_drain_copies_native_batch_into_log_before_ring_loss() -> None:
    from headless_re_mcp.core.event_drain import drain_native_into_log
    from headless_re_mcp.core.event_log import PersistentDebugEventLog
    from headless_re_mcp.core.events import DebugEvent, DebugEventBatch, DebugEventCursor

    class _FakeNative:
        def __init__(self) -> None:
            self.calls: list[int] = []

        def read_events(self, cursor: int, *, limit: int = 100, timeout: float = 10.0) -> DebugEventBatch:
            self.calls.append(cursor)
            if cursor >= 3:
                return DebugEventBatch(
                    events=(),
                    cursor=cursor,
                    next_cursor=cursor,
                    oldest_sequence=1,
                    latest_sequence=3,
                    dropped=0,
                    dropped_total=0,
                    has_more=False,
                    capacity=DEBUG_EVENT_CAPACITY,
                )
            events = tuple(
                DebugEvent(
                    sequence=i,
                    timestamp_unix_ms=i,
                    source="x64dbg.plugin_callback",
                    kind="debug.paused",
                    data={},
                )
                for i in range(cursor + 1, 4)
            )
            return DebugEventBatch(
                events=events[:limit],
                cursor=cursor,
                next_cursor=events[:limit][-1].sequence,
                oldest_sequence=1,
                latest_sequence=3,
                dropped=0,
                dropped_total=0,
                has_more=False,
                capacity=DEBUG_EVENT_CAPACITY,
            )

    log = PersistentDebugEventLog()
    drain = DebugEventCursor()
    native = _FakeNative()
    appended = drain_native_into_log(native, drain, log, timeout=0.05)
    assert appended == 3
    assert drain.value == 3
    served = log.read_after(0, limit=10)
    assert [event.sequence for event in served.batch.events] == [1, 2, 3]