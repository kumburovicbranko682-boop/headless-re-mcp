from __future__ import annotations

from dataclasses import dataclass
from typing import Any

JsonObject = dict[str, Any]
DEBUG_EVENT_CAPACITY = 1024
DEFAULT_DEBUG_EVENT_BATCH = 100
MAX_DEBUG_EVENT_BATCH = 256
_MAX_JSON_INTEGER = (1 << 63) - 1

_EVENT_INTEGER_FIELDS: dict[str, frozenset[str]] = {
    "debug.init": frozenset(),
    "debug.stopping": frozenset(),
    "debug.stopped": frozenset(),
    "process.created": frozenset(
        {"process_id", "thread_id", "image_base", "start_address"}
    ),
    "process.exited": frozenset({"exit_code"}),
    "thread.created": frozenset(
        {"thread_id", "start_address", "thread_local_base"}
    ),
    "thread.exited": frozenset({"thread_id", "exit_code"}),
    "module.loaded": frozenset({"base", "size"}),
    "module.unloaded": frozenset({"base"}),
    "breakpoint.hit": frozenset({"address", "type"}),
    "exception": frozenset({"code", "address"}),
    "debug.system_breakpoint": frozenset(),
    "debug.paused": frozenset(),
    "debug.resumed": frozenset(),
    "debug.stepped": frozenset(),
    "debug.attaching": frozenset({"process_id"}),
    "debug.detaching": frozenset({"process_id"}),
    "debug.unrecovered_gap": frozenset(),
}
_EVENT_TEXT_FIELDS: dict[str, frozenset[str]] = {
    "debug.init": frozenset({"path"}),
    "process.created": frozenset({"path"}),
    "module.loaded": frozenset({"name"}),
    "breakpoint.hit": frozenset({"name", "module"}),
}
_EVENT_BOOLEAN_FIELDS: dict[str, frozenset[str]] = {
    "exception": frozenset({"first_chance"}),
}


class DebugEventProtocolError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DebugEvent:
    sequence: int
    timestamp_unix_ms: int
    source: str
    kind: str
    data: JsonObject

    def to_dict(self) -> JsonObject:
        return {
            "sequence": self.sequence,
            "timestamp_unix_ms": self.timestamp_unix_ms,
            "source": self.source,
            "kind": self.kind,
            "data": dict(self.data),
        }


@dataclass(frozen=True, slots=True)
class DebugEventBatch:
    events: tuple[DebugEvent, ...]
    cursor: int
    next_cursor: int
    oldest_sequence: int
    latest_sequence: int
    dropped: int
    dropped_total: int
    has_more: bool
    capacity: int

    def to_dict(self) -> JsonObject:
        return {
            "events": [event.to_dict() for event in self.events],
            "count": len(self.events),
            "cursor": self.cursor,
            "next_cursor": self.next_cursor,
            "oldest_sequence": self.oldest_sequence,
            "latest_sequence": self.latest_sequence,
            "dropped": self.dropped,
            "dropped_total": self.dropped_total,
            "has_more": self.has_more,
            "capacity": self.capacity,
        }


@dataclass(slots=True)
class DebugEventCursor:
    value: int = 0

    def advance(self, batch: DebugEventBatch) -> None:
        if batch.cursor != self.value:
            raise DebugEventProtocolError(
                f"event batch cursor {batch.cursor} does not match stream cursor {self.value}"
            )
        self.value = batch.next_cursor


def parse_debug_event_batch(
    payload: object,
    *,
    requested_cursor: int,
    requested_limit: int,
) -> DebugEventBatch:
    if not isinstance(payload, dict):
        raise DebugEventProtocolError("event batch must be an object")
    if type(requested_cursor) is not int or not 0 <= requested_cursor <= _MAX_JSON_INTEGER:
        raise ValueError("requested_cursor must be a non-negative signed 64-bit integer")
    if (
        type(requested_limit) is not int
        or not 1 <= requested_limit <= MAX_DEBUG_EVENT_BATCH
    ):
        raise ValueError(
            f"requested_limit must be between 1 and {MAX_DEBUG_EVENT_BATCH}"
        )

    cursor = _integer(payload, "cursor")
    next_cursor = _integer(payload, "next_cursor")
    oldest = _integer(payload, "oldest_sequence")
    latest = _integer(payload, "latest_sequence")
    dropped = _integer(payload, "dropped")
    dropped_total = _integer(payload, "dropped_total")
    capacity = _integer(payload, "capacity", positive=True)
    if capacity != DEBUG_EVENT_CAPACITY:
        raise DebugEventProtocolError("event batch capacity is incompatible")
    has_more = _boolean(payload, "has_more")
    count = _integer(payload, "count")

    if cursor != requested_cursor:
        raise DebugEventProtocolError("event batch cursor does not match the request")
    if cursor > latest:
        raise DebugEventProtocolError("event batch cursor is ahead of latest_sequence")
    if latest == 0:
        expected_oldest = 0
        expected_dropped_total = 0
    else:
        expected_oldest = max(1, latest - capacity + 1)
        expected_dropped_total = max(0, latest - capacity)
    if oldest != expected_oldest:
        raise DebugEventProtocolError("event sequence bounds are inconsistent")
    if dropped_total != expected_dropped_total:
        raise DebugEventProtocolError("event batch dropped_total is inconsistent")

    expected_dropped = max(0, oldest - cursor - 1) if oldest else 0
    if dropped != expected_dropped:
        raise DebugEventProtocolError("event batch dropped count is inconsistent")

    raw_events = payload.get("events")
    if not isinstance(raw_events, list):
        raise DebugEventProtocolError("event batch events must be an array")
    if count != len(raw_events) or count > requested_limit:
        raise DebugEventProtocolError("event batch count is inconsistent")

    events = tuple(_parse_event(raw) for raw in raw_events)
    first_available = max(cursor + 1, oldest) if oldest else latest + 1
    expected_count = min(requested_limit, max(0, latest - first_available + 1))
    if count != expected_count:
        raise DebugEventProtocolError("event batch does not contain the expected sequence window")

    expected_sequence = cursor + dropped + 1
    for event in events:
        if event.sequence != expected_sequence:
            raise DebugEventProtocolError("event sequences must be contiguous and monotonic")
        expected_sequence += 1

    expected_next = events[-1].sequence if events else cursor + dropped
    if next_cursor != expected_next:
        raise DebugEventProtocolError("event batch next_cursor is inconsistent")
    if has_more != (next_cursor < latest):
        raise DebugEventProtocolError("event batch has_more is inconsistent")

    return DebugEventBatch(
        events=events,
        cursor=cursor,
        next_cursor=next_cursor,
        oldest_sequence=oldest,
        latest_sequence=latest,
        dropped=dropped,
        dropped_total=dropped_total,
        has_more=has_more,
        capacity=capacity,
    )


def _parse_event(payload: object) -> DebugEvent:
    if not isinstance(payload, dict):
        raise DebugEventProtocolError("debug event must be an object")
    sequence = _integer(payload, "sequence", positive=True)
    timestamp = _integer(payload, "timestamp_unix_ms", positive=True)
    source = payload.get("source")
    if source != "x64dbg.plugin_callback":
        raise DebugEventProtocolError("debug event source is invalid")
    kind = payload.get("kind")
    if not isinstance(kind, str) or kind not in _EVENT_INTEGER_FIELDS:
        raise DebugEventProtocolError("debug event kind is invalid")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise DebugEventProtocolError("debug event data must be an object")
    parsed_data = _parse_event_data(kind, data)
    return DebugEvent(
        sequence=sequence,
        timestamp_unix_ms=timestamp,
        source=source,
        kind=kind,
        data=parsed_data,
    )


def _parse_event_data(kind: str, data: JsonObject) -> JsonObject:
    integer_fields = _EVENT_INTEGER_FIELDS[kind]
    text_fields = _EVENT_TEXT_FIELDS.get(kind, frozenset())
    boolean_fields = _EVENT_BOOLEAN_FIELDS.get(kind, frozenset())
    truncation_fields = frozenset(f"{key}_truncated" for key in text_fields)
    allowed_fields = integer_fields | text_fields | boolean_fields | truncation_fields
    if any(not isinstance(key, str) for key in data) or not data.keys() <= allowed_fields:
        raise DebugEventProtocolError(f"debug event data is invalid for kind {kind}")

    parsed: JsonObject = {}
    for key, value in data.items():
        if key in integer_fields:
            if type(value) is not int or not 0 <= value <= _MAX_JSON_INTEGER:
                raise DebugEventProtocolError(
                    f"debug event data {key} must be a non-negative signed 64-bit integer"
                )
        elif key in text_fields:
            maximum_bytes = 1023 if key == "path" else 511
            if not isinstance(value, str) or len(value.encode("utf-8")) > maximum_bytes:
                raise DebugEventProtocolError(f"debug event data {key} is invalid")
        elif key in boolean_fields:
            if type(value) is not bool:
                raise DebugEventProtocolError(f"debug event data {key} must be a boolean")
        else:
            text_key = key.removesuffix("_truncated")
            if type(value) is not bool or value is not True or text_key not in data:
                raise DebugEventProtocolError(
                    f"debug event data {key} must mark a present truncated string"
                )
        parsed[key] = value
    return parsed


def _integer(payload: JsonObject, key: str, *, positive: bool = False) -> int:
    value = payload.get(key)
    minimum = 1 if positive else 0
    if type(value) is not int or not minimum <= value <= _MAX_JSON_INTEGER:
        qualifier = "positive" if positive else "non-negative"
        raise DebugEventProtocolError(
            f"event batch {key} must be a {qualifier} signed 64-bit integer"
        )
    return value


def _boolean(payload: JsonObject, key: str) -> bool:
    value = payload.get(key)
    if type(value) is not bool:
        raise DebugEventProtocolError(f"event batch {key} must be a boolean")
    return value