"""Guard/edge coverage for the web console monitor snapshot builder.

``test_monitor_snapshot.py`` covers the live x64dbg path against a real
service. These pin the remaining branches with light duck-typed fakes: the
timeline tail bailing out when its first read is not ok, the event tail
reporting a render-safe error when the durable log raises, and the unpack
section surfacing stage / recoverability from an ok unpack result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from headless_re_mcp.core.event_log import PersistentDebugEventLog
from headless_re_mcp.core.events import DebugEvent
from headless_re_mcp.web.monitor import (
    _event_tail,
    _timeline_tail,
    build_monitor_snapshot,
)

JsonObject = dict[str, Any]


@dataclass(frozen=True)
class _Err:
    code: str | None = None
    message: str = ""


@dataclass(frozen=True)
class _Result:
    ok: bool = True
    data: JsonObject | None = None
    error: _Err | None = None


class _RaisingLog:
    """A durable event log whose read blows up mid-frame."""

    @property
    def latest_sequence(self) -> int:
        return 7

    def read_after(self, cursor: int, *, limit: int) -> Any:
        raise RuntimeError("event log is wedged")


@dataclass
class _Runtime:
    event_log: Any


@dataclass
class _FakeService:
    session: _Result
    dynamic: _Result = field(default_factory=_Result)
    workflow: _Result = field(default_factory=_Result)
    unpack: _Result = field(default_factory=_Result)
    web: _Result = field(default_factory=_Result)
    timeline: _Result = field(default_factory=_Result)
    artifacts: _Result = field(default_factory=_Result)
    _runtime_owner: dict[str, Any] = field(default_factory=dict)

    def get_session(self, session_id: str) -> _Result:
        return self.session

    def dynamic_state(self, session_id: str) -> _Result:
        return self.dynamic

    def workflow_status(self, session_id: str) -> _Result:
        return self.workflow

    def unpack_status(self, session_id: str) -> _Result:
        return self.unpack

    def web_status(self, session_id: str) -> _Result:
        return self.web

    def timeline_list(self, session_id: str, *, offset: int, limit: int) -> _Result:
        return self.timeline

    def artifacts_list(self, *, session_id: str, offset: int, limit: int) -> _Result:
        return self.artifacts


def test_timeline_tail_returns_head_when_first_read_is_not_ok() -> None:
    head = _Result(ok=False, error=_Err(code="boom", message="no timeline"))

    class _S:
        def timeline_list(self, session_id: str, *, offset: int, limit: int) -> _Result:
            return head

    result = _timeline_tail(_S(), "sess", 48)  # type: ignore[arg-type]
    # No usable page -> the head result is returned verbatim (no second read).
    assert result is head


def test_event_tail_reports_a_render_safe_error_when_the_log_raises() -> None:
    service = _FakeService(session=_Result(), _runtime_owner={"sess": _Runtime(_RaisingLog())})

    payload, error = _event_tail(service, "sess", 24)  # type: ignore[arg-type]

    assert payload is None
    assert error is not None
    assert error["code"] == "events_unavailable"
    assert "wedged" in error["message"]


def test_event_frame_discloses_its_window_and_what_the_ring_lost() -> None:
    """A busy session's event panel is a tail over a hole, and must say so.

    The tail reads the newest 24 events but surfaced only the events and a
    cursor: a session at sequence 103 drew a frame that read as the whole
    stream, and the three events the native ring overwrote before drain could
    copy them (sequences 1-3 here) vanished without a trace. The durable log's
    batch already knows the high-water mark and the loss count; the frame now
    carries total, truncated, and dropped_total.
    """
    log = PersistentDebugEventLog()
    log.append_events(
        [
            DebugEvent(
                sequence=seq,
                timestamp_unix_ms=seq,
                source="x64dbg",
                kind="debug.stepped",
                data={},
            )
            for seq in range(4, 104)  # 1..3 were overwritten before the drain ran
        ]
    )
    service = _FakeService(
        session=_Result(data={"session": {"target": "pe", "state": "running"}}),
        _runtime_owner={"sess": _Runtime(log)},
    )

    payload, error = _event_tail(service, "sess", 24)  # type: ignore[arg-type]

    assert error is None
    assert payload is not None
    assert [event["sequence"] for event in payload["events"]] == list(range(80, 104))
    assert payload["total"] == 103
    assert payload["truncated"] is True
    assert payload["dropped_total"] == 3
    # The loss (1-3) is entirely before the shown window; the 24 events drawn
    # here run 80..103 with no hole among them, so the frame is contiguous and
    # must not claim otherwise. dropped_total is true while unrecovered_gap is
    # false: they are different facts.
    assert payload["unrecovered_gap"] is False

    snapshot = build_monitor_snapshot(service, "sess")  # type: ignore[arg-type]

    events = snapshot["events"]
    assert len(events["items"]) == 24
    assert events["total"] == 103
    assert events["truncated"] is True
    assert events["dropped_total"] == 3
    assert events["unrecovered_gap"] is False
    assert events["error"] is None


def test_event_frame_discloses_a_hole_inside_the_window_it_shows() -> None:
    """A gap among the shown events is not implied by truncated or dropped_total.

    The drain copied 1..97, the native ring then overwrote 98 and 99 before it
    could copy them, and 100..103 followed. The newest-24 window opens at 80 and
    so straddles that hole: the events it can actually show are 100..103, with a
    gap where 98-99 belong. Surfacing only events/cursor drew those four as a
    clean run. unrecovered_gap says the run has a hole in it -- a fact neither
    truncated (older events exist before the window) nor dropped_total
    (cumulative eviction count) carries.
    """
    log = PersistentDebugEventLog()
    log.append_events(
        [
            DebugEvent(
                sequence=seq,
                timestamp_unix_ms=seq,
                source="x64dbg",
                kind="debug.stepped",
                data={},
            )
            for seq in range(1, 98)
        ]
    )
    log.note_unrecovered_gap(98, 99)  # overwritten in the native ring before drain
    log.append_events(
        [
            DebugEvent(
                sequence=seq,
                timestamp_unix_ms=seq,
                source="x64dbg",
                kind="debug.stepped",
                data={},
            )
            for seq in range(100, 104)
        ]
    )
    service = _FakeService(
        session=_Result(data={"session": {"target": "pe", "state": "running"}}),
        _runtime_owner={"sess": _Runtime(log)},
    )

    payload, error = _event_tail(service, "sess", 24)  # type: ignore[arg-type]

    assert error is None
    assert payload is not None
    # read_after cannot bridge the hole, so the frame is the post-gap events.
    assert [event["sequence"] for event in payload["events"]] == [100, 101, 102, 103]
    assert payload["total"] == 103
    assert payload["truncated"] is True
    assert payload["unrecovered_gap"] is True

    snapshot = build_monitor_snapshot(service, "sess")  # type: ignore[arg-type]

    events = snapshot["events"]
    assert [item["sequence"] for item in events["items"]] == [100, 101, 102, 103]
    assert events["unrecovered_gap"] is True
    assert events["error"] is None


def test_unpack_section_surfaces_stage_and_recoverability() -> None:
    service = _FakeService(
        session=_Result(data={"session": {"target": "pe", "state": "running"}}),
        dynamic=_Result(data={"state": "running", "debugging": True}),
        workflow=_Result(data={"workflow": {"phase": "navigating"}}),
        unpack=_Result(data={"unpack": {"stage": "dumped", "recoverability": "iat_recoverable"}}),
        timeline=_Result(data={"items": [{"seq": 1}], "total": 1, "count": 1}),
        artifacts=_Result(data={"artifacts": []}),
    )

    snapshot = build_monitor_snapshot(service, "sess")  # type: ignore[arg-type]

    assert snapshot["ok"] is True
    assert snapshot["unpack"]["present"] is True
    assert snapshot["unpack"]["stage"] == "dumped"
    assert snapshot["unpack"]["recoverability"] == "iat_recoverable"
    assert snapshot["workflow"]["present"] is True
    assert snapshot["dynamic"]["state"] == "running"
    assert snapshot["claims_universal_unpack"] is False


def test_unpack_section_falls_back_to_the_top_level_object() -> None:
    # No nested "unpack" key: the whole ok payload becomes the object, and the
    # stage is read from it directly.
    service = _FakeService(
        session=_Result(data={"session": {"target": "pe", "state": "running"}}),
        unpack=_Result(data={"stage": "iat_rebuilt", "recoverability_hint": "recoverable"}),
    )

    snapshot = build_monitor_snapshot(service, "sess")  # type: ignore[arg-type]

    assert snapshot["unpack"]["present"] is True
    assert snapshot["unpack"]["stage"] == "iat_rebuilt"
    assert snapshot["unpack"]["recoverability"] == "recoverable"
