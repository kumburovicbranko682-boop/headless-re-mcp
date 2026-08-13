"""What a console frame costs the agent it is watching.

The monitor and the agent read the same session. One of them advancing the
session's only consumer cursor takes events off the other, and does it without
leaving a gap for anyone to notice.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.web.monitor import build_monitor_snapshot
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _event_batch,
    _service,
    _write_minimal_pe,
)


def test_a_console_frame_does_not_eat_the_agents_events(tmp_path: Path) -> None:
    """Watching the run must not change it.

    dynamic_events reads through the session's single consumer cursor and
    advances it, so every frame the console drew handed itself events the agent
    would then never be given. The batch reports no gap either, because the
    cursor moved legitimately -- the agent cannot tell it lost anything, and it
    only happens while somebody is looking.
    """
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker(event_batches=[_event_batch(0, (1, 2, 3, 4, 5), latest=5)])
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok

    first = service.dynamic_events(session_id, limit=2)
    assert first.ok and first.data is not None
    assert [event["sequence"] for event in first.data["events"]] == [1, 2]

    snapshot = build_monitor_snapshot(service, session_id)

    remaining = service.dynamic_events(session_id, limit=10)
    assert remaining.ok and remaining.data is not None
    assert [event["sequence"] for event in remaining.data["events"]] == [3, 4, 5], (
        "the frame consumed what the agent had not read yet"
    )
    assert remaining.data["dropped"] == 0

    shown = snapshot["events"]["items"]
    assert [event["sequence"] for event in shown] == [1, 2, 3, 4, 5], (
        "the frame still has to show the live stream"
    )
    assert snapshot["events"]["error"] is None


def test_a_frame_for_a_session_with_no_event_log_says_so(tmp_path: Path) -> None:
    """A static-only session has no debugger stream, and that is not a failure."""
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = _create(service, binary)

    snapshot = build_monitor_snapshot(service, session_id)

    assert snapshot["ok"] is True
    assert snapshot["events"]["items"] == []
    assert snapshot["events"]["error"] is not None
