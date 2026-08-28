"""Remaining guard/persistence arms of ``AnalysisService.dynamic_events``.

test_dynamic_service.py drives the durable-log happy paths, the bounds guards,
and the fatal drain error. What is left dark are three narrow arms: a backend
that lacks the ``events.read`` capability, a runtime whose durable log has been
torn down, a cursor that rejects the served batch as inconsistent, and the
opt-in timeline mirror that fires only when ``persist_debug_events`` is on.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.events import DebugEventProtocolError
from headless_re_mcp.core.models import BackendKind
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _create,
    _event_batch,
    _settings,
    _write_minimal_pe,
)


class _NoEventsReadWorker(FakeDynamicWorker):
    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset(cap for cap in super().capabilities if cap != "events.read")


def _open(
    tmp_path: Path, worker: FakeDynamicWorker, **settings: Any
) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    base = _settings(tmp_path)
    service = AnalysisService(
        replace(base, **settings) if settings else base,
        dynamic_worker_factory=lambda session, s: worker,
    )
    session_id = _create(service, binary)
    assert service.open_dynamic(session_id).ok
    return service, session_id


def test_events_without_the_read_capability_is_rejected(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, _NoEventsReadWorker())

    result = service.dynamic_events(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"
    assert result.error.details["capability"] == "events.read"


def test_events_without_a_durable_log_is_a_protocol_error(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, FakeDynamicWorker())
    runtime = service._runtime(session_id, BackendKind.X64DBG)
    runtime.event_log = None  # tear the durable log down after opening

    result = service.dynamic_events(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"
    assert "durable event log" in result.error.message


def test_events_reports_an_inconsistent_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = FakeDynamicWorker(event_batches=[_event_batch(0, (1, 2))])
    service, session_id = _open(tmp_path, worker)
    runtime = service._runtime(session_id, BackendKind.X64DBG)
    original = runtime.event_cursor
    assert original is not None
    current_value = original.value

    class _RejectingCursor:
        # DebugEventCursor is slotted, so its advance cannot be patched in
        # place; a stand-in serves the same value and refuses the batch.
        value = current_value

        def advance(self, batch: Any) -> None:
            raise DebugEventProtocolError("sequence went backwards")

    runtime.event_cursor = _RejectingCursor()  # type: ignore[assignment]

    result = service.dynamic_events(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "event_cursor_inconsistent"


def test_events_mirror_the_timeline_when_persistence_is_enabled(tmp_path: Path) -> None:
    worker = FakeDynamicWorker(event_batches=[_event_batch(0, (1, 2))])
    service, session_id = _open(tmp_path, worker, persist_debug_events=True)

    result = service.dynamic_events(session_id, limit=7, timeout=2.5)

    assert result.ok and result.data is not None
    assert result.data["events"], "the batch must carry events for the mirror to run"
    timeline = service.timeline_list(session_id)
    assert timeline.ok and timeline.data is not None
    kinds = [entry.get("event") for entry in timeline.data["events"]]
    assert "debug.event" in kinds


def test_events_survive_a_worker_whose_read_raises_but_stays_alive(tmp_path: Path) -> None:
    # A retryable transport fault during the native drain must surface as a
    # structured failure without tearing the runtime down.
    worker = FakeDynamicWorker(
        XdbgRpcError("rpc_transport_error", "pipe stalled", retryable=True)
    )
    service, session_id = _open(tmp_path, worker)

    result = service.dynamic_events(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_transport_error"
