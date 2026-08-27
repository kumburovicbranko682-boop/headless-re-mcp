"""The run event SSE stream must deliver the run's terminal event.

The orchestrator commits a run's status flip and its terminal event
(``run.completed`` / ``run.failed`` / ``run.cancelled`` / ``run.rejected``) in
two separate transactions. A stream that ended the instant it read the run as
terminal could stop in the gap between those commits and never send the event,
leaving the client on a run that never visibly finishes. These drive that exact
interleaving against the extracted stream generator with a no-op sleep, so the
behaviour is pinned without depending on timing.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.web.routes.agent import (
    _TERMINAL_EVENT_GRACE_POLLS,
    _run_event_stream,
)


class _FakeEvent:
    def __init__(self, seq: int, type_: str) -> None:
        self.seq = seq
        self.type = type_

    def dump(self) -> dict[str, Any]:
        return {"seq": self.seq, "type": self.type}


class _FakeRun:
    def __init__(self, status: RunStatus) -> None:
        self.status = status


class _ScriptedStore:
    """Returns one pre-scripted ``list_events`` batch per call; ``get_run`` fixed."""

    def __init__(self, status: RunStatus, batches: list[list[_FakeEvent]]) -> None:
        self._run = _FakeRun(status)
        self._batches = batches
        self.list_calls = 0

    def get_run(self, run_id: str) -> _FakeRun:
        return self._run

    def list_events(self, run_id: str, *, after: int = 0) -> list[_FakeEvent]:
        index = self.list_calls
        self.list_calls += 1
        return self._batches[index] if index < len(self._batches) else []


async def _noop_sleep(seconds: float) -> None:
    return None


async def _collect(gen: Any) -> str:
    return "".join([chunk.decode() async for chunk in gen])


@pytest.mark.asyncio
async def test_stream_delivers_terminal_event_appended_after_status_flipped() -> None:
    # The run already reads COMPLETED while list_events is still empty for two
    # polls; then run.completed lands. The stream must not have ended early.
    store = _ScriptedStore(
        RunStatus.COMPLETED,
        [[], [], [_FakeEvent(7, "run.completed")]],
    )
    body = await _collect(_run_event_stream(store, "r1", 0, sleep=_noop_sleep))
    assert "event: run.completed" in body
    assert "id: 7" in body


@pytest.mark.asyncio
async def test_stream_stops_after_grace_when_no_terminal_event_ever_arrives() -> None:
    # A run that reads terminal but never records a terminal event must not hold
    # the socket open forever: it ends after the bounded grace, sending nothing.
    store = _ScriptedStore(RunStatus.FAILED, [])
    body = await _collect(_run_event_stream(store, "r1", 0, sleep=_noop_sleep))
    assert body == ""
    assert store.list_calls == _TERMINAL_EVENT_GRACE_POLLS


@pytest.mark.asyncio
async def test_stream_delivers_earlier_events_before_the_terminal_one() -> None:
    store = _ScriptedStore(
        RunStatus.STREAMING,
        [[_FakeEvent(1, "llm.started")], [_FakeEvent(2, "run.completed")]],
    )
    body = await _collect(_run_event_stream(store, "r1", 0, sleep=_noop_sleep))
    assert "event: llm.started" in body
    assert "event: run.completed" in body
