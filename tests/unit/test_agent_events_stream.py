from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.agent.models import RunEvent, RunStatus
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.web.routes.agent import _stream_run_events

JsonObject = dict[str, Any]


class _FakeRun:
    def __init__(self, status: RunStatus) -> None:
        self.status = status


class _ScriptedStore:
    """Serves ``list_events`` / ``get_run`` from a fixed script.

    Each ``list_events`` call consumes the next scripted page, so a test can
    place the terminal event a poll later than the terminal status and drive
    the exact interleaving the real store exposes: the run flips to a terminal
    status in one transaction and appends its terminal event in the next, so a
    reader can see the status before the event.
    """

    def __init__(self, *, pages: list[list[RunEvent]], run_status: RunStatus) -> None:
        self._pages = pages
        self._run_status = run_status
        self.list_calls = 0

    def list_events(self, run_id: str, *, after: int = 0, limit: int = 1000) -> list[RunEvent]:
        self.list_calls += 1
        page = self._pages.pop(0) if self._pages else []
        return [event for event in page if event.seq > after]

    def get_run(self, run_id: str) -> _FakeRun | None:
        return _FakeRun(self._run_status)


def _event(seq: int, type_: str) -> RunEvent:
    return RunEvent(run_id="r", seq=seq, type=type_, data={"status": type_}, created_at="2026-01-01T00:00:00+00:00")


async def _collect(store: Any, run_id: str = "r", after: int = 0) -> list[bytes]:
    frames: list[bytes] = []
    async for frame in _stream_run_events(store, run_id, after, poll_interval_s=0.0):
        frames.append(frame)
    return frames


def _types(frames: list[bytes]) -> list[str]:
    seen: list[str] = []
    for frame in frames:
        for line in frame.decode().splitlines():
            if line.startswith("event: "):
                seen.append(line[len("event: ") :])
    return seen


@pytest.mark.asyncio
async def test_terminal_event_committed_after_terminal_status_is_still_streamed() -> None:
    """The race the stream has to survive.

    First poll sees no events; the run already reads terminal (its status was
    committed first). The terminal event lands in the very next transaction, so
    a stream that stopped on "terminal and nothing new" would close without
    ever sending run.completed. The stream must drain once more and deliver it.
    """
    store = _ScriptedStore(
        pages=[[], [_event(1, "run.completed")]],
        run_status=RunStatus.COMPLETED,
    )

    frames = await _collect(store)

    assert "run.completed" in _types(frames)


@pytest.mark.asyncio
async def test_terminal_event_present_on_first_poll_ends_the_stream() -> None:
    """The ordinary path: the event is already there, so one poll suffices."""
    store = _ScriptedStore(
        pages=[[_event(1, "message.delta"), _event(2, "run.completed")]],
        run_status=RunStatus.COMPLETED,
    )

    frames = await _collect(store)

    assert _types(frames) == ["message.delta", "run.completed"]
    # Breaking on the event, not the status, means get_run was never consulted:
    # the event is the last thing a run emits.
    assert store.list_calls == 1


@pytest.mark.asyncio
async def test_stream_stops_when_a_run_is_terminal_with_no_event_left() -> None:
    """A run abandoned in a terminal state must not stream forever.

    No terminal event will ever arrive, so the status is the only signal that
    the stream is over. The drain confirms nothing is pending, then the loop
    ends rather than polling indefinitely.
    """
    store = _ScriptedStore(pages=[[]], run_status=RunStatus.INTERRUPTED)

    frames = await _collect(store)

    assert _types(frames) == []


@pytest.mark.asyncio
async def test_real_store_stream_delivers_the_terminal_event(tmp_path: Path) -> None:
    """End to end against the real store and its two-transaction terminal path."""
    store = AgentStore(tmp_path / "agent.db")
    thread = store.create_thread()
    run = store.create_run(thread.id, provider_profile="default", model=None, deadline_seconds=60)
    store.transition(run.id, RunStatus.STREAMING)
    store.append_event(run.id, "message.delta", {"delta": "hi"})
    store.transition(run.id, RunStatus.COMPLETED)
    store.append_event(run.id, "run.completed", {"status": RunStatus.COMPLETED.value})

    frames = await _collect(store, run_id=run.id)

    types = _types(frames)
    assert "message.delta" in types
    # The terminal event is delivered and closes the stream: it is last, and
    # nothing follows it.
    assert types[-1] == "run.completed"
    assert types.count("run.completed") == 1
