"""Debugger analyzer-window history must stay bounded over long sessions.

Both debugger backends keep a cumulative record of analyzer windows they have
seen, for gate diagnostics.  A progress-bearing window title changes on every
sighting (the x64dbg monitor polls every 50 ms), so an uncapped record grows by
one permanent string per sighting for the life of the worker.
"""

from __future__ import annotations

import queue
from collections import deque
from itertools import count
from threading import Lock

import pytest

from headless_re_mcp.backends.ida import client as ida_client
from headless_re_mcp.backends.ida.client import IdaWorkerClient, IdaWorkerError
from headless_re_mcp.backends.x64dbg import client as xdbg_client
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError

_SIGHTINGS = 1_000


class _FakeProcess:
    pid = 4321

    def poll(self) -> int | None:
        return None


def _bare_ida_client() -> IdaWorkerClient:
    client = IdaWorkerClient.__new__(IdaWorkerClient)
    client._process = _FakeProcess()  # type: ignore[assignment]
    client._stdout_log = deque(maxlen=100)
    client._stderr_log = deque(maxlen=100)
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    # _diagnostics() also reports the bounded pending-message queue, so a bare
    # client needs those attributes too, exactly as __init__ sets them.
    client._messages = queue.Queue(maxsize=ida_client._MAX_PENDING_WORKER_MESSAGES)
    client._messages_dropped = 0
    return client


def _bare_xdbg_client() -> XdbgClient:
    client = XdbgClient.__new__(XdbgClient)
    client._process = _FakeProcess()  # type: ignore[assignment]
    client._stdout_log = deque(maxlen=200)
    client._stderr_log = deque(maxlen=200)
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    return client


def test_ida_analyzer_window_history_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _bare_ida_client()
    tick = count()
    monkeypatch.setattr(
        ida_client,
        "describe_process_windows",
        lambda pid: [f"0x40a2:TForm:auto-analysis {next(tick)}"],
    )

    for _ in range(_SIGHTINGS):
        with pytest.raises(IdaWorkerError) as caught:
            client._observe_windows()
        assert caught.value.code == "analyzer_window_detected"

    assert len(client._observed_windows) == ida_client._MAX_OBSERVED_WINDOWS
    assert client._observed_windows_dropped == _SIGHTINGS - ida_client._MAX_OBSERVED_WINDOWS

    diagnostics = client._diagnostics()
    assert diagnostics["analyzer_window_capacity"] == ida_client._MAX_OBSERVED_WINDOWS
    assert diagnostics["analyzer_windows_dropped"] == client._observed_windows_dropped


def test_xdbg_analyzer_window_history_is_bounded() -> None:
    client = _bare_xdbg_client()

    # Both the 50 ms monitor thread and the request gate record through the
    # same helper; feed it one fresh progress title per tick, as the monitor
    # would observe against a live analyzer.
    for tick in range(_SIGHTINGS):
        client._record_observed_windows([f"0x1a2b:Qt5QWindowIcon:Analysing {tick}"])

    assert len(client._observed_windows) == xdbg_client._MAX_OBSERVED_WINDOWS
    assert client._observed_windows_dropped == _SIGHTINGS - xdbg_client._MAX_OBSERVED_WINDOWS

    diagnostics = client._diagnostics()
    assert diagnostics["analyzer_window_capacity"] == xdbg_client._MAX_OBSERVED_WINDOWS
    assert diagnostics["analyzer_windows_dropped"] == client._observed_windows_dropped


def test_xdbg_gate_still_refuses_after_recording_is_capped() -> None:
    client = _bare_xdbg_client()
    full_history = [f"seen:{index}" for index in range(xdbg_client._MAX_OBSERVED_WINDOWS)]
    client._record_observed_windows(full_history)

    def _describe() -> list[str]:
        return ["0x1a2b:Qt5QWindowIcon:Analysing"]

    client._describe_analyzer_windows = _describe  # type: ignore[method-assign]

    with pytest.raises(XdbgRpcError) as caught:
        client._observe_windows()

    assert caught.value.code == "analyzer_window_detected"
    assert caught.value.details == {"windows": ["0x1a2b:Qt5QWindowIcon:Analysing"]}
