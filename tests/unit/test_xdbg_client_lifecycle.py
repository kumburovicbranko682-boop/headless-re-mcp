"""XdbgClient lifecycle and diagnostics must fail closed off Windows.

The named-pipe transport is Windows-only, but everything wrapped around it --
the request lock and its fail-closed guards, the best-effort teardown ``close``
performs before killing the worker, ``terminate``'s kill-first ordering, the
on-demand ``reconnect`` guards, and a handful of pure diagnostics helpers -- is
portable Python. A hostile or wedged worker is exactly when this logic runs, so
this module drives it with fake process/transport doubles (no pipe, no JVM):

* ``request`` clamps a bad deadline, refuses a closed/exited/uncapable client,
  reconnects a dropped transport, and dispatches an accepted call,
* ``close`` skips the pre-stop chatter when the worker is already gone, stops an
  active trace and debuggee before exiting, swallows an RPC fault mid-teardown,
  and still kills a worker that will not wait,
* ``terminate`` kills first and then drops the transport,
* ``reconnect`` refuses a closed/exited client and no-ops when still connected,
* the read-side helpers (``read_events`` bounds/mapping, ``_note_debuggee_pid``,
  ``_record_observed_windows`` cap, ``_observe_windows`` refusal, ``_diagnostics``,
  ``_process_exit_error``) hold their contracts.

On Linux ``describe_process_windows`` returns nothing, so ``_observe_windows``
is a no-op unless a fake desktop reports a window -- which one test exploits to
exercise the refusal path directly.
"""

from __future__ import annotations

import subprocess
from collections import deque
from pathlib import Path
from threading import Event, Lock, RLock
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg import client as xdbg_client
from headless_re_mcp.backends.x64dbg.client import (
    _MAX_OBSERVED_WINDOWS,
    XdbgClient,
    XdbgRpcError,
)
from headless_re_mcp.core.events import DebugEventProtocolError

JsonObject = dict[str, Any]


class _FakeProc:
    def __init__(
        self,
        *,
        returncode: int | None = None,
        wait_raises: bool = False,
        pid: int = 1234,
        stdin: Any = None,
    ) -> None:
        self._returncode = returncode
        self._wait_raises = wait_raises
        self.pid = pid
        self.stdin = stdin
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int | None:
        self.wait_calls += 1
        if self._wait_raises:
            raise subprocess.TimeoutExpired(cmd="x64dbg", timeout=timeout or 0.0)
        return self._returncode


class _FakeTransport:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _client(**over: Any) -> XdbgClient:
    client = object.__new__(XdbgClient)
    client._request_lock = RLock()
    client._closed = False
    client._capabilities = frozenset({"events.read"})
    client._transport = None
    client._process = _FakeProc()  # type: ignore[assignment]
    client._stdout_log = deque(maxlen=10)
    client._stderr_log = deque(maxlen=10)
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    client._desktop = None
    client._debuggee_pid = None
    client._monitor_stop = Event()
    client._isolation_job = None
    client._metadata = {}
    for key, value in over.items():
        setattr(client, key, value)
    return client


# --------------------------------------------------------------------------
# request() -- deadline clamp + fail-closed guards + dispatch
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [float("nan"), 0.0, -1.0])
def test_request_rejects_a_non_positive_or_nan_deadline(bad: float) -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _client().request("events.read", timeout=bad)
    assert exc.value.code == "invalid_params"


def test_request_dispatches_an_accepted_call_over_a_live_transport() -> None:
    client = _client(_transport=_FakeTransport())
    calls: list[tuple[str, JsonObject, float]] = []

    def fake_request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        calls.append((method, params, timeout))
        return {"ok": True}

    client._request = fake_request  # type: ignore[method-assign]
    out = client.request("events.read", {"cursor": 3}, timeout=5.0)
    assert out == {"ok": True}
    assert calls == [("events.read", {"cursor": 3}, 5.0)]


def test_request_reconnects_a_dropped_transport_before_dispatch() -> None:
    client = _client(_transport=None)
    reconnected: list[bool] = []

    def fake_reconnect() -> None:
        reconnected.append(True)
        client._transport = _FakeTransport()  # type: ignore[assignment]

    def fake_request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        return {"served": method}

    client._reconnect = fake_reconnect  # type: ignore[method-assign]
    client._request = fake_request  # type: ignore[method-assign]
    out = client.request("events.read")
    assert reconnected == [True]
    assert out == {"served": "events.read"}


# --------------------------------------------------------------------------
# close()
# --------------------------------------------------------------------------


def test_close_is_idempotent_when_already_closed() -> None:
    transport = _FakeTransport()
    client = _client(_closed=True, _transport=transport)
    client.close()
    assert transport.closed is False


def test_close_stops_an_active_trace_and_debuggee_then_tears_down() -> None:
    transport = _FakeTransport()
    proc = _FakeProc(returncode=None, stdin=None)
    client = _client(
        _transport=transport,
        _process=proc,
        _capabilities=frozenset({"trace.status", "trace.stop"}),
    )
    calls: list[str] = []
    replies = {
        "trace.status": {"recording": True},
        "trace.stop": {},
        "debug.state": {"debugging": True},
        "debug.stop": {},
    }

    def fake_request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        calls.append(method)
        return replies[method]

    client._request = fake_request  # type: ignore[method-assign]
    client.close()
    assert calls == ["trace.status", "trace.stop", "debug.state", "debug.stop"]
    assert client._closed is True
    assert transport.closed is True
    assert client._transport is None
    assert proc.wait_calls == 1


def test_close_skips_the_stop_chatter_when_the_worker_already_exited() -> None:
    transport = _FakeTransport()
    client = _client(_transport=transport, _process=_FakeProc(returncode=3))
    calls: list[str] = []

    def fake_request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        calls.append(method)
        return {}

    client._request = fake_request  # type: ignore[method-assign]
    client.close()
    assert calls == []
    assert transport.closed is True


def test_close_skips_stops_when_nothing_is_recording_or_running() -> None:
    client = _client(
        _transport=_FakeTransport(),
        _process=_FakeProc(returncode=None),
        _capabilities=frozenset({"trace.status", "trace.stop"}),
    )
    calls: list[str] = []
    replies = {"trace.status": {"recording": False}, "debug.state": {"debugging": False}}

    def fake_request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        calls.append(method)
        return replies[method]

    client._request = fake_request  # type: ignore[method-assign]
    client.close()
    assert calls == ["trace.status", "debug.state"]


def test_close_swallows_an_rpc_fault_during_pre_stop() -> None:
    transport = _FakeTransport()
    client = _client(
        _transport=transport,
        _process=_FakeProc(returncode=None),
        _capabilities=frozenset({"trace.status"}),
    )

    def fake_request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        raise XdbgRpcError("rpc_transport_error", "boom")

    client._request = fake_request  # type: ignore[method-assign]
    client.close()
    assert client._closed is True
    assert transport.closed is True


def test_close_kills_a_worker_that_will_not_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    proc = _FakeProc(returncode=None, wait_raises=True)
    client = _client(_transport=_FakeTransport(), _process=proc, _capabilities=frozenset())
    terminated: list[bool] = []

    def fake_request(method: str, params: JsonObject, *, timeout: float) -> JsonObject:
        return {"debugging": False}

    client._request = fake_request  # type: ignore[method-assign]
    client._terminate_process = lambda: terminated.append(True)  # type: ignore[method-assign]
    client.close()
    assert terminated == [True]


# --------------------------------------------------------------------------
# terminate()
# --------------------------------------------------------------------------


def test_terminate_kills_first_then_drops_the_transport() -> None:
    transport = _FakeTransport()
    client = _client(_transport=transport)
    order: list[str] = []

    def fake_terminate() -> None:
        order.append("kill")
        assert transport.closed is False

    client._terminate_process = fake_terminate  # type: ignore[method-assign]
    client.terminate()
    assert order == ["kill"]
    assert client._closed is True
    assert transport.closed is True
    assert client._transport is None


# --------------------------------------------------------------------------
# reconnect() guards
# --------------------------------------------------------------------------


def test_reconnect_refuses_a_closed_client() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _client(_closed=True).reconnect()
    assert exc.value.code == "session_closed"


def test_reconnect_reports_a_worker_that_exited() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _client(_process=_FakeProc(returncode=9)).reconnect()
    assert exc.value.code == "worker_exited"


def test_reconnect_is_a_no_op_while_still_connected() -> None:
    transport = _FakeTransport()
    client = _client(_transport=transport)
    client.reconnect()
    assert id(client._transport) == id(transport)
    assert transport.closed is False


# --------------------------------------------------------------------------
# read-only properties
# --------------------------------------------------------------------------


def test_status_properties_reflect_the_process_and_negotiated_state() -> None:
    transport = _FakeTransport()
    client = _client(
        _transport=transport,
        _process=_FakeProc(returncode=None, pid=777),
        _capabilities=frozenset({"a", "b"}),
        _metadata={"tool": "x64dbg"},
    )
    assert client.pid == 777
    assert client.exit_code is None
    assert client.transport_connected is True
    assert client.capabilities == frozenset({"a", "b"})
    assert client.metadata == {"tool": "x64dbg"}
    client.metadata["tool"] = "mutated"
    assert client.metadata == {"tool": "x64dbg"}


def test_transport_connected_is_false_after_a_drop() -> None:
    assert _client(_transport=None).transport_connected is False


def test_runtime_directory_reflects_the_user_directory(tmp_path: Path) -> None:
    class _Dir:
        name = str(tmp_path)

    client = _client(_user_directory=_Dir())
    assert client.runtime_directory == tmp_path


# --------------------------------------------------------------------------
# _note_debuggee_pid
# --------------------------------------------------------------------------


def test_note_debuggee_pid_ignores_a_payload_without_a_pid() -> None:
    client = _client(_debuggee_pid=55)
    client._note_debuggee_pid({"unrelated": 1})
    assert client._debuggee_pid == 55


def test_note_debuggee_pid_accepts_a_positive_integer() -> None:
    client = _client()
    client._note_debuggee_pid({"process_id": 4242})
    assert client._debuggee_pid == 4242


def test_note_debuggee_pid_falls_back_to_a_string_debuggee_pid() -> None:
    client = _client()
    client._note_debuggee_pid({"process_id": None, "debuggee_pid": "808"})
    assert client._debuggee_pid == 808


@pytest.mark.parametrize("value", [0, -1, "0", "not-a-number"])
def test_note_debuggee_pid_rejects_a_non_positive_or_bad_value(value: Any) -> None:
    client = _client()
    client._note_debuggee_pid({"process_id": value})
    assert client._debuggee_pid is None


# --------------------------------------------------------------------------
# _record_observed_windows
# --------------------------------------------------------------------------


def test_record_observed_windows_dedupes_and_caps() -> None:
    client = _client()
    client._record_observed_windows(["a", "b", "a"])
    assert client._observed_windows == {"a", "b"}
    assert client._observed_windows_dropped == 0

    client._observed_windows = {f"w{i}" for i in range(_MAX_OBSERVED_WINDOWS)}
    client._record_observed_windows(["overflow"])
    assert "overflow" not in client._observed_windows
    assert client._observed_windows_dropped == 1


# --------------------------------------------------------------------------
# _observe_windows / _describe_analyzer_windows (fake desktop)
# --------------------------------------------------------------------------


class _FakeDesktop:
    def __init__(self, windows: list[str]) -> None:
        self._windows = windows

    def process_window_descriptions(self, pid: int) -> list[str]:
        return list(self._windows)


def test_observe_windows_refuses_and_records_a_visible_window() -> None:
    client = _client(_desktop=_FakeDesktop(["0x1:Dlg:Analyzing"]))
    with pytest.raises(XdbgRpcError) as exc:
        client._observe_windows()
    assert exc.value.code == "analyzer_window_detected"
    assert exc.value.details == {"windows": ["0x1:Dlg:Analyzing"]}
    assert "0x1:Dlg:Analyzing" in client._observed_windows


def test_observe_windows_is_silent_when_no_window_is_up() -> None:
    client = _client(_desktop=_FakeDesktop([]))
    client._observe_windows()
    assert client._observed_windows == set()


# --------------------------------------------------------------------------
# read_events -- input bounds + protocol-error mapping
# --------------------------------------------------------------------------


def _recording_client(payload: JsonObject) -> tuple[XdbgClient, list[JsonObject]]:
    client = _client()
    seen: list[JsonObject] = []

    def fake_request(
        method: str, params: JsonObject | None = None, *, timeout: float = 10.0
    ) -> JsonObject:
        seen.append({"method": method, **(params or {})})
        return dict(payload)

    client.request = fake_request  # type: ignore[method-assign]
    return client, seen


@pytest.mark.parametrize("cursor", [-1, True, 1 << 63])
def test_read_events_rejects_an_out_of_range_cursor(cursor: Any) -> None:
    client, seen = _recording_client({})
    with pytest.raises(ValueError, match="cursor"):
        client.read_events(cursor)
    assert seen == []


@pytest.mark.parametrize("limit", [0, 10_000_000, True])
def test_read_events_rejects_an_out_of_range_limit(limit: Any) -> None:
    client, seen = _recording_client({})
    with pytest.raises(ValueError, match="limit"):
        client.read_events(0, limit=limit)
    assert seen == []


def test_read_events_maps_a_bad_batch_to_a_protocol_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = _recording_client({"events": "not-a-list"})

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise DebugEventProtocolError("malformed batch")

    monkeypatch.setattr(xdbg_client, "parse_debug_event_batch", boom)
    with pytest.raises(XdbgRpcError) as exc:
        client.read_events(0)
    assert exc.value.code == "rpc_protocol_error"
    assert "malformed batch" in str(exc.value)


# --------------------------------------------------------------------------
# _diagnostics / _process_exit_error
# --------------------------------------------------------------------------


def test_diagnostics_snapshots_process_and_window_state() -> None:
    client = _client(_process=_FakeProc(returncode=None, pid=99))
    client._stdout_log.append("out")
    client._stderr_log.append("err")
    client._observed_windows = {"win"}
    client._observed_windows_dropped = 4
    diag = client._diagnostics()
    assert diag["pid"] == 99
    assert diag["exit_code"] is None
    assert diag["stdout"] == ["out"]
    assert diag["stderr"] == ["err"]
    assert diag["analyzer_windows"] == ["win"]
    assert diag["analyzer_window_capacity"] == _MAX_OBSERVED_WINDOWS
    assert diag["analyzer_windows_dropped"] == 4


def test_process_exit_error_is_retryable_and_carries_the_code() -> None:
    client = _client(_process=_FakeProc(returncode=42))
    error = client._process_exit_error()
    assert error.code == "worker_exited"
    assert error.details["exit_code"] == 42
    assert error.retryable is True


# --------------------------------------------------------------------------
# _request_exit
# --------------------------------------------------------------------------


class _FakeStdin:
    def __init__(self, *, write_raises: bool = False) -> None:
        self.writes: list[str] = []
        self.flushed = False
        self.closed = False
        self._write_raises = write_raises

    def write(self, data: str) -> int:
        if self._write_raises:
            raise BrokenPipeError("peer gone")
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        self.flushed = True

    def close(self) -> None:
        self.closed = True


def test_request_exit_writes_exit_to_a_live_worker() -> None:
    stdin = _FakeStdin()
    client = _client(_process=_FakeProc(returncode=None, stdin=stdin))
    client._request_exit()
    assert stdin.writes == ["exit\n"]
    assert stdin.flushed is True
    assert stdin.closed is True


def test_request_exit_returns_early_when_the_worker_is_gone() -> None:
    stdin = _FakeStdin()
    client = _client(_process=_FakeProc(returncode=0, stdin=stdin))
    client._request_exit()
    assert stdin.writes == []


def test_request_exit_swallows_a_broken_stdin() -> None:
    stdin = _FakeStdin(write_raises=True)
    client = _client(_process=_FakeProc(returncode=None, stdin=stdin))
    client._request_exit()
    assert stdin.writes == []
