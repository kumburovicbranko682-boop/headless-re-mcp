"""XdbgClient's framing codec and handshake distrust every byte from the pipe.

``_request`` is the one place the client turns a method call into a length-
prefixed frame and turns the worker's reply back into a result, and
``_connect_transport`` / ``_reconnect`` are where a fresh (or rebuilt)
connection re-authenticates and re-negotiates capabilities. Both run against a
process the client did not write and cannot trust, so this module drives them
with a scripted byte transport and a fake named-pipe factory -- no Windows, no
real pipe:

* ``_request`` returns a well-formed result, and otherwise raises the right
  structured error for a bad frame length, a torn connection (worker alive vs.
  exited), non-JSON / non-object / bad-envelope / not-ok / non-object-result
  replies, an oversize request, deeply nested JSON, a missing transport, and a
  non-positive deadline,
* ``_connect_transport`` closes a stale transport, checks the server PID and
  the hello PID/architecture, and unwinds the transport on any failure,
* ``_reconnect`` refreshes the capability set and rejects a non-array,
* the worker-plumbing helpers (``_read_log``, ``_suppress_input_desktop_leaks``,
  ``_terminate_process``, ``_finish_threads`` cleanup, one ``_monitor_windows``
  tick, and the ``desktop_snapshot`` / ``desktop_capture`` passthrough) hold.
"""

from __future__ import annotations

import io
import json
from collections import deque
from pathlib import Path
from threading import Event, Lock, RLock
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg import client as xdbg_client
from headless_re_mcp.backends.x64dbg.client import (
    _MAX_FRAME_BYTES,
    _PROTOCOL,
    _PROTOCOL_VERSION,
    XdbgClient,
    XdbgRpcError,
)
from headless_re_mcp.core import ui_win32, windows
from headless_re_mcp.core.models import Architecture

JsonObject = dict[str, Any]


class _FakeProc:
    def __init__(self, *, returncode: int | None = None, pid: int = 1234) -> None:
        self._returncode = returncode
        self.pid = pid

    def poll(self) -> int | None:
        return self._returncode


class _ScriptedTransport:
    """Serve a canned byte stream for ``read_exact`` and record every write."""

    def __init__(self, read_bytes: bytes = b"", *, raise_on: str | None = None) -> None:
        self._read_bytes = read_bytes
        self._pos = 0
        self.writes: list[bytes] = []
        self.closed = False
        self._raise_on = raise_on

    def write_all(self, data: bytes, *, timeout: float) -> None:
        if self._raise_on == "write":
            raise BrokenPipeError("named-pipe write failed")
        self.writes.append(data)

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        if self._raise_on == "read":
            raise OSError("named-pipe read failed")
        chunk = self._read_bytes[self._pos : self._pos + size]
        self._pos += size
        return chunk

    def close(self) -> None:
        self.closed = True


def _client(**over: Any) -> XdbgClient:
    client = object.__new__(XdbgClient)
    client._request_lock = RLock()
    client._closed = False
    client._capabilities = frozenset({"events.read"})
    client._transport = None
    client._process = _FakeProc()  # type: ignore[assignment]
    client._request_id = 0
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
    client._token = "tok"
    client._pipe_name = r"\\.\pipe\headless-re-xdbg-test"
    client._architecture = Architecture.X64
    for key, value in over.items():
        setattr(client, key, value)
    return client


def _frame(body: bytes) -> bytes:
    return len(body).to_bytes(4, "little") + body


def _reply(rid: str = "1", **over: Any) -> bytes:
    payload: JsonObject = {
        "protocol": _PROTOCOL,
        "version": _PROTOCOL_VERSION,
        "id": rid,
        "ok": True,
        "result": {},
    }
    payload.update(over)
    return _frame(json.dumps(payload).encode("utf-8"))


# --------------------------------------------------------------------------
# _request -- happy path
# --------------------------------------------------------------------------


def test_request_round_trips_a_well_formed_reply() -> None:
    transport = _ScriptedTransport(_reply(result={"value": 7, "process_id": 4242}))
    client = _client(_transport=transport)
    result = client._request("events.read", {"cursor": 0}, timeout=5.0)
    assert result == {"value": 7, "process_id": 4242}
    assert client._debuggee_pid == 4242
    assert len(transport.writes) == 1
    # The frame is a 4-byte little-endian length prefix followed by the body.
    frame = transport.writes[0]
    assert int.from_bytes(frame[:4], "little") == len(frame) - 4


# --------------------------------------------------------------------------
# _request -- fail-closed guards
# --------------------------------------------------------------------------


def test_request_rejects_a_missing_transport() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=None)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_unavailable"


def test_request_rejects_a_non_positive_deadline() -> None:
    with pytest.raises(ValueError, match="timeout must be positive"):
        _client(_transport=_ScriptedTransport())._request("events.read", {}, timeout=0.0)


def test_request_rejects_an_oversize_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(xdbg_client, "_MAX_FRAME_BYTES", 8)
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=_ScriptedTransport())._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "request_too_large"


@pytest.mark.parametrize("declared", [0, _MAX_FRAME_BYTES + 1])
def test_request_rejects_an_invalid_response_frame_length(declared: int) -> None:
    transport = _ScriptedTransport(declared.to_bytes(4, "little"))
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=transport)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_protocol_error"


def test_request_reports_a_transport_fault_as_retryable_when_the_worker_lives() -> None:
    transport = _ScriptedTransport(raise_on="read")
    client = _client(_transport=transport, _process=_FakeProc(returncode=None))
    with pytest.raises(XdbgRpcError) as exc:
        client._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_transport_error"
    assert exc.value.retryable is True
    assert transport.closed is True
    assert client._transport is None


def test_request_reports_worker_exited_when_the_fault_followed_a_crash() -> None:
    transport = _ScriptedTransport(raise_on="read")
    client = _client(_transport=transport, _process=_FakeProc(returncode=139))
    with pytest.raises(XdbgRpcError) as exc:
        client._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "worker_exited"
    assert exc.value.details["exit_code"] == 139


def test_request_rejects_a_reply_that_is_not_utf8_json() -> None:
    transport = _ScriptedTransport(_frame(b"\xff\xfenot json"))
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=transport)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_protocol_error"


def test_request_rejects_a_reply_that_is_not_an_object() -> None:
    transport = _ScriptedTransport(_frame(json.dumps([1, 2, 3]).encode("utf-8")))
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=transport)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_protocol_error"


def test_request_rejects_a_reply_with_a_broken_envelope() -> None:
    transport = _ScriptedTransport(_reply(id="mismatched-id"))
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=transport)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_protocol_error"


def test_request_surfaces_a_not_ok_reply_as_the_worker_error() -> None:
    body = _reply(ok=False, error={"code": "bad_state", "message": "paused"})
    transport = _ScriptedTransport(body)
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=transport)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "bad_state"
    assert str(exc.value) == "paused"


def test_request_rejects_a_non_object_result() -> None:
    transport = _ScriptedTransport(_reply(result="not-a-map"))
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=transport)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_protocol_error"


def test_request_rejects_a_reply_that_nests_too_deeply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _RecursingJson:
        dumps = staticmethod(json.dumps)
        JSONDecodeError = json.JSONDecodeError

        @staticmethod
        def loads(data: Any) -> Any:
            raise RecursionError("too deep")

    monkeypatch.setattr(xdbg_client, "json", _RecursingJson)
    transport = _ScriptedTransport(_reply())
    with pytest.raises(XdbgRpcError) as exc:
        _client(_transport=transport)._request("events.read", {}, timeout=5.0)
    assert exc.value.code == "rpc_protocol_error"
    assert "deeply" in str(exc.value)


# --------------------------------------------------------------------------
# _connect_transport -- handshake and unwind
# --------------------------------------------------------------------------


class _HandshakeTransport:
    def __init__(self, server_pid: int) -> None:
        self._server_pid = server_pid
        self.closed = False

    @property
    def server_pid(self) -> int:
        return self._server_pid

    def close(self) -> None:
        self.closed = True


def _patch_connect(
    monkeypatch: pytest.MonkeyPatch, transport: _HandshakeTransport
) -> None:
    def fake_connect(pipe_name: str, *, timeout: float, process: Any) -> _HandshakeTransport:
        return transport

    monkeypatch.setattr(xdbg_client._NamedPipeTransport, "connect", staticmethod(fake_connect))


def test_connect_transport_authenticates_and_closes_the_stale_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = _HandshakeTransport(1234)
    fresh = _HandshakeTransport(1234)
    client = _client(_transport=stale, _process=_FakeProc(returncode=None, pid=1234))
    _patch_connect(monkeypatch, fresh)
    hello = {"pid": 1234, "architecture": "x64", "capabilities": ["events.read"]}
    client._request = lambda method, params, *, timeout: dict(hello)  # type: ignore[method-assign]
    out = client._connect_transport(5.0)
    assert out == hello
    assert stale.closed is True
    assert id(client._transport) == id(fresh)


def test_connect_transport_rejects_a_server_pid_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = _HandshakeTransport(9999)
    client = _client(_transport=None, _process=_FakeProc(returncode=None, pid=1234))
    _patch_connect(monkeypatch, fresh)
    with pytest.raises(XdbgRpcError) as exc:
        client._connect_transport(5.0)
    assert exc.value.code == "rpc_peer_mismatch"
    assert fresh.closed is True
    assert client._transport is None


def test_connect_transport_rejects_a_hello_pid_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = _HandshakeTransport(1234)
    client = _client(_transport=None, _process=_FakeProc(returncode=None, pid=1234))
    _patch_connect(monkeypatch, fresh)
    client._request = lambda method, params, *, timeout: {"pid": 5, "architecture": "x64"}  # type: ignore[method-assign]
    with pytest.raises(XdbgRpcError) as exc:
        client._connect_transport(5.0)
    assert exc.value.code == "rpc_peer_mismatch"
    assert fresh.closed is True


def test_connect_transport_rejects_an_architecture_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = _HandshakeTransport(1234)
    client = _client(_transport=None, _process=_FakeProc(returncode=None, pid=1234))
    _patch_connect(monkeypatch, fresh)
    client._request = lambda method, params, *, timeout: {"pid": 1234, "architecture": "x86"}  # type: ignore[method-assign]
    with pytest.raises(XdbgRpcError) as exc:
        client._connect_transport(5.0)
    assert exc.value.code == "architecture_mismatch"
    assert fresh.closed is True


# --------------------------------------------------------------------------
# _reconnect -- capability refresh
# --------------------------------------------------------------------------


def test_reconnect_refreshes_the_capability_set() -> None:
    client = _client(_capabilities=frozenset())
    client._connect_transport = lambda timeout: {"capabilities": ["a", "b"]}  # type: ignore[method-assign]
    client._reconnect()
    assert client._capabilities == frozenset({"a", "b"})


def test_reconnect_rejects_a_non_array_capability_set() -> None:
    client = _client()
    client._connect_transport = lambda timeout: {"capabilities": "nope"}  # type: ignore[method-assign]
    with pytest.raises(XdbgRpcError) as exc:
        client._reconnect()
    assert exc.value.code == "rpc_protocol_error"


# --------------------------------------------------------------------------
# worker-plumbing helpers
# --------------------------------------------------------------------------


def test_read_log_drains_a_stream_into_the_ring_buffer() -> None:
    client = _client()
    target: deque[str] = deque(maxlen=10)
    client._read_log(io.StringIO("first\nsecond\n"), target)
    assert list(target) == ["first", "second"]


def test_suppress_input_desktop_leaks_covers_the_debuggee_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden: list[set[int]] = []
    monkeypatch.setattr(xdbg_client, "enumerate_direct_children", lambda pid: [55, 66])
    monkeypatch.setattr(
        xdbg_client, "hide_input_desktop_windows_for_pids", lambda pids: hidden.append(set(pids))
    )
    client = _client(_process=_FakeProc(pid=1234), _debuggee_pid=4242)
    client._suppress_input_desktop_leaks()
    assert hidden == [{1234, 4242, 55, 66}]


def test_terminate_process_kills_the_whole_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    killed: list[Any] = []
    monkeypatch.setattr(
        xdbg_client, "terminate_process_tree", lambda proc, wait_s: killed.append((proc, wait_s))
    )
    proc = _FakeProc()
    _client(_process=proc)._terminate_process()
    assert killed == [(proc, 5.0)]


class _Closeable:
    def __init__(self, *, raises: bool = False) -> None:
        self.closed = False
        self._raises = raises

    def close(self) -> None:
        self.closed = True
        if self._raises:
            raise OSError("cleanup refused")

    def cleanup(self) -> None:
        self.close()


def test_finish_threads_releases_the_desktop_and_isolation_job() -> None:
    desktop = _Closeable()
    job = _Closeable()
    userdir = _Closeable()
    client = _client(_desktop=desktop, _isolation_job=job, _user_directory=userdir)
    client._finish_threads()
    assert client._monitor_stop.is_set()
    assert desktop.closed is True
    assert job.closed is True
    assert userdir.closed is True
    assert client._desktop is None
    assert client._isolation_job is None


def test_finish_threads_suppresses_cleanup_failures() -> None:
    client = _client(
        _desktop=_Closeable(raises=True),
        _isolation_job=_Closeable(raises=True),
        _user_directory=_Closeable(raises=True),
    )
    client._finish_threads()
    assert client._monitor_stop.is_set()


def test_suppress_input_desktop_leaks_uses_only_the_worker_pid_without_a_debuggee(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden: list[set[int]] = []

    def refuse(pid: int) -> list[int]:
        raise AssertionError("must not enumerate children without a debuggee")

    monkeypatch.setattr(xdbg_client, "enumerate_direct_children", refuse)
    monkeypatch.setattr(
        xdbg_client, "hide_input_desktop_windows_for_pids", lambda pids: hidden.append(set(pids))
    )
    client = _client(_process=_FakeProc(pid=1234), _debuggee_pid=None)
    client._suppress_input_desktop_leaks()
    assert hidden == [{1234}]


def test_monitor_windows_records_and_suppresses_for_one_tick() -> None:
    client = _client(_desktop=object())
    suppressed: list[bool] = []

    def fake_describe() -> list[str]:
        client._monitor_stop.set()
        return ["0x9:Dlg:Working"]

    client._describe_analyzer_windows = fake_describe  # type: ignore[method-assign]
    client._suppress_input_desktop_leaks = lambda: suppressed.append(True)  # type: ignore[method-assign]
    client._monitor_windows()
    assert "0x9:Dlg:Working" in client._observed_windows
    assert suppressed == [True]


def test_monitor_windows_backs_off_on_an_empty_tick_without_a_desktop() -> None:
    client = _client(_desktop=None)

    def fake_describe() -> list[str]:
        client._monitor_stop.set()
        return []

    client._describe_analyzer_windows = fake_describe  # type: ignore[method-assign]
    client._monitor_windows()
    assert client._observed_windows == set()


# --------------------------------------------------------------------------
# desktop passthrough (hidden-desktop branch)
# --------------------------------------------------------------------------


class _FakeHiddenDesktop:
    def __init__(self) -> None:
        self.snapshot_calls: list[Any] = []
        self.capture_calls: list[Any] = []

    def snapshot(self, *, allowed_pids: Any = None) -> JsonObject:
        self.snapshot_calls.append(allowed_pids)
        return {"windows": []}

    def capture(self, hwnd: int, *, allowed_pids: Any, output_path: Any) -> JsonObject:
        self.capture_calls.append((hwnd, allowed_pids, output_path))
        return {"path": str(output_path)}


def test_desktop_snapshot_delegates_to_the_hidden_desktop() -> None:
    desktop = _FakeHiddenDesktop()
    client = _client(_desktop=desktop)
    out = client.desktop_snapshot(allowed_pids=frozenset({1}))
    assert out == {"windows": []}
    assert desktop.snapshot_calls == [frozenset({1})]


def test_desktop_capture_delegates_to_the_hidden_desktop(tmp_path: Path) -> None:
    desktop = _FakeHiddenDesktop()
    client = _client(_desktop=desktop)
    target = tmp_path / "shot.png"
    out = client.desktop_capture(0x1, allowed_pids=frozenset({1}), output_path=target)
    assert out == {"path": str(target)}
    assert desktop.capture_calls == [(0x1, frozenset({1}), target)]


def test_desktop_snapshot_falls_back_when_no_hidden_desktop() -> None:
    out = _client(_desktop=None).desktop_snapshot()
    assert out["available"] is False


def test_desktop_capture_refuses_an_unauthorized_window() -> None:
    client = _client(_desktop=None)
    with pytest.raises(XdbgRpcError) as exc:
        client.desktop_capture(0x1, allowed_pids=frozenset({1}), output_path="/tmp/x.bmp")
    assert exc.value.code == "window_not_authorized"


def test_desktop_capture_falls_back_to_a_direct_capture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        windows, "list_input_desktop_windows", lambda *, allowed_pids=None: [{"hwnd": 0x1}]
    )
    captured: list[Any] = []

    def fake_capture(hwnd: int, allowed_pids: Any, output_path: Any) -> JsonObject:
        captured.append((hwnd, allowed_pids, output_path))
        return {"path": str(output_path)}

    monkeypatch.setattr(ui_win32, "capture_hwnd_screenshot", fake_capture)
    client = _client(_desktop=None)
    target = tmp_path / "shot.bmp"
    out = client.desktop_capture(0x1, allowed_pids=frozenset({1}), output_path=target)
    assert out == {"path": str(target)}
    assert captured == [(0x1, frozenset({1}), target)]
