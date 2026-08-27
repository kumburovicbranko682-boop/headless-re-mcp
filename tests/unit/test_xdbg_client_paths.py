"""Cross-platform arms of the x64dbg RPC client.

The named-pipe transport (``_NamedPipeTransport``) is Windows-only ctypes and
cannot run here, but the client's request dispatch, trace-result validation,
event/window/log bookkeeping, reconnect handshake and teardown are all plain
Python. The existing suite pins a handful of those; this drives the rest --
every thin RPC wrapper, the trace validator's branch matrix, the diagnostics
and process-teardown helpers, the reconnect/handshake mismatch arms, and the
``_request`` response-envelope guards -- with fake processes and transports.
"""

from __future__ import annotations

import json
import subprocess
from collections import deque
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Lock, RLock
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.client as client_module
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.core.models import Architecture

JsonObject = dict[str, Any]


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #


class FakeStdin:
    def __init__(self, events: list[str], *, fail: BaseException | None = None) -> None:
        self.events = events
        self.value = ""
        self.closed = False
        self._fail = fail

    def write(self, value: str) -> int:
        if self._fail is not None:
            raise self._fail
        self.events.append(f"stdin.write:{value.rstrip()}")
        self.value += value
        return len(value)

    def flush(self) -> None:
        self.events.append("stdin.flush")

    def close(self) -> None:
        self.events.append("stdin.close")
        self.closed = True


class FakeProcess:
    def __init__(
        self,
        events: list[str] | None = None,
        *,
        stdin_fail: BaseException | None = None,
        wait_raises: bool = False,
    ) -> None:
        self.pid = 9911
        self.returncode: int | None = None
        self.events = events if events is not None else []
        self.stdin: FakeStdin | None = FakeStdin(self.events, fail=stdin_fail)
        self._wait_raises = wait_raises

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self._wait_raises:
            raise subprocess.TimeoutExpired(cmd="x64dbg", timeout=1.0)
        self.events.append("process.wait")
        self.returncode = 0
        return 0


class FakeThread:
    def __init__(self) -> None:
        self.joined = False

    def join(self, timeout: float | None = None) -> None:
        del timeout
        self.joined = True


class EnvelopeTransport:
    """Answers every request with a correct envelope and per-method result."""

    def __init__(self, results: dict[str, JsonObject] | None = None) -> None:
        self.results = results or {}
        self.methods: list[str] = []
        self.closed = False
        self._reads: deque[bytes] = deque()

    def write_all(self, data: bytes, *, timeout: float) -> None:
        del timeout
        request = json.loads(data[4:])
        self.methods.append(request["method"])
        result = self.results.get(request["method"], {"request_id": request["id"]})
        encoded = json.dumps(
            {
                "protocol": "headless-re-xdbg",
                "version": 1,
                "id": request["id"],
                "ok": True,
                "result": result,
            },
            separators=(",", ":"),
        ).encode()
        self._reads.extend((len(encoded).to_bytes(4, "little"), encoded))

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        del timeout
        value = self._reads.popleft()
        assert len(value) == size
        return value

    def close(self) -> None:
        self.closed = True


class RawBodyTransport:
    """Frames an arbitrary response body so envelope guards can be exercised."""

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False
        self._reads: deque[bytes] = deque()

    def write_all(self, data: bytes, *, timeout: float) -> None:
        del data, timeout
        self._reads.extend((len(self.body).to_bytes(4, "little"), self.body))

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        del timeout
        value = self._reads.popleft()
        assert len(value) == size
        return value

    def close(self) -> None:
        self.closed = True


class FlexHandshake:
    """A handshake transport with tunable server PID, hello PID and payload."""

    def __init__(
        self,
        *,
        server_pid: int,
        hello_pid: int,
        architecture: str = "x64",
        capabilities: list[str] | None = None,
    ) -> None:
        self.server_pid = server_pid
        self._hello_pid = hello_pid
        self._arch = architecture
        self._caps = capabilities
        self.closed = False
        self._reads: deque[bytes] = deque()

    def write_all(self, data: bytes, *, timeout: float) -> None:
        del timeout
        request = json.loads(data[4:])
        result: JsonObject = {"pid": self._hello_pid, "architecture": self._arch}
        if self._caps is not None:
            result["capabilities"] = self._caps
        encoded = json.dumps(
            {
                "protocol": "headless-re-xdbg",
                "version": 1,
                "id": request["id"],
                "ok": True,
                "result": result,
            },
            separators=(",", ":"),
        ).encode()
        self._reads.extend((len(encoded).to_bytes(4, "little"), encoded))

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        del timeout
        value = self._reads.popleft()
        assert len(value) == size
        return value

    def close(self) -> None:
        self.closed = True


def _bare_client() -> XdbgClient:
    client = object.__new__(XdbgClient)
    client._request_id = 0
    client._request_lock = RLock()
    client._closed = False
    client._capabilities = frozenset({"events.read"})
    client._process = FakeProcess()  # type: ignore[assignment]
    client._stdout_log = deque(maxlen=10)
    client._stderr_log = deque(maxlen=10)
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    client._debuggee_pid = None
    client._desktop = None
    return client


def _recording_client() -> tuple[XdbgClient, list[tuple[str, JsonObject | None, float]]]:
    client = _bare_client()
    calls: list[tuple[str, JsonObject | None, float]] = []

    def request(
        method: str, params: JsonObject | None = None, *, timeout: float = 10.0
    ) -> JsonObject:
        calls.append((method, params, timeout))
        return {"echo": method}

    client.request = request  # type: ignore[method-assign]
    return client, calls


# --------------------------------------------------------------------------- #
# thin RPC wrappers
# --------------------------------------------------------------------------- #


def test_memory_and_thread_wrappers_dispatch_expected_rpc() -> None:
    client, calls = _recording_client()
    client.memory_regions(offset=2, limit=10, timeout=5)
    client.memory_regions()
    client.memory_protect_query(0x1004, timeout=7)
    client.memory_protection(0x2000)
    client.memory_protection(0x2000, rights="rw-")
    client.threads_list(offset=1, limit=5, timeout=3)
    client.threads_current()
    client.threads_context_read(7, timeout=4)
    client.threads_context_write(7, "eax", 1, timeout=4)
    assert calls == [
        ("memory.regions", {"offset": 2, "limit": 10}, 5),
        ("memory.regions", {"offset": 0}, 30.0),
        ("memory.protect.query", {"address": 0x1004}, 7),
        ("memory.protection", {"address": 0x2000}, 10.0),
        ("memory.protection", {"address": 0x2000, "rights": "rw-"}, 10.0),
        ("threads.list", {"offset": 1, "limit": 5}, 3),
        ("threads.current", None, 10.0),
        ("threads.context.read", {"tid": 7}, 4),
        ("threads.context.write", {"tid": 7, "name": "eax", "value": 1}, 4),
    ]


def test_stack_disasm_and_symbol_wrappers_dispatch_expected_rpc() -> None:
    client, calls = _recording_client()
    client.stack_read(count=8)
    client.stack_read(address=0x10, count=4)
    client.stack_trace(limit=64, timeout=6)
    client.disassembly_read(0x40, count=3)
    client.symbols_list(0x400000, limit=10, timeout=15)
    client.symbols_resolve("main")
    assert calls == [
        ("stack.read", {"count": 8}, 10.0),
        ("stack.read", {"count": 4, "address": 0x10}, 10.0),
        ("stack.trace", {"limit": 64}, 6),
        ("disassembly.read", {"address": 0x40, "count": 3}, 10.0),
        ("symbols.list", {"module_base": 0x400000, "limit": 10}, 15),
        ("symbols.resolve", {"expression": "main"}, 10.0),
    ]


def test_breakpoint_and_patch_wrappers_dispatch_expected_rpc() -> None:
    client, calls = _recording_client()
    client.breakpoints_hardware_set(0x50, bp_type="w", size=4)
    client.breakpoints_hardware_remove(0x50)
    client.breakpoints_hardware_list()
    client.breakpoints_memory_set(0x60, bp_type="r")
    client.breakpoints_memory_remove(0x60)
    client.breakpoints_memory_list()
    client.breakpoints_condition_set(0x70, "x==1")
    client.breakpoints_condition_get(0x70)
    client.patches_list()
    client.patches_apply(0x80, "90")
    client.patches_restore(0x80)
    assert calls == [
        ("breakpoints.hardware.set", {"address": 0x50, "type": "w", "size": 4}, 10.0),
        ("breakpoints.hardware.remove", {"address": 0x50}, 10.0),
        ("breakpoints.hardware.list", None, 10.0),
        ("breakpoints.memory.set", {"address": 0x60, "type": "r"}, 10.0),
        ("breakpoints.memory.remove", {"address": 0x60}, 10.0),
        ("breakpoints.memory.list", None, 10.0),
        ("breakpoints.condition.set", {"address": 0x70, "expression": "x==1"}, 10.0),
        ("breakpoints.condition.get", {"address": 0x70}, 10.0),
        ("patches.list", None, 10.0),
        ("patches.apply", {"address": 0x80, "data": "90"}, 10.0),
        ("patches.restore", {"address": 0x80}, 10.0),
    ]


def test_module_and_import_wrappers_dispatch_expected_rpc() -> None:
    client, calls = _recording_client()
    out = str(Path("/tmp/mod.bin"))
    hdr = str(Path("/tmp/h.bin"))
    client.modules_dump(0x400000, "/tmp/mod.bin", size=0x1000, timeout=9)
    client.modules_dump(0x400000, "/tmp/mod.bin")
    client.pe_headers_runtime(0x400000)
    client.pe_headers_runtime(0x400000, output_path="/tmp/h.bin")
    client.imports_scan(0x400000)
    client.imports_scan(
        0x400000, search_start=1, search_size=2, max_candidates=3, mode="strict"
    )
    client.imports_read(0x1000, 16)
    assert calls == [
        ("modules.dump", {"base": 0x400000, "output_path": out, "size": 0x1000}, 9),
        ("modules.dump", {"base": 0x400000, "output_path": out}, 60.0),
        ("pe.headers.runtime", {"base": 0x400000}, 30.0),
        ("pe.headers.runtime", {"base": 0x400000, "output_path": hdr}, 30.0),
        ("imports.scan", {"module_base": 0x400000}, 60.0),
        (
            "imports.scan",
            {
                "module_base": 0x400000,
                "search_start": 1,
                "search_size": 2,
                "max_candidates": 3,
                "mode": "strict",
            },
            60.0,
        ),
        ("imports.read", {"iat_va": 0x1000, "size": 16}, 30.0),
    ]


# --------------------------------------------------------------------------- #
# trace_start validation and _validate_trace_result
# --------------------------------------------------------------------------- #


def _valid_trace_result(path: str, **over: Any) -> JsonObject:
    base: JsonObject = {
        "recording": True,
        "path": path,
        "max_events": 5,
        "timeout_ms": 1000,
        "max_file_bytes": 4096,
        "events_written": 0,
        "file_bytes": 0,
        "elapsed_ms": 0,
        "stop_reason": "none",
    }
    base.update(over)
    return base


def test_trace_start_stop_and_status_validate_and_return(tmp_path: Path) -> None:
    client = _bare_client()
    trace = tmp_path / "t.bin"

    def request(method: str, params: JsonObject | None = None, *, timeout: float) -> JsonObject:
        if method == "trace.start":
            return _valid_trace_result(str(trace))
        if method == "trace.stop":
            return _valid_trace_result(str(trace), recording=False)
        if method == "trace.status":
            return _valid_trace_result(str(trace), recording=False)
        raise AssertionError(method)

    client.request = request  # type: ignore[method-assign]
    started = client.trace_start(trace, max_events=5, timeout_ms=1000, max_file_bytes=4096)
    assert started["recording"] is True
    assert client.trace_stop()["recording"] is False
    assert client.trace_status()["recording"] is False
    assert client.trace_cancel()["recording"] is False


def test_trace_status_skips_validation_when_uninitialized() -> None:
    client = _bare_client()
    client.request = lambda method, params=None, *, timeout=10.0: {"initialized": False}  # type: ignore[method-assign,assignment]
    assert client.trace_status() == {"initialized": False}


@pytest.mark.parametrize(
    ("kwargs",),
    [
        ({"max_events": 0},),
        ({"max_events": 2_000_000},),
        ({"timeout_ms": 0},),
        ({"timeout_ms": 4_000_000},),
        ({"max_file_bytes": 0},),
        ({"max_file_bytes": 512 * 1024 * 1024},),
    ],
)
def test_trace_start_rejects_out_of_range_bounds(tmp_path: Path, kwargs: JsonObject) -> None:
    client = _bare_client()
    client.request = lambda *a, **k: {}  # type: ignore[method-assign,assignment]
    with pytest.raises(ValueError):
        client.trace_start(tmp_path / "t.bin", **kwargs)


def test_trace_start_requires_an_absolute_path() -> None:
    client = _bare_client()
    client.request = lambda *a, **k: {}  # type: ignore[method-assign,assignment]
    with pytest.raises(ValueError, match="absolute"):
        client.trace_start("relative/trace.bin")


def test_validate_trace_result_rejects_non_boolean_recording() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result({"recording": "yes"})
    assert exc.value.code == "rpc_protocol_error"


def test_validate_trace_result_rejects_unexpected_recording_state() -> None:
    with pytest.raises(XdbgRpcError) as exc:
        XdbgClient._validate_trace_result({"recording": False}, recording=True)
    assert "unexpected trace recording state" in str(exc.value)


def test_validate_trace_result_rejects_an_invalid_path(tmp_path: Path) -> None:
    result = _valid_trace_result("\x00not-a-path")
    with pytest.raises(XdbgRpcError, match="invalid trace path"):
        XdbgClient._validate_trace_result(result, path=tmp_path / "t.bin")


def test_validate_trace_result_rejects_a_different_path(tmp_path: Path) -> None:
    result = _valid_trace_result(str(tmp_path / "other.bin"))
    with pytest.raises(XdbgRpcError, match="different trace path"):
        XdbgClient._validate_trace_result(result, path=tmp_path / "t.bin")


def test_validate_trace_result_rejects_mismatched_quota(tmp_path: Path) -> None:
    result = _valid_trace_result(str(tmp_path / "t.bin"), max_events=99)
    with pytest.raises(XdbgRpcError, match="max_events"):
        XdbgClient._validate_trace_result(result, path=tmp_path / "t.bin", max_events=5)


def test_validate_trace_result_defaults_and_bounds_counters() -> None:
    result = _valid_trace_result("/tmp/t.bin")
    del result["events_written"]  # missing -> defaulted to 0
    XdbgClient._validate_trace_result(result)
    assert result["events_written"] == 0

    bad = _valid_trace_result("/tmp/t.bin", file_bytes=-1)
    with pytest.raises(XdbgRpcError, match="file_bytes"):
        XdbgClient._validate_trace_result(bad)


def test_validate_trace_result_defaults_missing_stop_reason() -> None:
    result = _valid_trace_result("/tmp/t.bin", stop_reason="")
    XdbgClient._validate_trace_result(result)
    assert result["stop_reason"] == "none"


# --------------------------------------------------------------------------- #
# window / debuggee / log bookkeeping
# --------------------------------------------------------------------------- #


def test_record_observed_windows_dedupes_and_caps() -> None:
    client = _bare_client()
    client._record_observed_windows(["a", "a", "b"])
    assert client.analyzer_windows == ("a", "b")

    over = [f"w{i}" for i in range(client_module._MAX_OBSERVED_WINDOWS + 5)]
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    client._record_observed_windows(over)
    assert len(client._observed_windows) == client_module._MAX_OBSERVED_WINDOWS
    assert client._observed_windows_dropped == 5


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({"process_id": 4321}, 4321),
        ({"process_id": "8765"}, 8765),
        ({"debuggee_pid": 12}, 12),
        ({"process_id": None, "debuggee_pid": 34}, 34),
        ({"process_id": 0}, None),
        ({"process_id": "not-a-number"}, None),
        ({"unrelated": 1}, "unchanged"),
    ],
)
def test_note_debuggee_pid_parses_or_ignores(payload: JsonObject, expected: Any) -> None:
    client = _bare_client()
    client._debuggee_pid = "sentinel"  # type: ignore[assignment]
    client._note_debuggee_pid(payload)
    if expected == "unchanged":
        assert client._debuggee_pid == "sentinel"
    else:
        assert client._debuggee_pid == expected


def test_read_log_appends_until_stream_end(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _bare_client()
    lines = iter(["first", "second", None])
    monkeypatch.setattr(
        client_module, "read_bounded_text_line", lambda stream, *, max_chars: next(lines)
    )
    target: deque[str] = deque()
    client._read_log(object(), target)  # type: ignore[arg-type]
    assert list(target) == ["first", "second"]


def test_describe_analyzer_windows_uses_process_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _bare_client()
    monkeypatch.setattr(client_module, "describe_process_windows", lambda pid: {"b", "a"})
    assert client._describe_analyzer_windows() == ["a", "b"]


def test_describe_analyzer_windows_uses_the_hidden_desktop() -> None:
    client = _bare_client()
    client._desktop = type(
        "D", (), {"process_window_descriptions": staticmethod(lambda pid: ["x64dbg"])}
    )()
    assert client._describe_analyzer_windows() == ["x64dbg"]


def test_monitor_windows_records_and_suppresses(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _bare_client()
    client._desktop = object()
    suppressed: list[bool] = []

    class _StopTwice:
        def __init__(self) -> None:
            self.n = 0

        def wait(self, timeout: float) -> bool:
            self.n += 1
            return self.n > 1

    client._monitor_stop = _StopTwice()  # type: ignore[assignment]
    monkeypatch.setattr(client, "_describe_analyzer_windows", lambda: ["win"])
    monkeypatch.setattr(client, "_suppress_input_desktop_leaks", lambda: suppressed.append(True))
    client._monitor_windows()
    assert client.analyzer_windows == ("win",)
    assert suppressed == [True]


def test_suppress_input_desktop_leaks_includes_debuggee_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _bare_client()
    client._debuggee_pid = 555
    seen: list[set[int]] = []
    monkeypatch.setattr(client_module, "enumerate_direct_children", lambda pid: [777])
    monkeypatch.setattr(
        client_module, "hide_input_desktop_windows_for_pids", lambda pids: seen.append(set(pids))
    )
    client._suppress_input_desktop_leaks()
    assert seen == [{client._process.pid, 555, 777}]


def test_suppress_input_desktop_leaks_without_a_debuggee(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _bare_client()
    client._debuggee_pid = None
    seen: list[set[int]] = []
    monkeypatch.setattr(
        client_module, "hide_input_desktop_windows_for_pids", lambda pids: seen.append(set(pids))
    )
    client._suppress_input_desktop_leaks()
    assert seen == [{client._process.pid}]


# --------------------------------------------------------------------------- #
# diagnostics and process teardown
# --------------------------------------------------------------------------- #


def test_diagnostics_and_process_exit_error() -> None:
    client = _bare_client()
    client._process.returncode = 42
    client._stdout_log.append("out")
    client._stderr_log.append("err")
    client._observed_windows.add("w")
    diag = client._diagnostics()
    assert diag["pid"] == client._process.pid
    assert diag["exit_code"] == 42
    assert diag["stdout"] == ["out"]
    error = client._process_exit_error()
    assert error.code == "worker_exited"
    assert error.retryable is True
    assert error.details["exit_code"] == 42


def test_request_exit_writes_exit_then_closes() -> None:
    client = _bare_client()
    client._request_exit()
    assert client._process.stdin is not None
    assert client._process.stdin.value == "exit\n"
    assert client._process.stdin.closed is True


def test_request_exit_returns_when_the_process_is_gone() -> None:
    client = _bare_client()
    client._process.returncode = 0
    client._request_exit()
    assert client._process.stdin is not None
    assert client._process.stdin.value == ""


def test_request_exit_swallows_a_broken_pipe() -> None:
    client = _bare_client()
    client._process.stdin = FakeStdin([], fail=BrokenPipeError("gone"))
    client._request_exit()  # must not raise


def test_terminate_process_delegates_to_the_tree_killer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _bare_client()
    killed: list[Any] = []
    monkeypatch.setattr(
        client_module, "terminate_process_tree", lambda process, wait_s: killed.append(process)
    )
    client._terminate_process()
    assert killed == [client._process]


def test_finish_threads_joins_and_cleans_up() -> None:
    client = _bare_client()
    client._monitor_stop = Event()
    client._window_thread = FakeThread()  # type: ignore[assignment]
    client._stdout_thread = FakeThread()  # type: ignore[assignment]
    client._stderr_thread = FakeThread()  # type: ignore[assignment]
    closed: list[str] = []
    client._desktop = type("D", (), {"close": lambda self: closed.append("desktop")})()
    client._isolation_job = type("J", (), {"close": lambda self: closed.append("job")})()
    runtime = TemporaryDirectory(prefix="headless-re-xdbg-finish-")
    runtime_path = Path(runtime.name)
    client._user_directory = runtime

    client._finish_threads()

    assert client._monitor_stop.is_set()
    assert client._window_thread.joined and client._stdout_thread.joined
    assert client._stderr_thread.joined
    assert sorted(closed) == ["desktop", "job"]
    assert client._desktop is None and client._isolation_job is None
    assert not runtime_path.exists()


def test_terminate_kills_the_process_and_drops_the_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _bare_client()
    order: list[str] = []
    transport = EnvelopeTransport()
    client._transport = transport  # type: ignore[assignment]
    monkeypatch.setattr(client, "_terminate_process", lambda: order.append("kill"))
    monkeypatch.setattr(client, "_finish_threads", lambda: order.append("finish"))
    client.terminate()
    assert client._closed is True
    assert client._transport is None
    assert transport.closed is True
    assert order == ["kill", "finish"]


def test_close_stops_trace_and_debugging_before_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    transport = EnvelopeTransport(
        {
            "trace.status": {"recording": True},
            "trace.stop": {},
            "debug.state": {"debugging": True, "state": "idle"},
            "debug.stop": {},
        }
    )
    client = _bare_client()
    client._capabilities = frozenset({"trace.status", "trace.stop", "debug.stop"})
    client._transport = transport  # type: ignore[assignment]
    client._process = FakeProcess(events)  # type: ignore[assignment]
    client._monitor_stop = Event()
    client._window_thread = FakeThread()  # type: ignore[assignment]
    client._stdout_thread = FakeThread()  # type: ignore[assignment]
    client._stderr_thread = FakeThread()  # type: ignore[assignment]
    client._user_directory = TemporaryDirectory(prefix="headless-re-xdbg-close-")
    monkeypatch.setattr(client, "_describe_analyzer_windows", lambda: [])

    client.close()

    assert transport.methods == ["trace.status", "trace.stop", "debug.state", "debug.stop"]
    assert client._process.stdin is not None
    assert client._process.stdin.value == "exit\n"
    assert transport.closed is True
    assert client._closed is True


def test_close_is_idempotent() -> None:
    client = _bare_client()
    client._closed = True
    client.close()  # returns immediately without touching the process


def test_close_terminates_a_process_that_will_not_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _bare_client()
    client._capabilities = frozenset()
    transport = EnvelopeTransport({"debug.state": {"debugging": False, "state": "idle"}})
    client._transport = transport  # type: ignore[assignment]
    client._process = FakeProcess(wait_raises=True)  # type: ignore[assignment]
    client._monitor_stop = Event()
    client._user_directory = TemporaryDirectory(prefix="headless-re-xdbg-close2-")
    terminated: list[str] = []
    monkeypatch.setattr(client, "_describe_analyzer_windows", lambda: [])
    monkeypatch.setattr(client, "_terminate_process", lambda: terminated.append("kill"))
    monkeypatch.setattr(client, "_finish_threads", lambda: None)

    client.close()

    assert terminated == ["kill"]
    assert transport.closed is True


# --------------------------------------------------------------------------- #
# reconnect / handshake mismatch arms
# --------------------------------------------------------------------------- #


def _reconnect_client(monkeypatch: pytest.MonkeyPatch, transport: Any) -> XdbgClient:
    client = _bare_client()
    client._transport = None
    client._pipe_name = r"\\.\pipe\headless-re-test"
    client._token = "token"
    client._architecture = Architecture.X64
    client._startup_timeout = 5.0
    monkeypatch.setattr(client, "_describe_analyzer_windows", lambda: [])
    monkeypatch.setattr(
        client_module._NamedPipeTransport,
        "connect",
        classmethod(lambda cls, pipe_name, *, timeout, process: transport),
    )
    return client


def test_reconnect_refuses_when_closed() -> None:
    client = _bare_client()
    client._closed = True
    with pytest.raises(XdbgRpcError, match="closed"):
        client.reconnect()


def test_reconnect_reports_a_dead_worker() -> None:
    client = _bare_client()
    client._transport = None
    client._process.returncode = 7
    with pytest.raises(XdbgRpcError) as exc:
        client.reconnect()
    assert exc.value.code == "worker_exited"


def test_reconnect_is_a_noop_when_already_connected() -> None:
    client = _bare_client()
    client._transport = EnvelopeTransport()  # type: ignore[assignment]
    client.reconnect()  # transport present -> returns without rebuilding
    assert client.transport_connected is True


def test_reconnect_rebuilds_and_refreshes_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pid = 9911
    transport = FlexHandshake(server_pid=pid, hello_pid=pid, capabilities=["events.read", "trace"])
    client = _reconnect_client(monkeypatch, transport)
    client.reconnect()
    assert client.transport_connected is True
    assert client._capabilities == frozenset({"events.read", "trace"})


def test_reconnect_rejects_non_array_capabilities(monkeypatch: pytest.MonkeyPatch) -> None:
    pid = 9911
    transport = FlexHandshake(server_pid=pid, hello_pid=pid, capabilities=None)
    client = _reconnect_client(monkeypatch, transport)
    with pytest.raises(XdbgRpcError, match="capabilities must be an array"):
        client.reconnect()


def test_connect_transport_rejects_a_server_pid_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FlexHandshake(server_pid=1, hello_pid=1, capabilities=["events.read"])
    client = _reconnect_client(monkeypatch, transport)  # process.pid is 9911
    with pytest.raises(XdbgRpcError) as exc:
        client.reconnect()
    assert exc.value.code == "rpc_peer_mismatch"
    assert transport.closed is True
    assert client._transport is None


def test_connect_transport_rejects_a_hello_pid_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FlexHandshake(server_pid=9911, hello_pid=1, capabilities=["events.read"])
    client = _reconnect_client(monkeypatch, transport)
    with pytest.raises(XdbgRpcError) as exc:
        client.reconnect()
    assert exc.value.code == "rpc_peer_mismatch"


def test_connect_transport_rejects_an_architecture_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FlexHandshake(
        server_pid=9911, hello_pid=9911, architecture="x86", capabilities=["events.read"]
    )
    client = _reconnect_client(monkeypatch, transport)
    with pytest.raises(XdbgRpcError) as exc:
        client.reconnect()
    assert exc.value.code == "architecture_mismatch"


# --------------------------------------------------------------------------- #
# _request response-envelope guards
# --------------------------------------------------------------------------- #


def _raw_client(body: bytes) -> XdbgClient:
    client = _bare_client()
    client._transport = RawBodyTransport(body)  # type: ignore[assignment]
    return client


def test_request_rejects_a_missing_transport() -> None:
    client = _bare_client()
    client._transport = None
    with pytest.raises(XdbgRpcError, match="transport is unavailable"):
        client._request("debug.state", {}, timeout=1)


def test_request_rejects_a_non_positive_timeout() -> None:
    client = _raw_client(b"{}")
    with pytest.raises(ValueError, match="timeout must be positive"):
        client._request("debug.state", {}, timeout=0)


def test_request_rejects_non_utf8_json_body() -> None:
    client = _raw_client(b"\xff\xfe")
    with pytest.raises(XdbgRpcError, match="not valid UTF-8 JSON"):
        client._request("debug.state", {}, timeout=1)


def test_request_rejects_a_non_object_response() -> None:
    client = _raw_client(b"[]")
    with pytest.raises(XdbgRpcError, match="must be an object"):
        client._request("debug.state", {}, timeout=1)


def test_request_rejects_a_bad_envelope() -> None:
    body = json.dumps(
        {"protocol": "wrong", "version": 1, "id": "1", "ok": True, "result": {}}
    ).encode()
    client = _raw_client(body)
    with pytest.raises(XdbgRpcError, match="envelope is invalid"):
        client._request("debug.state", {}, timeout=1)


def test_request_rejects_a_non_object_result() -> None:
    body = json.dumps(
        {"protocol": "headless-re-xdbg", "version": 1, "id": "1", "ok": True, "result": []}
    ).encode()
    client = _raw_client(body)
    with pytest.raises(XdbgRpcError, match="result must be an object"):
        client._request("debug.state", {}, timeout=1)


def test_request_notes_the_debuggee_pid_from_a_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = json.dumps(
        {
            "protocol": "headless-re-xdbg",
            "version": 1,
            "id": "1",
            "ok": True,
            "result": {"process_id": 24680},
        }
    ).encode()
    client = _raw_client(body)
    monkeypatch.setattr(client, "_describe_analyzer_windows", lambda: [])
    result = client._request("debug.state", {}, timeout=1)
    assert result == {"process_id": 24680}
    assert client._debuggee_pid == 24680
