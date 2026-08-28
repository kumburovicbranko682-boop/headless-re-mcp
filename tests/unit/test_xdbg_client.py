from __future__ import annotations

import ctypes
import json
import time
from collections import deque
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Lock, RLock
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.client as client_module
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.core.events import DebugEvent, DebugEventBatch
from headless_re_mcp.core.models import Architecture

JsonObject = dict[str, Any]


class FakeProcess:
    def __init__(self, events: list[str] | None = None) -> None:
        self.pid = 9911
        self.returncode: int | None = None
        self.events = events if events is not None else []
        self.stdin = FakeStdin(self.events)

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.events.append("process.wait")
        self.returncode = 0
        return 0


class FakeStdin:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.value = ""
        self.closed = False

    def write(self, value: str) -> int:
        self.events.append(f"stdin.write:{value.rstrip()}")
        self.value += value
        return len(value)

    def flush(self) -> None:
        self.events.append("stdin.flush")

    def close(self) -> None:
        self.events.append("stdin.close")
        self.closed = True


class ScriptedTransport:
    def __init__(
        self,
        response: JsonObject | None = None,
        *,
        fail: BaseException | None = None,
        response_size: int | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.response = response
        self.fail = fail
        self.response_size = response_size
        self.events = events if events is not None else []
        self.requests: list[JsonObject] = []
        self.writes: list[bytes] = []
        self._reads: deque[bytes] = deque()
        self.closed = False

    def write_all(self, data: bytes, *, timeout: float) -> None:
        del timeout
        if self.fail is not None:
            raise self.fail
        self.events.append("transport.write")
        self.writes.append(data)
        size = int.from_bytes(data[:4], "little")
        assert size == len(data) - 4
        request = json.loads(data[4:])
        assert isinstance(request, dict)
        self.requests.append(request)

        response = self.response or {
            "protocol": "headless-re-xdbg",
            "version": 1,
            "id": request["id"],
            "ok": True,
            "result": {"request_id": request["id"]},
        }
        encoded = json.dumps(response, separators=(",", ":")).encode()
        encoded_size = len(encoded) if self.response_size is None else self.response_size
        self._reads.extend((encoded_size.to_bytes(4, "little"), encoded))

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        del timeout
        if self.fail is not None:
            raise self.fail
        value = self._reads.popleft()
        assert len(value) == size
        return value

    def close(self) -> None:
        self.events.append("transport.close")
        self.closed = True


class FakeThread:
    def __init__(self) -> None:
        self.joined = False

    def join(self, timeout: float | None = None) -> None:
        del timeout
        self.joined = True


def _client(transport: ScriptedTransport, process: FakeProcess | None = None) -> XdbgClient:
    client = object.__new__(XdbgClient)
    client._request_id = 0
    client._request_lock = RLock()
    client._closed = False
    client._capabilities = frozenset({"events.read"})
    client._transport = transport  # type: ignore[assignment]
    client._process = process or FakeProcess()  # type: ignore[assignment]
    client._stdout_log = deque(maxlen=10)
    client._stderr_log = deque(maxlen=10)
    client._window_lock = Lock()
    client._observed_windows = set()
    client._observed_windows_dropped = 0
    return client


def _event_result(*, next_cursor: int = 1) -> JsonObject:
    events: list[JsonObject] = []
    if next_cursor:
        events.append(
            {
                "sequence": next_cursor,
                "timestamp_unix_ms": 1_700_000_000_000,
                "source": "x64dbg.plugin_callback",
                "kind": "debug.paused",
                "data": {},
            }
        )
    return {
        "events": events,
        "count": len(events),
        "cursor": 0,
        "next_cursor": next_cursor,
        "oldest_sequence": next_cursor,
        "latest_sequence": next_cursor,
        "dropped": 0,
        "dropped_total": 0,
        "has_more": False,
        "capacity": 1024,
    }


def _success_response(result: JsonObject) -> JsonObject:
    return {
        "protocol": "headless-re-xdbg",
        "version": 1,
        "id": "1",
        "ok": True,
        "result": result,
    }


class ReplayTransport:
    """A transport that returns one caller-supplied response frame verbatim."""

    def __init__(self, response_frame: bytes) -> None:
        self._reads: deque[bytes] = deque()
        self._frame = response_frame
        self.closed = False

    def write_all(self, data: bytes, *, timeout: float) -> None:
        del data, timeout
        self._reads.append(self._frame[:4])
        self._reads.append(self._frame[4:])

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        del timeout
        value = self._reads.popleft()
        assert len(value) == size
        return value

    def close(self) -> None:
        self.closed = True


def test_request_maps_a_deeply_nested_response_to_a_protocol_error() -> None:
    """The live decode path shares the fuzz target's recursion gap.

    request() reads a size-prefixed frame off the pipe and json.loads it under
    an ``except (UnicodeDecodeError, json.JSONDecodeError)`` that does not name
    RecursionError. The frame cap is 8 MiB, so a 200 KB array nested past the C
    decoder's ceiling parses under the limit yet raises RecursionError, which
    escaped request() and _failure filed it as an internal incident instead of
    the clean rpc_protocol_error a malformed frame is supposed to produce.
    """
    depth = 100_000
    body = (b"[" * depth) + (b"]" * depth)
    frame = len(body).to_bytes(4, "little") + body
    assert len(frame) - 4 <= client_module._MAX_FRAME_BYTES
    client = _client(ReplayTransport(frame))  # type: ignore[arg-type]

    with pytest.raises(XdbgRpcError) as exc_info:
        client._request("debug.state", {}, timeout=1)
    assert exc_info.value.code == "rpc_protocol_error"


def test_request_frames_are_bounded_and_ids_are_monotonic() -> None:
    transport = ScriptedTransport()
    client = _client(transport)

    assert client._request("debug.state", {}, timeout=1) == {"request_id": "1"}
    assert client._request("debug.state", {}, timeout=1) == {"request_id": "2"}
    assert [request["id"] for request in transport.requests] == ["1", "2"]
    assert all(
        int.from_bytes(frame[:4], "little") == len(frame) - 4 for frame in transport.writes
    )

    with pytest.raises(XdbgRpcError, match="frame limit") as exc_info:
        client._request(
            "memory.write",
            {"data": "0" * client_module._MAX_FRAME_BYTES},
            timeout=1,
        )
    assert exc_info.value.code == "request_too_large"
    assert len(transport.writes) == 2


def test_a_window_blocks_the_call_only_while_it_is_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dismissed dialog must not retire a worker that is headless again.

    The passive monitor records windows the request path never saw, so latching
    on the cumulative set meant one dialog x64dbg opened and closed on its own
    turned every later call into analyzer_window_detected, which the service
    treats as fatal. The cumulative set still has to keep the sighting, because
    that is what the zero-window gates assert on.
    """
    client = _client(ScriptedTransport())
    visible: list[str] = []
    monkeypatch.setattr(client, "_describe_analyzer_windows", lambda: list(visible))

    client._observe_windows()

    visible.append("x64dbg [Modules]")
    with pytest.raises(XdbgRpcError) as exc_info:
        client._observe_windows()
    assert exc_info.value.code == "analyzer_window_detected"

    visible.clear()
    client._observe_windows()

    # The sighting survives for the gates even though calls work again.
    assert client.analyzer_windows == ("x64dbg [Modules]",)


@pytest.mark.parametrize("response_size", [0, client_module._MAX_FRAME_BYTES + 1])
def test_invalid_response_frame_boundary_is_rejected(response_size: int) -> None:
    client = _client(ScriptedTransport(response_size=response_size))

    with pytest.raises(XdbgRpcError) as exc_info:
        client._request("debug.state", {}, timeout=1)
    assert exc_info.value.code == "rpc_protocol_error"


def test_wrong_response_id_is_rejected() -> None:
    client = _client(
        ScriptedTransport(
            {
                "protocol": "headless-re-xdbg",
                "version": 1,
                "id": "unexpected",
                "ok": True,
                "result": {},
            }
        )
    )

    with pytest.raises(XdbgRpcError) as exc_info:
        client._request("debug.state", {}, timeout=1)
    assert exc_info.value.code == "rpc_protocol_error"


def test_structured_authentication_error_is_preserved() -> None:
    client = _client(
        ScriptedTransport(
            {
                "protocol": "headless-re-xdbg",
                "version": 1,
                "id": "1",
                "ok": False,
                "error": {
                    "code": "authentication_failed",
                    "message": "RPC token is invalid",
                    "details": {"field": "token"},
                    "retryable": False,
                },
            }
        )
    )

    with pytest.raises(XdbgRpcError) as exc_info:
        client._request("rpc.hello", {"token": "wrong"}, timeout=1)
    error = exc_info.value
    assert error.code == "authentication_failed"
    assert error.details == {"field": "token"}
    assert error.retryable is False


class BudgetTransport(ScriptedTransport):
    """Records the timeout each I/O was granted, and can burn wall time."""

    def __init__(self, *, write_cost: float = 0.0) -> None:
        super().__init__()
        self.write_cost = write_cost
        self.grants: list[float] = []

    def write_all(self, data: bytes, *, timeout: float) -> None:
        self.grants.append(timeout)
        if self.write_cost:
            time.sleep(self.write_cost)
        super().write_all(data, timeout=timeout)

    def read_exact(self, size: int, *, timeout: float) -> bytes:
        self.grants.append(timeout)
        return super().read_exact(size, timeout=timeout)


def test_one_call_spends_its_timeout_once_not_once_per_io() -> None:
    """The write, the length read and the body read each got the full budget.

    Three independent deadlines mean a caller asking for ten seconds can wait
    thirty, so every bound in the tool catalog was worth three times what it
    said. The IDA worker already runs one deadline across its whole exchange.
    """
    transport = BudgetTransport(write_cost=0.10)
    client = _client(transport)

    assert client._request("debug.state", {}, timeout=2.0) == {"request_id": "1"}

    assert len(transport.grants) == 3, "write, length read and body read"
    # Starting the shared monotonic deadline necessarily spends a few
    # microseconds before the first I/O receives its remaining budget.
    assert 1.99 < transport.grants[0] <= 2.0
    assert transport.grants[1] < 1.95, "the read must inherit what the write left"
    assert transport.grants[2] <= transport.grants[1], "the budget only shrinks"


def test_a_call_cannot_outlive_the_timeout_it_was_given() -> None:
    """Spending the budget on the write leaves nothing to wait for a reply."""
    transport = BudgetTransport(write_cost=0.20)
    client = _client(transport)

    started = time.monotonic()
    with pytest.raises(XdbgRpcError) as exc_info:
        client._request("debug.state", {}, timeout=0.05)
    elapsed = time.monotonic() - started

    assert exc_info.value.code == "rpc_transport_error"
    assert transport.closed, "a channel abandoned mid-exchange must not be reused"
    assert elapsed < 1.0, f"the call ran {elapsed:.2f}s past a 0.05s budget"


def test_transport_timeout_closes_the_failed_channel() -> None:
    transport = ScriptedTransport(fail=TimeoutError("deadline expired"))
    client = _client(transport)

    with pytest.raises(XdbgRpcError) as exc_info:
        client._request("debug.state", {}, timeout=0.01)
    assert exc_info.value.code == "rpc_transport_error"
    assert client._transport is None
    assert transport.closed


def test_abnormal_process_exit_has_worker_diagnostics() -> None:
    transport = ScriptedTransport(fail=BrokenPipeError("peer closed"))
    process = FakeProcess()
    process.returncode = 73
    client = _client(transport, process)

    with pytest.raises(XdbgRpcError) as exc_info:
        client._request("debug.state", {}, timeout=1)
    error = exc_info.value
    assert error.code == "worker_exited"
    assert error.details["pid"] == process.pid
    assert error.details["exit_code"] == 73


def test_read_events_uses_narrow_method_and_validates_response() -> None:
    transport = ScriptedTransport(_success_response(_event_result()))
    client = _client(transport)

    batch = client.read_events(0, limit=17, timeout=2.0)

    assert batch.next_cursor == 1
    assert [event.kind for event in batch.events] == ["debug.paused"]
    assert transport.requests[0]["method"] == "events.read"
    assert transport.requests[0]["params"] == {"cursor": 0, "limit": 17}


@pytest.mark.parametrize(
    ("cursor", "limit"),
    [(-1, 100), (True, 100), (1 << 63, 100), (0, 0), (0, 257), (0, True)],
)
def test_read_events_rejects_invalid_bounds_before_transport(
    cursor: int,
    limit: int,
) -> None:
    transport = ScriptedTransport()
    client = _client(transport)

    with pytest.raises(ValueError):
        client.read_events(cursor, limit=limit)

    assert transport.requests == []


def test_read_events_preserves_native_structured_error() -> None:
    client = _client(
        ScriptedTransport(
            {
                "protocol": "headless-re-xdbg",
                "version": 1,
                "id": "1",
                "ok": False,
                "error": {
                    "code": "invalid_cursor",
                    "message": "event cursor is ahead of the current stream",
                    "details": {"cursor": 9, "latest_sequence": 3},
                    "retryable": False,
                },
            }
        )
    )

    with pytest.raises(XdbgRpcError) as exc_info:
        client.read_events(9)

    assert exc_info.value.code == "invalid_cursor"
    assert exc_info.value.details == {"cursor": 9, "latest_sequence": 3}


def test_read_events_upgrades_malformed_batch_to_protocol_error() -> None:
    malformed = _event_result()
    malformed["next_cursor"] = 0
    client = _client(ScriptedTransport(_success_response(malformed)))

    with pytest.raises(XdbgRpcError) as exc_info:
        client.read_events(0)

    assert exc_info.value.code == "rpc_protocol_error"
    assert "invalid event batch" in str(exc_info.value)


def test_wait_for_state_samples_state_after_transition_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = object.__new__(XdbgClient)
    operations: list[str] = []
    transition_observed = False
    states = iter(({"state": "running"}, {"state": "paused"}))

    def read_events(
        cursor: int,
        *,
        limit: int,
        timeout: float,
    ) -> DebugEventBatch:
        nonlocal transition_observed
        del limit, timeout
        assert cursor == 11
        operations.append("events.read")
        transition_observed = True
        return DebugEventBatch(
            events=(
                DebugEvent(
                    sequence=12,
                    timestamp_unix_ms=1_700_000_000_000,
                    source="x64dbg.plugin_callback",
                    kind="debug.resumed",
                    data={},
                ),
            ),
            cursor=11,
            next_cursor=12,
            oldest_sequence=1,
            latest_sequence=12,
            dropped=0,
            dropped_total=0,
            has_more=False,
            capacity=1024,
        )

    def request(
        method: str,
        params: JsonObject | None = None,
        *,
        timeout: float,
    ) -> JsonObject:
        del params, timeout
        assert method == "debug.state"
        assert transition_observed
        operations.append("debug.state")
        return next(states)

    monkeypatch.setattr(client, "read_events", read_events)
    monkeypatch.setattr(client, "request", request)
    monkeypatch.setattr(client_module.time, "sleep", lambda _: None)

    state = client.wait_for_state(
        {"paused", "idle"},
        timeout=1.0,
        after_event_sequence=11,
        transition_event_kinds=frozenset({"debug.resumed"}),
    )

    assert state == {"state": "paused"}
    assert operations == ["events.read", "debug.state", "debug.state"]


def test_wait_for_state_does_not_treat_a_dropped_batch_as_the_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = object.__new__(XdbgClient)

    def read_events(
        cursor: int,
        *,
        limit: int,
        timeout: float,
    ) -> DebugEventBatch:
        del limit, timeout
        return DebugEventBatch(
            events=(),
            cursor=cursor,
            next_cursor=cursor + 8,
            oldest_sequence=9,
            latest_sequence=16,
            dropped=8,
            dropped_total=8,
            has_more=False,
            capacity=1024,
        )

    def request(
        method: str,
        params: JsonObject | None = None,
        *,
        timeout: float,
    ) -> JsonObject:
        del params, timeout
        assert method == "debug.state"
        return {"state": "paused"}

    now = [0.0]

    def fake_monotonic() -> float:
        now[0] += 0.6
        return now[0]

    client._process = FakeProcess()
    client._stdout_log = deque()
    client._stderr_log = deque()
    monkeypatch.setattr(client, "_diagnostics", lambda: {})
    monkeypatch.setattr(client, "read_events", read_events)
    monkeypatch.setattr(client, "request", request)
    monkeypatch.setattr(client_module.time, "sleep", lambda _: None)
    monkeypatch.setattr(client_module.time, "monotonic", fake_monotonic)

    with pytest.raises(XdbgRpcError) as exc_info:
        client.wait_for_state(
            {"paused", "idle"},
            timeout=1.0,
            after_event_sequence=8,
            transition_event_kinds=frozenset({"debug.resumed"}),
        )

    assert exc_info.value.code == "debug_state_timeout"


def test_close_sends_exit_before_disconnecting_and_cleans_runtime_directory() -> None:
    events: list[str] = []
    transport = ScriptedTransport(
        {
            "protocol": "headless-re-xdbg",
            "version": 1,
            "id": "1",
            "ok": True,
            "result": {"debugging": False, "state": "idle"},
        },
        events=events,
    )
    process = FakeProcess(events)
    runtime_directory = TemporaryDirectory(prefix="headless-re-xdbg-client-unit-")
    runtime_path = Path(runtime_directory.name)
    client = _client(transport, process)
    client._request_lock = RLock()
    client._closed = False
    client._monitor_stop = Event()
    client._user_directory = runtime_directory
    client._window_thread = FakeThread()  # type: ignore[assignment]
    client._stdout_thread = FakeThread()  # type: ignore[assignment]
    client._stderr_thread = FakeThread()  # type: ignore[assignment]

    client.close()

    assert process.stdin.value == "exit\n"
    assert process.returncode == 0
    assert transport.closed
    assert events.index("stdin.write:exit") < events.index("process.wait")
    assert events.index("process.wait") < events.index("transport.close")
    assert not runtime_path.exists()
    assert client.exit_code == 0
def test_memory_regions_and_modules_dump_helpers_dispatch_expected_rpc() -> None:
    client = object.__new__(XdbgClient)
    calls: list[tuple[str, JsonObject, float]] = []

    def request(
        method: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 10.0,
    ) -> JsonObject:
        payload = params or {}
        calls.append((method, payload, timeout))
        return {"method": method, **payload}

    client.request = request  # type: ignore[method-assign]

    regions = client.memory_regions(offset=2, limit=10, timeout=5)
    protect = client.memory_protect_query(0x1004, timeout=7)
    dumped = client.modules_dump(
        0x400000, Path(r"C:\sample\tmp\mod.bin"), size=0x1000, timeout=9
    )

    assert regions["method"] == "memory.regions"
    assert protect["address"] == 0x1004
    assert dumped["output_path"] == r"C:\sample\tmp\mod.bin"
    assert calls == [
        ("memory.regions", {"offset": 2, "limit": 10}, 5),
        ("memory.protect.query", {"address": 0x1004}, 7),
        (
            "modules.dump",
            {"base": 0x400000, "output_path": r"C:\sample\tmp\mod.bin", "size": 0x1000},
            9,
        ),
    ]


class HandshakeTransport:
    """A transport that answers the handshake and records the methods it saw."""

    def __init__(self, *, pid: int, architecture: str = "x64") -> None:
        self.server_pid = pid
        self.architecture = architecture
        self.methods: list[str] = []
        self.closed = False
        self._reads: deque[bytes] = deque()

    def write_all(self, data: bytes, *, timeout: float) -> None:
        del timeout
        request = json.loads(data[4:])
        self.methods.append(request["method"])
        if request["method"] == "rpc.hello":
            result: JsonObject = {
                "pid": self.server_pid,
                "architecture": self.architecture,
                "capabilities": ["events.read"],
            }
        else:
            result = {"request_id": request["id"]}
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


def _prepare_reconnect(client: XdbgClient) -> None:
    client._pipe_name = r"\\.\pipe\headless-re-test"
    client._token = "token"
    client._architecture = Architecture.X64
    client._startup_timeout = 5.0


def test_transport_fault_heals_on_the_next_request_without_replaying_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    client = _client(ScriptedTransport(fail=TimeoutError("named-pipe read timed out")), process)
    _prepare_reconnect(client)

    with pytest.raises(XdbgRpcError) as failure:
        client.request("events.read")

    assert failure.value.code == "rpc_transport_error"
    # The worker outlived the fault, so the caller can expect a later call to work.
    assert failure.value.retryable is True
    assert client.transport_connected is False

    healed = HandshakeTransport(pid=process.pid)
    monkeypatch.setattr(
        client_module._NamedPipeTransport,
        "connect",
        classmethod(lambda cls, pipe_name, *, timeout, process: healed),
    )

    result = client.request("events.read")

    assert result["request_id"]
    assert client.transport_connected is True
    # Replaying the failed call would run a state-changing operation twice, so
    # only the handshake and the new call may reach the rebuilt connection.
    assert healed.methods == ["rpc.hello", "events.read"]


def test_reconnect_refuses_once_the_worker_is_gone() -> None:
    process = FakeProcess()
    client = _client(ScriptedTransport(fail=TimeoutError("named-pipe read timed out")), process)
    _prepare_reconnect(client)

    with pytest.raises(XdbgRpcError):
        client.request("events.read")
    process.returncode = 1

    with pytest.raises(XdbgRpcError) as failure:
        client.reconnect()

    # Rebuilding a connection to a dead worker would hang until the pipe timeout
    # and then report a transport problem instead of the real cause.
    assert failure.value.code == "worker_exited"


def test_named_pipe_timeout_does_not_wait_forever_after_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CancelIoEx then WaitForSingleObject(INFINITE) held the request lock.

    Measured: when cancel returned 0 the waiter never came back. A timed-out
    read then pinned every later RPC on that client for the process life.
    """
    waits: list[int] = []

    class _Kernel:
        def ResetEvent(self, event: object) -> int:
            del event
            return 1

        def WaitForSingleObject(self, event: object, milliseconds: int) -> int:
            del event
            waits.append(int(milliseconds))
            return client_module._NamedPipeTransport._WAIT_TIMEOUT

        def CancelIoEx(self, handle: object, overlapped: object) -> int:
            del handle, overlapped
            return 0

    monkeypatch.setattr(
        client_module.ctypes,
        "get_last_error",
        lambda: 997,
        raising=False,
    )

    transport = client_module._NamedPipeTransport.__new__(
        client_module._NamedPipeTransport
    )
    transport._kernel32 = _Kernel()  # type: ignore[method-assign]
    transport._handle = 1
    transport._event = 1
    transport._closed = False
    transport._CANCEL_WAIT_MS = 50

    buffer = ctypes.create_string_buffer(4)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="named-pipe I/O timed out"):
        transport._run_io(lambda *_args: 0, buffer, 4, 0.05)
    elapsed = time.monotonic() - started

    assert elapsed < 2.0
    assert len(waits) == 2
    assert waits[0] != 0xFFFFFFFF
    assert waits[1] == 50
    assert waits[1] != 0xFFFFFFFF
