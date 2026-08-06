from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Lock, RLock
from typing import Any

import pytest

import headless_re_mcp.backends.x64dbg.client as client_module
from headless_re_mcp.backends.x64dbg.client import XdbgClient, XdbgRpcError
from headless_re_mcp.core.events import DebugEvent, DebugEventBatch

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
