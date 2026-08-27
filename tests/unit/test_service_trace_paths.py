"""Coverage for the bounded-trace service surface (TraceMixin).

trace.* is driven through a real AnalysisService wired to a scriptable
in-process worker, so the full start/stop/status/finalize plumbing runs. The
pure helpers and the odd error arcs are called directly on the service, which
is itself a TraceMixin, with hand-built _TraceArtifactState values.
"""

from __future__ import annotations

from collections import deque
from pathlib import Path
from threading import RLock
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_trace as service_trace
from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.events import DebugEventBatch
from headless_re_mcp.core.models import BackendKind, Session, SessionState
from headless_re_mcp.core.service import AnalysisService, DynamicWorker, JsonObject
from headless_re_mcp.core.service_trace import (
    TraceMixin,
    _instruction_pointer,
    _register_arguments,
    _stack_arguments,
    _TraceArtifactState,
)

_TRACE_CAPS = frozenset(
    {
        "trace.start",
        "trace.stop",
        "trace.status",
        "debug.state",
        "debug.resume",
        "registers.read",
        "stack.read",
        "symbols.resolve",
        "breakpoints.set",
        "breakpoints.remove",
        "events.read",
    }
)


def _write_minimal_pe(path: Path, machine: int = 0x8664) -> None:
    is_x86 = machine == 0x014C
    optional_size = 0xE0 if is_x86 else 0xF0
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    image[0x94:0x96] = optional_size.to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x10B if is_x86 else 0x20B).to_bytes(2, "little")
    base = 0x400000 if is_x86 else 0x140000000
    base_offset = optional + (28 if is_x86 else 24)
    base_size = 4 if is_x86 else 8
    image[base_offset : base_offset + base_size] = base.to_bytes(base_size, "little")
    image[optional + 56 : optional + 60] = (0x4000).to_bytes(4, "little")
    path.write_bytes(image)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        debug_event_background_drain=False,
    )


class TraceWorker:
    """An x64dbg-shaped worker whose trace and debugger replies are scriptable."""

    def __init__(
        self,
        *,
        architecture: str = "x64",
        capabilities: frozenset[str] = _TRACE_CAPS,
        api_address: int = 0x140002000,
    ) -> None:
        self.architecture = architecture
        self._caps = capabilities
        self.api_address = api_address
        self.symbol_address = api_address
        self.trace_path: str | None = None
        self.max_events = 0
        self.timeout_ms = 0
        self.max_file_bytes = 0
        self.write_on_start = True
        self.start_over: JsonObject = {}
        self.stop_over: JsonObject = {}
        self.status_queue: deque[JsonObject] = deque()
        self.fail: dict[str, XdbgRpcError] = {}
        self.registers: JsonObject | None = None
        self.stack_entries: list[JsonObject] | None = None
        self.requests: list[tuple[str, JsonObject]] = []
        self.breakpoints: set[int] = set()
        self.current_state = {"debugging": True, "running": False, "state": "paused"}
        self.closed = False
        self.terminated = False

    @property
    def pid(self) -> int:
        return 7000

    @property
    def capabilities(self) -> frozenset[str]:
        return self._caps

    @property
    def metadata(self) -> JsonObject:
        return {"architecture": self.architecture, "capabilities": sorted(self._caps)}

    def _status(self, recording: bool, **over: Any) -> JsonObject:
        base: JsonObject = {
            "recording": recording,
            "path": self.trace_path,
            "max_events": self.max_events,
            "timeout_ms": self.timeout_ms,
            "max_file_bytes": self.max_file_bytes,
            "events_written": 0,
            "file_bytes": 0,
            "elapsed_ms": 0,
            "stop_reason": "none" if recording else "stopped",
        }
        base.update(over)
        return base

    def request(
        self,
        command: str,
        params: JsonObject | None = None,
        *,
        timeout: float = 120.0,
    ) -> JsonObject:
        del timeout
        values = params or {}
        self.requests.append((command, values))
        if command in self.fail:
            raise self.fail[command]
        if command == "trace.start":
            self.trace_path = str(values["path"])
            self.max_events = int(values["max_events"])
            self.timeout_ms = int(values["timeout_ms"])
            self.max_file_bytes = int(values["max_file_bytes"])
            if self.write_on_start:
                Path(self.trace_path).write_bytes(b"trace-bytes")
            started = self._status(True)
            started.update(self.start_over)
            return started
        if command == "trace.status":
            if self.status_queue:
                return self.status_queue.popleft()
            return self._status(True)
        if command == "trace.stop":
            stopped = self._status(False)
            stopped.update(self.stop_over)
            return stopped
        if command == "debug.state":
            return dict(self.current_state)
        if command == "debug.resume":
            self.current_state = {"debugging": True, "running": True, "state": "running"}
            return dict(self.current_state)
        if command == "registers.read":
            if self.registers is not None:
                return dict(self.registers)
            return {"registers": {"rip": self.api_address, "rsp": 0x120000}}
        if command == "stack.read":
            entries = self.stack_entries
            if entries is None:
                entries = [
                    {"index": 0, "value": 0x401234},
                    {"index": 1, "value": 0xAAAA},
                    {"index": 2, "value": 0xBBBB},
                    {"index": 3, "value": 0xCCCC},
                    {"index": 4, "value": 0xDDDD},
                ]
            return {"pointer_size": 4, "entries": entries}
        if command == "symbols.resolve":
            return {"expression": values.get("expression"), "address": self.symbol_address}
        if command == "breakpoints.set":
            address = int(values["address"])
            self.breakpoints.add(address)
            return {"address": address, "set": True}
        if command == "breakpoints.remove":
            address = int(values["address"])
            self.breakpoints.discard(address)
            return {"address": address, "set": False}
        raise AssertionError(f"unexpected command: {command}")

    def read_events(
        self,
        cursor: int,
        *,
        limit: int = 100,
        timeout: float = 10.0,
    ) -> DebugEventBatch:
        del limit, timeout
        return DebugEventBatch(
            events=(),
            cursor=cursor,
            next_cursor=cursor,
            oldest_sequence=1 if cursor else 0,
            latest_sequence=cursor,
            dropped=0,
            dropped_total=0,
            has_more=False,
            capacity=1024,
        )

    def wait_for_state(
        self,
        states: set[str],
        *,
        timeout: float = 30.0,
        after_event_sequence: int | None = None,
        transition_event_kinds: frozenset[str] = frozenset(),
    ) -> JsonObject:
        del timeout, after_event_sequence, transition_event_kinds
        if "paused" in states:
            self.current_state = {"debugging": True, "running": False, "state": "paused"}
        return dict(self.current_state)

    def close(self, *, timeout: float = 15.0) -> None:
        del timeout
        self.closed = True

    def terminate(self) -> None:
        self.terminated = True


def _service(tmp_path: Path, worker: DynamicWorker) -> AnalysisService:
    def factory(session: Session, settings: Settings) -> DynamicWorker:
        del session, settings
        return worker

    return AnalysisService(_settings(tmp_path), dynamic_worker_factory=factory)


def _open(
    tmp_path: Path, worker: TraceWorker, machine: int = 0x8664
) -> tuple[AnalysisService, str]:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary, machine)
    service = _service(tmp_path, worker)
    created = service.create_session(str(binary))
    session_id = str(created.data["session"]["id"])
    assert service.open_dynamic(session_id).ok
    return service, session_id


# ============================================================ trace_start


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"path": ""}, "path must be a non-empty"),
        ({"path": "t", "max_events": 0}, "max_events out of range"),
        ({"path": "t", "timeout_ms": 0}, "timeout_ms out of range"),
        ({"path": "t", "max_file_bytes": 0}, "max_file_bytes out of range"),
    ],
)
def test_trace_start_rejects_bad_parameters(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    service, session_id = _open(tmp_path, TraceWorker())

    result = service.trace_start(session_id, **kwargs)

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert message in result.error.message


def test_trace_start_refuses_when_disk_is_too_small(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    monkeypatch.setattr(
        service_trace.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=0, used=0, free=1),
    )

    result = service.trace_start(session_id, "run.trace", max_file_bytes=1024)

    assert not result.ok and result.error is not None
    assert result.error.code == "insufficient_disk_space"


def test_trace_start_refuses_without_the_capability(tmp_path: Path) -> None:
    worker = TraceWorker(capabilities=_TRACE_CAPS - {"trace.start"})
    service, session_id = _open(tmp_path, worker)

    result = service.trace_start(session_id, "run.trace")

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_start_records_and_then_refuses_a_second_trace(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)

    first = service.trace_start(session_id, "run.trace", max_events=10)

    assert first.ok and first.data is not None
    assert first.data["recording"] is True
    assert first.data["session_owned"] is True
    assert first.data["artifact_pending"] is True

    second = service.trace_start(session_id, "again.trace")
    assert not second.ok and second.error is not None
    assert second.error.code == "already_tracing"


def test_trace_start_reports_a_missing_artifact_file(tmp_path: Path) -> None:
    worker = TraceWorker()
    worker.write_on_start = False
    service, session_id = _open(tmp_path, worker)

    result = service.trace_start(session_id, "run.trace")

    assert not result.ok and result.error is not None
    assert result.error.code == "artifact_missing"


def test_trace_start_failure_stops_cleanly_without_failing_the_runtime(
    tmp_path: Path,
) -> None:
    worker = TraceWorker()
    worker.fail = {"trace.start": XdbgRpcError("trace_start_failed", "no go")}
    service, session_id = _open(tmp_path, worker)

    result = service.trace_start(session_id, "run.trace")

    assert not result.ok and result.error is not None
    assert result.error.code == "trace_start_failed"
    # A clean stop keeps the runtime usable: the details carry the partial artifact.
    assert "artifact_path" in result.error.details
    assert session_id in service._runtime_owner.active_session_ids(BackendKind.X64DBG)


def test_trace_start_fatal_failure_tears_down_the_runtime(tmp_path: Path) -> None:
    worker = TraceWorker()
    worker.fail = {"trace.start": XdbgRpcError("rpc_protocol_error", "garbage")}
    service, session_id = _open(tmp_path, worker)

    result = service.trace_start(session_id, "run.trace")

    assert not result.ok and result.error is not None
    assert result.error.code == "rpc_protocol_error"
    assert session_id not in service._runtime_owner.active_session_ids(BackendKind.X64DBG)


def test_trace_start_wraps_an_unexpected_error(tmp_path: Path) -> None:
    worker = TraceWorker()
    worker.fail = {"trace.start": RuntimeError("boom")}  # type: ignore[dict-item]
    service, session_id = _open(tmp_path, worker)

    result = service.trace_start(session_id, "run.trace")

    assert not result.ok and result.error is not None


def test_trace_start_on_a_failed_session_reports_the_state(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    service.registry.transition(session_id, SessionState.FAILED)

    result = service.trace_start(session_id, "run.trace")

    assert not result.ok and result.error is not None


# ============================================================= trace_stop


def test_trace_stop_without_an_active_trace_returns_the_native_status(
    tmp_path: Path,
) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)

    result = service.trace_stop(session_id)

    assert result.ok and result.data is not None
    assert result.data["recording"] is False


def test_trace_stop_refuses_without_the_capability(tmp_path: Path) -> None:
    worker = TraceWorker(capabilities=_TRACE_CAPS - {"trace.stop"})
    service, session_id = _open(tmp_path, worker)

    result = service.trace_stop(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_stop_finalizes_an_active_trace(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok

    result = service.trace_stop(session_id)

    assert result.ok and result.data is not None
    assert result.data["recording"] is False
    assert result.data["artifact_registered"] is True
    assert result.data["artifact_id"] is not None


def test_trace_stop_that_keeps_recording_is_an_error(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok
    worker.stop_over = {"recording": True}

    result = service.trace_stop(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "trace_stop_failed"
    assert "artifact_path" in result.error.details


def test_trace_stop_wraps_an_unexpected_error(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok
    worker.fail = {"trace.stop": RuntimeError("boom")}  # type: ignore[dict-item]

    result = service.trace_stop(session_id)

    assert not result.ok and result.error is not None


def test_trace_stop_without_a_runtime_is_backend_unavailable(tmp_path: Path) -> None:
    binary = tmp_path / "fixture.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, TraceWorker())
    session_id = str(service.create_session(str(binary)).data["session"]["id"])

    result = service.trace_stop(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "backend_unavailable"


def test_trace_stop_on_a_failed_session_reports_the_state(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    service.registry.transition(session_id, SessionState.FAILED)

    result = service.trace_stop(session_id)

    assert not result.ok and result.error is not None


# =========================================================== trace_status


def test_trace_status_without_an_active_trace_returns_native(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)

    result = service.trace_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["recording"] is True


def test_trace_status_refuses_without_the_capability(tmp_path: Path) -> None:
    worker = TraceWorker(capabilities=_TRACE_CAPS - {"trace.status"})
    service, session_id = _open(tmp_path, worker)

    result = service.trace_status(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_status_reports_an_active_trace(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok

    result = service.trace_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["recording"] is True
    assert result.data["artifact_pending"] is True


def test_trace_status_finalizes_when_the_trace_has_stopped(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok
    worker.status_queue.append(worker._status(False, stop_reason="ended"))

    result = service.trace_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["recording"] is False
    assert result.data["artifact_registered"] is True
    assert result.data["terminal_reason"] == "ended"


def test_trace_status_enforces_the_quota_and_labels_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace", max_events=5, timeout_ms=1000).ok
    # Push the clock well past the deadline so the service-side stop is labelled
    # a timeout rather than a plain stop.
    monkeypatch.setattr(service_trace, "monotonic", lambda: 1e12)
    # Still recording but the event budget is spent, so the service stops it.
    worker.status_queue.append(worker._status(True, events_written=5))

    result = service.trace_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["recording"] is False
    assert result.data["stop_reason"] == "timeout"
    assert result.data["quota_stopped"] is True


def test_trace_status_raises_when_a_quota_stop_keeps_recording(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace", max_events=5, timeout_ms=60_000).ok
    worker.status_queue.append(worker._status(True, events_written=5))
    # The service-side quota stop is issued, but the worker refuses to leave the
    # recording state, so validation of that stop reports it as a failed stop.
    worker.stop_over = {"recording": True}

    result = service.trace_status(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "trace_stop_failed"


def test_trace_status_after_finalize_does_not_tear_down_the_session(
    tmp_path: Path,
) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok
    worker.status_queue.append(worker._status(False, stop_reason="ended"))
    assert service.trace_status(session_id).ok  # finalizes
    # A later poll fails at the worker, but the finalized artifact is replayed.
    worker.fail = {"trace.status": XdbgRpcError("worker_exited", "gone")}

    result = service.trace_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["artifact_registered"] is True


def test_trace_status_replays_a_finalized_trace_after_an_unexpected_error(
    tmp_path: Path,
) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok
    worker.status_queue.append(worker._status(False, stop_reason="ended"))
    assert service.trace_status(session_id).ok  # finalizes
    worker.fail = {"trace.status": RuntimeError("boom")}  # type: ignore[dict-item]

    result = service.trace_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["artifact_registered"] is True


def test_trace_status_wraps_an_unexpected_error(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok
    worker.fail = {"trace.status": RuntimeError("boom")}  # type: ignore[dict-item]

    result = service.trace_status(session_id)

    assert not result.ok and result.error is not None


def test_trace_status_on_a_failed_session_reports_the_state(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    service.registry.transition(session_id, SessionState.FAILED)

    result = service.trace_status(session_id)

    assert not result.ok and result.error is not None


def test_trace_status_quota_stop_without_a_timeout_keeps_the_stop_reason(
    tmp_path: Path,
) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace", max_events=5, timeout_ms=60_000).ok
    # The event budget is spent but the deadline is far off, so the service-side
    # stop keeps whatever stop_reason the worker reported.
    worker.status_queue.append(worker._status(True, events_written=5))

    result = service.trace_status(session_id)

    assert result.ok and result.data is not None
    assert result.data["recording"] is False
    assert result.data["stop_reason"] == "stopped"
    assert "quota_stopped" not in result.data


# ================================================= trace_api_arguments


def test_trace_api_arguments_reads_x86_stack_slots(tmp_path: Path) -> None:
    worker = TraceWorker(architecture="x86", api_address=0x00401500)
    worker.registers = {"registers": {"eip": 0x00401500, "esp": 0x120000}}
    service, session_id = _open(tmp_path, worker, machine=0x014C)

    traced = service.trace_api_arguments(
        session_id, address=0x00401500, max_hits=1, argument_count=3
    )

    assert traced.ok and traced.data is not None
    assert traced.data["convention"] == "x86_stack_arguments"
    first = traced.data["hits"][0]
    assert [arg["value"] for arg in first["arguments"]] == [0xAAAA, 0xBBBB, 0xCCCC]
    assert first["arguments"][0]["source"] == "[esp+0x4]"


def test_trace_api_arguments_resolves_a_symbol_expression(tmp_path: Path) -> None:
    worker = TraceWorker(api_address=0x140003000)
    worker.symbol_address = 0x140003000
    service, session_id = _open(tmp_path, worker)

    traced = service.trace_api_arguments(
        session_id, expression="kernel32!VirtualAlloc", max_hits=1
    )

    assert traced.ok and traced.data is not None
    assert traced.data["target"]["address"] == 0x140003000
    assert traced.data["target"]["expression"] == "kernel32!VirtualAlloc"


def test_trace_api_arguments_returns_a_failed_symbol_resolution(tmp_path: Path) -> None:
    worker = TraceWorker()
    worker.fail = {"symbols.resolve": XdbgRpcError("not_found", "no such symbol")}
    service, session_id = _open(tmp_path, worker)

    traced = service.trace_api_arguments(session_id, expression="mystery")

    assert not traced.ok and traced.error is not None
    assert traced.error.code == "not_found"


def test_trace_api_arguments_rejects_a_non_address_resolution(tmp_path: Path) -> None:
    worker = TraceWorker()
    worker.symbol_address = "0x1000"  # type: ignore[assignment]
    service, session_id = _open(tmp_path, worker)

    traced = service.trace_api_arguments(session_id, expression="odd")

    assert not traced.ok and traced.error is not None


def test_trace_api_arguments_returns_a_failed_breakpoint(tmp_path: Path) -> None:
    worker = TraceWorker()
    worker.fail = {"breakpoints.set": XdbgRpcError("invalid_params", "bad address")}
    service, session_id = _open(tmp_path, worker)

    traced = service.trace_api_arguments(session_id, address=0x140002000)

    assert not traced.ok and traced.error is not None


def test_trace_api_arguments_stops_the_loop_when_a_resume_fails(tmp_path: Path) -> None:
    worker = TraceWorker(api_address=0x140002000)
    worker.fail = {"debug.resume": XdbgRpcError("worker_exited", "gone")}
    service, session_id = _open(tmp_path, worker)

    traced = service.trace_api_arguments(session_id, address=0x140002000, max_hits=3)

    assert traced.ok and traced.data is not None
    assert traced.data["hit_count"] == 0
    # The first resume failed, so the capture loop stopped before any hit.
    commands = [command for command, _ in worker.requests]
    assert commands.count("debug.resume") == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"address": 1, "max_hits": 0},
        {"address": 1, "max_hits": True},
        {"address": 1, "argument_count": 9},
        {"address": 1, "argument_count": True},
        {"address": 1, "timeout": "soon"},
        {"address": 1, "timeout": 0},
    ],
)
def test_trace_api_arguments_rejects_bad_parameters(
    tmp_path: Path, kwargs: dict[str, Any]
) -> None:
    service, session_id = _open(tmp_path, TraceWorker())

    traced = service.trace_api_arguments(session_id, **kwargs)

    assert not traced.ok and traced.error is not None


# ===================================================== argument decoders


def test_register_arguments_decode_and_reject_non_integers() -> None:
    registers = {"registers": {"rcx": 0x10, "rdx": True, "r8": None, "r9": 0x40}}

    decoded = _register_arguments(registers, 4)

    assert [arg["value"] for arg in decoded] == [0x10, None, None, 0x40]
    assert _register_arguments(None, 4) == []
    assert _register_arguments({"rcx": 1}, 0) == []


def test_register_arguments_use_a_flat_bank() -> None:
    decoded = _register_arguments({"rcx": 0x99}, 1)

    assert decoded[0]["value"] == 0x99


def test_stack_arguments_default_pointer_width_and_missing_slots() -> None:
    payload = {"entries": [{"value": 0x1}, {"value": 0x2}]}

    decoded = _stack_arguments(payload, 2)

    assert decoded[0]["source"] == "[esp+0x4]"
    assert decoded[1]["value"] is None
    assert _stack_arguments({"entries": "nope"}, 2) == []
    assert _stack_arguments(None, 1) == []


def test_instruction_pointer_prefers_rip_then_falls_back() -> None:
    assert _instruction_pointer({"registers": {"rip": 0x10}}) == 0x10
    assert _instruction_pointer({"eip": 0x20}) == 0x20
    assert _instruction_pointer({"pc": True}) is None
    assert _instruction_pointer(None) is None


# ======================================================= helper arcs


def _trace_state(service: AnalysisService, session_id: str) -> _TraceArtifactState:
    path = service._new_trace_artifact_path(session_id)
    path.write_bytes(b"trace-bytes")
    return _TraceArtifactState(
        session_id=session_id,
        path=path,
        requested_path="run.trace",
        max_events=10,
        timeout_ms=1000,
        max_file_bytes=4096,
        started_monotonic=0.0,
    )


def test_new_trace_artifact_path_rejects_a_path_unsafe_session_id(tmp_path: Path) -> None:
    service, _ = _open(tmp_path, TraceWorker())

    with pytest.raises(ValueError, match="invalid session id"):
        service._new_trace_artifact_path("../escape")


def test_new_trace_artifact_path_rejects_a_name_that_escapes_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: a uuid can never carry a separator, so force one to
    prove the artifact-escaped-its-root guard fires."""
    service, session_id = _open(tmp_path, TraceWorker())
    monkeypatch.setattr(
        service_trace, "uuid4", lambda: SimpleNamespace(hex="nested/evil")
    )

    with pytest.raises(ValueError, match="escaped the session artifact directory"):
        service._new_trace_artifact_path(session_id)


def test_trace_stop_defends_against_a_validator_that_missed_recording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Belt-and-suspenders: if validation ever let a recording status through,
    trace_stop still refuses it."""
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok

    def lax(state: Any, payload: Any, *, require_recording: Any = None) -> JsonObject:
        return {"recording": True, "stop_reason": "none", "path": str(state.path)}

    monkeypatch.setattr(service, "_validate_trace_status", lax)

    result = service.trace_stop(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "trace_stop_failed"


def test_trace_status_defends_when_a_quota_stop_is_reported_recording(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Belt-and-suspenders: reaching the quota stop with the validator waved
    through must still raise the enforcement-failed error."""
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace", max_events=5).ok

    def lax(state: Any, payload: Any, *, require_recording: Any = None) -> JsonObject:
        return {
            "recording": True,
            "events_written": 5,
            "file_bytes": 0,
            "elapsed_ms": 0,
            "max_events": 5,
            "timeout_ms": state.timeout_ms,
            "max_file_bytes": state.max_file_bytes,
            "stop_reason": "none",
            "path": str(state.path),
        }

    monkeypatch.setattr(service, "_validate_trace_status", lax)

    result = service.trace_status(session_id)

    assert not result.ok and result.error is not None
    assert result.error.code == "trace_quota_enforcement_failed"


def test_validate_trace_status_rejects_a_non_object(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    with pytest.raises(XdbgRpcError, match="non-object"):
        service._validate_trace_status(state, ["not", "a", "dict"])  # type: ignore[arg-type]


def test_validate_trace_status_requires_a_boolean_recording(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    with pytest.raises(XdbgRpcError, match="boolean recording"):
        service._validate_trace_status(state, {"recording": "yes", "path": str(state.path)})


def test_validate_trace_status_enforces_require_recording(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    payload = {"recording": False, "path": str(state.path)}

    with pytest.raises(XdbgRpcError, match="did not enter"):
        service._validate_trace_status(state, payload, require_recording=True)

    payload["recording"] = True
    with pytest.raises(XdbgRpcError, match="did not leave"):
        service._validate_trace_status(state, payload, require_recording=False)


def test_validate_trace_status_rejects_an_unparsable_path(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    with pytest.raises(XdbgRpcError, match="invalid artifact path"):
        service._validate_trace_status(
            state, {"recording": True, "path": "bad\x00path"}
        )


def test_validate_trace_status_rejects_a_foreign_path(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    with pytest.raises(XdbgRpcError, match="does not match"):
        service._validate_trace_status(
            state, {"recording": True, "path": str(tmp_path / "elsewhere.trace")}
        )


def test_validate_trace_status_fills_and_checks_quota_fields(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    filled = service._validate_trace_status(
        state, {"recording": True, "path": str(state.path)}
    )

    assert filled["max_events"] == state.max_events
    assert filled["events_written"] == 0
    assert filled["stop_reason"] == "none"


def test_validate_trace_status_rejects_a_wrong_quota_value(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    with pytest.raises(XdbgRpcError, match="invalid max_events"):
        service._validate_trace_status(
            state,
            {"recording": True, "path": str(state.path), "max_events": 999},
        )


def test_validate_trace_status_rejects_a_negative_counter(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    with pytest.raises(XdbgRpcError, match="invalid events_written"):
        service._validate_trace_status(
            state,
            {"recording": True, "path": str(state.path), "events_written": -1},
        )


def test_validate_trace_status_flags_a_quota_violation(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    with pytest.raises(XdbgRpcError, match="exceeded a hard quota"):
        service._validate_trace_status(
            state,
            {"recording": True, "path": str(state.path), "events_written": 11},
        )


def _fake_runtime(worker: Any) -> Any:
    return SimpleNamespace(lock=RLock(), worker=worker)


def test_stop_after_failure_false_without_the_capability(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    worker = SimpleNamespace(capabilities=frozenset())

    assert service._stop_trace_after_failure(_fake_runtime(worker), state) is False


def test_stop_after_failure_false_when_still_recording(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    worker = SimpleNamespace(
        capabilities=frozenset({"trace.stop"}),
        request=lambda *a, **k: {"recording": True},
    )

    assert service._stop_trace_after_failure(_fake_runtime(worker), state) is False


def test_stop_after_failure_true_on_a_clean_stop(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    worker = SimpleNamespace(
        capabilities=frozenset({"trace.stop"}),
        request=lambda *a, **k: {"recording": False, "stop_reason": "stopped"},
    )

    assert service._stop_trace_after_failure(_fake_runtime(worker), state) is True
    assert state.active is False


def test_stop_after_failure_false_on_an_exception(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    def boom(*_a: Any, **_k: Any) -> JsonObject:
        raise RuntimeError("worker gone")

    worker = SimpleNamespace(capabilities=frozenset({"trace.stop"}), request=boom)

    assert service._stop_trace_after_failure(_fake_runtime(worker), state) is False


def test_finalize_is_idempotent_after_registration(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    service._finalize_trace_artifact(state, terminal_reason="stopped")
    first_id = state.artifact_id
    assert first_id is not None

    service._finalize_trace_artifact(state, terminal_reason="worker_died")

    assert state.artifact_id == first_id
    assert state.terminal_reason == "worker_died"


def test_finalize_rejects_a_path_outside_the_session_root(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    state.path = tmp_path / "loose.trace"
    state.path.write_bytes(b"x")

    service._finalize_trace_artifact(state, terminal_reason="stopped")

    assert state.artifact_error is not None
    assert "outside its session-owned root" in state.artifact_error


def test_finalize_reports_a_missing_file(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    state.path.unlink()

    service._finalize_trace_artifact(state, terminal_reason="stopped")

    assert state.artifact_error == "trace artifact file is missing"


def test_finalize_truncates_an_over_quota_file(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)
    state.max_file_bytes = 4
    state.path.write_bytes(b"way too many bytes")

    service._finalize_trace_artifact(state, terminal_reason="stopped")

    assert state.artifact_truncated is True
    assert state.artifact_size == 4
    assert state.terminal_reason == "quota_violation"
    assert state.path.stat().st_size == 4


def test_finalize_records_a_backend_error_when_recording_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _open(tmp_path, TraceWorker())
    state = _trace_state(service, session_id)

    def boom(**_fields: Any) -> JsonObject:
        raise OSError("disk full")

    monkeypatch.setattr(service, "record_artifact", boom)

    service._finalize_trace_artifact(state, terminal_reason="stopped")

    assert state.artifact_error == "disk full"


def test_finalize_after_worker_loss_is_a_noop_without_a_trace(tmp_path: Path) -> None:
    service, session_id = _open(tmp_path, TraceWorker())

    service._finalize_trace_after_worker_loss(session_id, reason="worker_died")


def test_finalize_after_worker_loss_finalizes_a_live_trace(tmp_path: Path) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok

    service._finalize_trace_after_worker_loss(session_id, reason="target_exited")

    state = service._trace_owner.get(session_id)
    assert state is not None
    assert state.artifact_id is not None
    assert state.last_status["failed"] is False


def test_finalize_after_worker_loss_skips_an_already_finalized_trace(
    tmp_path: Path,
) -> None:
    worker = TraceWorker()
    service, session_id = _open(tmp_path, worker)
    assert service.trace_start(session_id, "run.trace").ok
    assert service.trace_stop(session_id).ok
    finalized = service._trace_owner.get(session_id)
    assert finalized is not None
    original_id = finalized.artifact_id

    service._finalize_trace_after_worker_loss(session_id, reason="worker_died")

    assert service._trace_owner.get(session_id).artifact_id == original_id


def test_attach_trace_artifact_details_copies_the_state_fields() -> None:
    error = XdbgRpcError("trace_start_failed", "no go")
    state = _TraceArtifactState(
        session_id="s",
        path=Path("/tmp/run.trace"),
        requested_path="run.trace",
        max_events=1,
        timeout_ms=1,
        max_file_bytes=1,
        started_monotonic=0.0,
        artifact_id="abc",
        artifact_sha256="def",
    )

    TraceMixin._attach_trace_artifact_details(object(), error, state)

    assert error.details["artifact_id"] == "abc"
    assert error.details["artifact_sha256"] == "def"
