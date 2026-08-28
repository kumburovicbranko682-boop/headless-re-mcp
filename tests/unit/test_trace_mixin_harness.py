"""The bounded-trace surface, driven on a fake backend so it runs anywhere.

TraceMixin is where the one debugger operation that writes unbounded data is
kept bounded: every trace carries an event/byte/time budget, the artifact is
finalised even when the worker dies mid-trace, an over-quota file is truncated
and filed as partial rather than retained, and a caller path is never trusted
as an output destination. None of that ran on a hosted platform -- the mixin
needs a live x64dbg session -- so it sat at 30%.

The mixin talks to its world through a handful of seams (a runtime with a
lock and a worker, a session registry, a trace-state owner, record_artifact,
and the dynamic.* step methods). Supplying fakes for exactly those seams
drives the real start/stop/status/finalise/validate logic and the API-argument
decode across their load-bearing branches, with real files on disk for the
finalise and quota paths.
"""

from __future__ import annotations

from pathlib import Path
from threading import RLock
from typing import Any

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture, BackendKind, Result, RpcError
from headless_re_mcp.core.runtime_state import TraceStateOwner
from headless_re_mcp.core.service_trace import (
    TraceMixin,
    _instruction_pointer,
    _register_arguments,
    _stack_arguments,
    _TraceArtifactState,
)

INVALID = "invalid_request"


def _ok(data: dict[str, Any]) -> Result[Any]:
    return Result(ok=True, data=data)


def _err(code: str, message: str = "nope") -> Result[Any]:
    return Result(ok=False, error=RpcError(code=code, message=message))


class _Worker:
    """A stand-in x64dbg worker: named capabilities and scripted replies."""

    def __init__(self, capabilities: set[str]) -> None:
        self.capabilities = set(capabilities)
        self._handlers: dict[str, Any] = {}
        self.calls: list[tuple[str, Any, float | None]] = []

    def on(self, method: str, handler: Any) -> None:
        self._handlers[method] = handler

    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        self.calls.append((method, params, timeout))
        handler = self._handlers[method]
        return handler(params) if callable(handler) else handler


class _Runtime:
    def __init__(self, worker: _Worker) -> None:
        self.lock = RLock()
        self.worker = worker


class _Session:
    def __init__(self, arch: Architecture) -> None:
        self._arch = arch

    def require_architecture(self) -> Architecture:
        return self._arch


class _Registry:
    def __init__(self, session: _Session) -> None:
        self._session = session

    def get(self, _session_id: str) -> _Session:
        return self._session


class _Harness(TraceMixin):
    """A minimal object that mixes in TraceMixin and fills every seam."""

    def __init__(
        self,
        settings: Settings,
        runtime: _Runtime,
        arch: Architecture = Architecture.X64,
    ) -> None:
        self.settings = settings
        self.registry = _Registry(_Session(arch))  # type: ignore[assignment]
        self._lock = RLock()
        self._trace_owner = TraceStateOwner()
        self._runtime_obj = runtime
        self.failed: list[tuple[str, BaseException | None]] = []
        self.recorded: list[dict[str, Any]] = []
        self._artifact_seq = 0
        # dynamic.* step stubs, overridden per test.
        self.stub_symbols: Any = None
        self.stub_bp_set: Any = None
        self.stub_bp_remove: Any = None
        self.stub_resume: Any = None
        self.stub_registers: Any = None
        self.stub_stack: Any = None
        self.bp_removed: list[int] = []

    def _runtime(self, _session_id: str, _kind: BackendKind) -> Any:
        return self._runtime_obj

    def _require_current_runtime(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def _fail_runtime(
        self,
        session_id: str,
        _kind: BackendKind,
        *,
        failure: BaseException | None = None,
    ) -> None:
        self.failed.append((session_id, failure))

    def record_artifact(self, **fields: Any) -> dict[str, Any]:
        self._artifact_seq += 1
        record = {"id": f"artifact-{self._artifact_seq}", **fields}
        self.recorded.append(record)
        return record

    def symbols_resolve(self, session_id: str, expression: str, *, timeout: float = 30.0) -> Any:
        return self.stub_symbols(session_id, expression)

    def dynamic_breakpoint_set(self, session_id: str, address: int, **_kwargs: Any) -> Any:
        return self.stub_bp_set(session_id, address)

    def dynamic_breakpoint_remove(self, session_id: str, address: int) -> Any:
        self.bp_removed.append(address)
        if self.stub_bp_remove is not None:
            return self.stub_bp_remove(session_id, address)
        return _ok({"removed": address})

    def dynamic_resume(self, session_id: str, **_kwargs: Any) -> Any:
        return self.stub_resume(session_id)

    def dynamic_registers_read(self, session_id: str) -> Any:
        return self.stub_registers(session_id)

    def stack_read(self, session_id: str, *, count: int = 32, **_kwargs: Any) -> Any:
        return self.stub_stack(session_id, count)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )


def _make(tmp_path: Path, caps: set[str], arch: Architecture = Architecture.X64) -> _Harness:
    return _Harness(_settings(tmp_path), _Runtime(_Worker(caps)), arch)


# --------------------------------------------------------------------------
# Pure argument/pointer decoders.
# --------------------------------------------------------------------------


def test_register_arguments_decode_and_reject() -> None:
    assert _register_arguments(None, 4) == []
    assert _register_arguments({"rcx": 1}, 0) == []
    flat = _register_arguments({"rcx": 1, "rdx": 2, "r8": 3, "r9": 4}, 3)
    assert [a["value"] for a in flat] == [1, 2, 3]
    assert [a["source"] for a in flat] == ["rcx", "rdx", "r8"]
    # A nested bank is unwrapped, and a bool is not a usable integer.
    nested = _register_arguments({"registers": {"rcx": True, "rdx": 7}}, 2)
    assert nested[0]["value"] is None
    assert nested[1]["value"] == 7


def test_stack_arguments_decode_and_reject() -> None:
    assert _stack_arguments(None, 2) == []
    assert _stack_arguments({"entries": "x"}, 2) == []
    payload = {
        "pointer_size": 8,
        "entries": [
            {"value": 0xDEAD},  # slot 0 = return address, skipped
            {"value": 0x11},
            {"value": True},  # bool -> unusable
        ],
    }
    args = _stack_arguments(payload, 2)
    assert args[0]["source"] == "[esp+0x8]"
    assert args[0]["value"] == 0x11
    assert args[1]["value"] is None  # bool rejected
    # A missing/invalid pointer_size falls back to 4-byte slots.
    widthless = _stack_arguments({"entries": [{}, {"value": 5}]}, 1)
    assert widthless[0]["source"] == "[esp+0x4]"


def test_instruction_pointer_precedence_and_rejection() -> None:
    assert _instruction_pointer(None) is None
    assert _instruction_pointer({"eip": 0x40}) == 0x40
    assert _instruction_pointer({"registers": {"pc": 0x50}}) == 0x50
    # rip wins over eip when both are present; a bool is not an address.
    assert _instruction_pointer({"rip": 0x1000, "eip": 0x40}) == 0x1000
    assert _instruction_pointer({"rip": True}) is None


# --------------------------------------------------------------------------
# trace_api_arguments.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # neither expression nor address
        {"expression": "kernel32!CreateFileW", "address": 0x1000},  # both
        {"address": 0x1000, "max_hits": 0},
        {"address": 0x1000, "max_hits": 65},
        {"address": 0x1000, "argument_count": 5},
        {"address": 0x1000, "timeout": "soon"},
        {"address": 0x1000, "timeout": 0},
    ],
)
def test_trace_api_arguments_validates_inputs(tmp_path: Path, kwargs: dict[str, Any]) -> None:
    harness = _make(tmp_path, {"trace.start"})
    result = harness.trace_api_arguments("sess", **kwargs)
    assert result.ok is False
    assert result.error is not None and result.error.code == INVALID


def test_trace_api_arguments_x64_registers(tmp_path: Path) -> None:
    harness = _make(tmp_path, set(), Architecture.X64)
    target = 0x14000
    harness.stub_symbols = lambda s, e: _ok({"address": target, "symbol": e})
    harness.stub_bp_set = lambda s, a: _ok({"set": a})
    harness.stub_resume = lambda s: _ok({"paused": True})
    harness.stub_registers = lambda s: _ok({"rip": target, "rcx": 1, "rdx": 2, "r8": 3, "r9": 4})

    result = harness.trace_api_arguments(
        "sess", "kernel32!CreateFileW", max_hits=2, argument_count=4
    )
    assert result.ok is True and result.data is not None
    data = result.data
    assert data["convention"] == "microsoft_x64_integer_registers"
    assert data["hit_count"] == 2
    assert data["truncated"] is True  # filled max_hits
    assert data["stopped_elsewhere"] is False
    assert data["hits"][0]["arguments"][0]["value"] == 1
    assert data["target"]["address"] == target
    # The breakpoint is always removed, once, no matter how the loop ends.
    assert harness.bp_removed == [target]


def test_trace_api_arguments_x86_reads_the_stack(tmp_path: Path) -> None:
    harness = _make(tmp_path, set(), Architecture.X86)
    target = 0x401000
    harness.stub_bp_set = lambda s, a: _ok({"set": a})
    resumes = iter([_ok({"paused": True}), _ok({"paused": True})])
    harness.stub_resume = lambda s: next(resumes, _err("stopped"))
    harness.stub_registers = lambda s: _ok({"eip": target})
    # entries[0] is the return address at the top of stack; args follow it.
    harness.stub_stack = lambda s, count: _ok(
        {
            "pointer_size": 4,
            "entries": [
                {"value": 0xC0DE},
                {"value": 0xA},
                {"value": 0xB},
                {"value": 0xC},
            ],
        }
    )

    result = harness.trace_api_arguments("sess", address=target, max_hits=1, argument_count=3)
    assert result.ok is True and result.data is not None
    assert result.data["convention"] == "x86_stack_arguments"
    assert result.data["hits"][0]["arguments"][0]["value"] == 0xA
    assert harness.bp_removed == [target]


def test_trace_api_arguments_stops_when_paused_elsewhere(tmp_path: Path) -> None:
    harness = _make(tmp_path, set(), Architecture.X64)
    target = 0x15000
    harness.stub_bp_set = lambda s, a: _ok({"set": a})
    harness.stub_resume = lambda s: _ok({"paused": True})
    # Paused at a different address: someone else's break, not our hit.
    harness.stub_registers = lambda s: _ok({"rip": target + 0x40})

    result = harness.trace_api_arguments("sess", address=target, max_hits=4)
    assert result.ok is True and result.data is not None
    assert result.data["hit_count"] == 0
    assert result.data["stopped_elsewhere"] is True
    assert harness.bp_removed == [target]


def test_trace_api_arguments_returns_a_failed_symbol_resolution(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    harness.stub_symbols = lambda s, e: _err("symbol_not_found")
    result = harness.trace_api_arguments("sess", "bogus!symbol")
    assert result.ok is False and result.error is not None
    assert result.error.code == "symbol_not_found"
    assert harness.bp_removed == []  # never armed


def test_trace_api_arguments_returns_a_failed_breakpoint(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    harness.stub_bp_set = lambda s, a: _err("breakpoint_failed")
    result = harness.trace_api_arguments("sess", address=0x16000)
    assert result.ok is False and result.error is not None
    assert result.error.code == "breakpoint_failed"


# --------------------------------------------------------------------------
# _validate_trace_status.
# --------------------------------------------------------------------------


def _state(tmp_path: Path, session_id: str = "sess") -> _TraceArtifactState:
    root = tmp_path / "artifacts" / "trace" / session_id
    root.mkdir(parents=True, exist_ok=True)
    path = (root / "run-abc.trace64").resolve()
    return _TraceArtifactState(
        session_id=session_id,
        path=path,
        requested_path="C:/wanted.trace",
        max_events=1000,
        timeout_ms=60_000,
        max_file_bytes=4096,
        started_monotonic=0.0,
    )


def _good_status_from_params(params: dict[str, Any], **over: Any) -> dict[str, Any]:
    base = {
        "recording": True,
        "path": params["path"],
        "max_events": params["max_events"],
        "timeout_ms": params["timeout_ms"],
        "max_file_bytes": params["max_file_bytes"],
        "events_written": 0,
        "file_bytes": 4,
        "elapsed_ms": 0,
        "stop_reason": "none",
    }
    base.update(over)
    return base


def _good_status(state: _TraceArtifactState, **over: Any) -> dict[str, Any]:
    base = {
        "recording": True,
        "path": str(state.path),
        "max_events": state.max_events,
        "timeout_ms": state.timeout_ms,
        "max_file_bytes": state.max_file_bytes,
        "events_written": 0,
        "file_bytes": 0,
        "elapsed_ms": 0,
        "stop_reason": "none",
    }
    base.update(over)
    return base


def test_validate_status_fills_counter_and_quota_defaults(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    raw = {"recording": True, "path": str(state.path)}  # omit counters + quotas
    data = harness._validate_trace_status(state, raw)
    assert data["events_written"] == 0 and data["file_bytes"] == 0
    assert data["max_events"] == state.max_events
    assert data["stop_reason"] == "none"


def test_validate_status_rejects_bad_shapes(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="non-object"):
        harness._validate_trace_status(state, ["not", "a", "dict"])  # type: ignore[arg-type]
    with pytest.raises(XdbgRpcError, match="boolean recording"):
        harness._validate_trace_status(state, {"recording": "yes", "path": str(state.path)})
    with pytest.raises(XdbgRpcError, match="does not match"):
        harness._validate_trace_status(state, _good_status(state, path="/tmp/elsewhere.trace"))


def test_validate_status_enforces_the_recording_gate(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError, match="did not enter"):
        harness._validate_trace_status(
            state, _good_status(state, recording=False), require_recording=True
        )
    with pytest.raises(XdbgRpcError, match="did not leave"):
        harness._validate_trace_status(
            state, _good_status(state, recording=True), require_recording=False
        )


def test_validate_status_raises_on_quota_violation(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError) as caught:
        harness._validate_trace_status(
            state, _good_status(state, events_written=state.max_events + 1)
        )
    assert caught.value.code == "trace_quota_violation"


# --------------------------------------------------------------------------
# _finalize_trace_artifact.
# --------------------------------------------------------------------------


def test_finalize_registers_a_bounded_artifact(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    state.path.write_bytes(b"trace-bytes")
    harness._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_id == "artifact-1"
    assert state.artifact_size == len(b"trace-bytes")
    assert state.artifact_error is None
    assert harness.recorded[0]["kind"] == "run_trace"
    assert state.terminal_reason == "stopped"


def test_finalize_truncates_an_over_quota_file_and_marks_it_partial(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    state.path.write_bytes(b"X" * (state.max_file_bytes + 500))
    harness._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_truncated is True
    assert state.artifact_size == state.max_file_bytes
    assert state.path.stat().st_size == state.max_file_bytes
    assert state.terminal_reason == "quota_violation"
    assert harness.recorded[0]["kind"] == "run_trace_partial"


def test_finalize_reports_a_missing_file(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)  # no file written
    harness._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_id is None
    assert state.artifact_error == "trace artifact file is missing"


def test_finalize_rejects_an_artifact_outside_its_session_root(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    escaped = (tmp_path / "artifacts" / "trace" / "other-session").resolve()
    escaped.mkdir(parents=True, exist_ok=True)
    object.__setattr__(state, "path", escaped / "run-x.trace64")
    state.path.write_bytes(b"data")
    harness._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_id is None
    assert "outside its session-owned root" in (state.artifact_error or "")


def test_finalize_is_idempotent(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    state.path.write_bytes(b"once")
    harness._finalize_trace_artifact(state, terminal_reason="stopped")
    harness._finalize_trace_artifact(state, terminal_reason="stopped_again")
    assert len(harness.recorded) == 1  # not registered twice
    assert state.terminal_reason == "stopped_again"


# --------------------------------------------------------------------------
# trace_start / trace_stop / trace_status lifecycle.
# --------------------------------------------------------------------------


def _start(harness: _Harness, session_id: str = "sess", **over: Any) -> Result[Any]:
    worker = harness._runtime_obj.worker

    def start(params: dict[str, Any]) -> dict[str, Any]:
        Path(params["path"]).write_bytes(b"seed")
        return {
            "recording": True,
            "path": params["path"],
            "max_events": params["max_events"],
            "timeout_ms": params["timeout_ms"],
            "max_file_bytes": params["max_file_bytes"],
            "events_written": 0,
            "file_bytes": 4,
            "elapsed_ms": 0,
            "stop_reason": "none",
        }

    worker.on("trace.start", start)
    return harness.trace_start(session_id, "C:/wanted.trace", max_file_bytes=4096, **over)


def test_trace_start_places_the_artifact_in_the_session_tree(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start"})
    result = _start(harness)
    assert result.ok is True and result.data is not None
    artifact_path = Path(result.data["artifact_path"])
    expected_root = (tmp_path / "artifacts" / "trace" / "sess").resolve()
    assert artifact_path.parent == expected_root
    assert result.data["requested_path"] == "C:/wanted.trace"
    assert result.data["session_owned"] is True
    assert harness._trace_owner.get("sess") is not None


def test_trace_start_refuses_a_backend_without_the_capability(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())  # no trace.start capability
    result = harness.trace_start("sess", "C:/x.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_start_refuses_a_second_concurrent_trace(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start"})
    assert _start(harness).ok is True
    second = harness.trace_start("sess", "C:/again.trace", max_file_bytes=4096)
    assert second.ok is False and second.error is not None
    assert second.error.code == "already_tracing"


def test_trace_stop_finalises_and_reports(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    harness._runtime_obj.worker.on(
        "trace.stop", lambda _p: _good_status(state, recording=False, stop_reason="cancelled")
    )
    result = harness.trace_stop("sess")
    assert result.ok is True and result.data is not None
    assert result.data["artifact_registered"] is True
    assert result.data["terminal_reason"] == "cancelled"
    assert state.active is False


def test_trace_status_auto_stops_a_trace_over_the_event_budget(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.status", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    # status still says recording, but the event budget is exhausted, so the
    # service must issue its own trace.stop rather than let it run on.
    harness._runtime_obj.worker.on(
        "trace.status",
        lambda _p: _good_status(state, recording=True, events_written=state.max_events),
    )
    harness._runtime_obj.worker.on(
        "trace.stop",
        lambda _p: _good_status(state, recording=False, events_written=state.max_events),
    )
    result = harness.trace_status("sess")
    assert result.ok is True and result.data is not None
    assert result.data["artifact_registered"] is True
    methods = [name for name, _params, _timeout in harness._runtime_obj.worker.calls]
    assert "trace.stop" in methods  # service-side quota enforcement fired


# --------------------------------------------------------------------------
# Failure and recovery: a lost trace must still be finalised as a partial.
# --------------------------------------------------------------------------


def test_trace_start_failure_stops_safely_and_keeps_the_partial(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    worker = harness._runtime_obj.worker

    def start(params: dict[str, Any]) -> dict[str, Any]:
        # The file is created but the backend never enters recording state.
        Path(params["path"]).write_bytes(b"partial")
        return _good_status_from_params(params, recording=False)

    worker.on("trace.start", start)
    worker.on("trace.stop", lambda _p: {"recording": False})

    result = harness.trace_start("sess", "C:/x.trace", max_file_bytes=4096)
    assert result.ok is False and result.error is not None
    assert result.error.code == "trace_start_failed"
    # The bounded partial was still registered, and its id is in the error.
    assert result.error.details["artifact_id"] == "artifact-1"
    assert harness.recorded[0]["kind"] == "run_trace"
    # A clean safe-stop means the analyzer was not torn down.
    assert harness.failed == []


def test_trace_stop_failure_finalises_a_partial_and_fails_the_runtime(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    # The backend claims it is still recording after trace.stop: unsafe.
    harness._runtime_obj.worker.on("trace.stop", lambda _p: _good_status(state, recording=True))
    result = harness.trace_stop("sess")
    assert result.ok is False and result.error is not None
    assert result.error.details["artifact_id"] == "artifact-1"
    assert state.active is False
    assert harness.failed and harness.failed[0][0] == "sess"


def test_trace_status_stale_poll_returns_the_finalised_state(tmp_path: Path) -> None:
    harness = _make(tmp_path, {"trace.start", "trace.stop", "trace.status"})
    assert _start(harness).ok is True
    state = harness._trace_owner.get("sess")
    assert state is not None
    harness._runtime_obj.worker.on(
        "trace.stop", lambda _p: _good_status(state, recording=False, stop_reason="target_exited")
    )
    assert harness.trace_stop("sess").ok is True  # artifact_id now set, active False

    def boom(_p: Any) -> dict[str, Any]:
        raise XdbgRpcError("rpc_protocol_error", "worker went away")

    harness._runtime_obj.worker.on("trace.status", boom)
    result = harness.trace_status("sess")
    # A stale poll after finalize must not tear down the session; it replays
    # the finalised state instead of surfacing the transient worker error.
    assert result.ok is True and result.data is not None
    assert result.data["artifact_id"] == "artifact-1"
    assert harness.failed == []


def test_finalize_after_worker_loss_marks_failure_reasons(tmp_path: Path) -> None:
    harness = _make(tmp_path, set())
    state = _state(tmp_path)
    state.path.write_bytes(b"trace")
    harness._trace_owner.put("sess", state)

    harness._finalize_trace_after_worker_loss("sess", reason="worker_crash")
    assert state.active is False
    assert state.last_status["stop_reason"] == "worker_crash"
    assert state.last_status["failed"] is True  # a crash is a failure
    assert state.artifact_id == "artifact-1"

    # A clean session close is not a failure, and finalize is not repeated.
    harness._finalize_trace_after_worker_loss("sess", reason="session_closed")
    assert len(harness.recorded) == 1
