"""Direct-call coverage for the bounded-trace mixin (``core/service_trace.py``).

The trace surface talks to a live x64dbg worker, but its argument guards, status
validation, artifact finalisation and API-argument decoding are all
self-contained enough to drive with a fake worker/runtime and a ``TraceMixin``
subclass. These tests pin the honesty properties the module is built around: a
partial trace is finalised rather than lost, an over-quota artifact is truncated
and marked partial, and a status that cannot be trusted is a failure rather than
a fabricated success.
"""

from __future__ import annotations

from pathlib import Path
from threading import RLock
from types import SimpleNamespace
from typing import Any, cast

import pytest

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import Architecture, Result, RpcError
from headless_re_mcp.core.runtime_state import TraceStateOwner
from headless_re_mcp.core.service_trace import (
    TraceMixin,
    _instruction_pointer,
    _register_arguments,
    _stack_arguments,
    _TraceArtifactState,
)


def _ok(data: dict[str, Any]) -> Result[dict[str, Any]]:
    return Result[dict[str, Any]](ok=True, data=data)


def _err(code: str, message: str = "boom") -> Result[dict[str, Any]]:
    return Result[dict[str, Any]](ok=False, error=RpcError(code=code, message=message))


# --------------------------------------------------------------------------- #
# Layer 1a: pure argument/pointer decoders
# --------------------------------------------------------------------------- #


def test_register_arguments_rejects_non_dict_and_nonpositive_count() -> None:
    assert _register_arguments(None, 4) == []
    assert _register_arguments({"rcx": 1}, 0) == []


def test_register_arguments_reads_nested_bank_and_flags_unusable() -> None:
    payload = {"registers": {"rcx": 5, "rdx": True, "r8": "nope"}}
    decoded = _register_arguments(payload, 3)
    assert [a["value"] for a in decoded] == [5, None, None]
    assert [a["source"] for a in decoded] == ["rcx", "rdx", "r8"]
    assert [a["index"] for a in decoded] == [0, 1, 2]


def test_stack_arguments_defaults_and_edges() -> None:
    assert _stack_arguments(None, 2) == []
    assert _stack_arguments({"entries": "not-a-list"}, 2) == []
    payload = {
        "entries": [{"value": 0xDEAD}, {"value": 0xA}, {"value": True}],
        # pointer_size omitted -> defaults to 4
    }
    decoded = _stack_arguments(payload, 3)
    # slot 1 -> 0xA, slot 2 -> bool rejected -> None, slot 3 missing -> None
    assert [a["value"] for a in decoded] == [0xA, None, None]
    assert decoded[0]["source"] == "[esp+0x4]"


def test_stack_arguments_honours_pointer_size() -> None:
    payload = {"entries": [{"value": 0}, {"value": 1}], "pointer_size": 8}
    decoded = _stack_arguments(payload, 1)
    assert decoded[0]["source"] == "[esp+0x8]"


def test_instruction_pointer_variants() -> None:
    assert _instruction_pointer(None) is None
    assert _instruction_pointer({"registers": {"rip": 0x1000}}) == 0x1000
    assert _instruction_pointer({"eip": 0x2000}) == 0x2000
    assert _instruction_pointer({"pc": True}) is None
    assert _instruction_pointer({"nothing": 1}) is None


# --------------------------------------------------------------------------- #
# Layer 1b: _validate_trace_status
# --------------------------------------------------------------------------- #


# Unbound mixin calls need a stand-in self; none of these arcs touch it.
def _mixin_self() -> TraceMixin:
    return cast(TraceMixin, object())


def _state(
    tmp_path: Path, session_id: str = "s", *, content: bytes | None = b"", **over: Any
) -> _TraceArtifactState:
    root = tmp_path / "trace" / session_id
    root.mkdir(parents=True, exist_ok=True)
    path = (root / "run.trace64").resolve()
    if content is not None:
        path.write_bytes(content)
    state = _TraceArtifactState(
        session_id=session_id,
        path=path,
        requested_path="C:/ignored.trace",
        max_events=over.pop("max_events", 1000),
        timeout_ms=over.pop("timeout_ms", 60_000),
        max_file_bytes=over.pop("max_file_bytes", 65_536),
        started_monotonic=0.0,
    )
    for key, value in over.items():
        setattr(state, key, value)
    return state


def _valid_status(state: _TraceArtifactState, **over: Any) -> dict[str, Any]:
    status = {
        "recording": True,
        "path": str(state.path),
        "max_events": state.max_events,
        "timeout_ms": state.timeout_ms,
        "max_file_bytes": state.max_file_bytes,
        "events_written": 0,
        "file_bytes": 0,
        "elapsed_ms": 0,
        "stop_reason": "running",
    }
    status.update(over)
    return status


def test_validate_status_rejects_non_object(tmp_path: Path) -> None:
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(
            _mixin_self(), _state(tmp_path), cast(dict[str, Any], ["not", "a", "dict"])
        )
    assert info.value.code == "rpc_protocol_error"


def test_validate_status_requires_boolean_recording(tmp_path: Path) -> None:
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(
            _mixin_self(), state, _valid_status(state, recording="yes")
        )
    assert "boolean recording" in str(info.value)


def test_validate_status_enforces_required_recording_state(tmp_path: Path) -> None:
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError) as start:
        TraceMixin._validate_trace_status(
            _mixin_self(), state, _valid_status(state, recording=False), require_recording=True
        )
    assert start.value.code == "trace_start_failed"
    with pytest.raises(XdbgRpcError) as stop:
        TraceMixin._validate_trace_status(
            _mixin_self(), state, _valid_status(state, recording=True), require_recording=False
        )
    assert stop.value.code == "trace_stop_failed"


def test_validate_status_rejects_unresolvable_path(tmp_path: Path) -> None:
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(_mixin_self(), state, _valid_status(state, path="\x00"))
    assert "invalid artifact path" in str(info.value)


def test_validate_status_rejects_foreign_path(tmp_path: Path) -> None:
    state = _state(tmp_path)
    other = str((tmp_path / "elsewhere.trace").resolve())
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(_mixin_self(), state, _valid_status(state, path=other))
    assert "does not match the session-owned artifact" in str(info.value)


def test_validate_status_rejects_wrong_quota_field(tmp_path: Path) -> None:
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(
            _mixin_self(), state, _valid_status(state, max_events=state.max_events + 1)
        )
    assert "invalid max_events" in str(info.value)


def test_validate_status_rejects_negative_counter(tmp_path: Path) -> None:
    state = _state(tmp_path)
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(
            _mixin_self(), state, _valid_status(state, events_written=-1)
        )
    assert "invalid events_written" in str(info.value)


def test_validate_status_fills_omitted_optionals(tmp_path: Path) -> None:
    state = _state(tmp_path)
    payload = {"recording": True, "path": str(state.path)}
    data = TraceMixin._validate_trace_status(_mixin_self(), state, payload)
    assert data["max_events"] == state.max_events
    assert data["events_written"] == 0
    assert data["stop_reason"] == "none"


def test_validate_status_flags_quota_violation(tmp_path: Path) -> None:
    state = _state(tmp_path, max_events=5)
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(
            _mixin_self(), state, _valid_status(state, events_written=6)
        )
    assert info.value.code == "trace_quota_violation"


def test_validate_status_flags_file_byte_quota(tmp_path: Path) -> None:
    state = _state(tmp_path, content=b"x" * 20, max_file_bytes=8)
    with pytest.raises(XdbgRpcError) as info:
        TraceMixin._validate_trace_status(_mixin_self(), state, _valid_status(state, file_bytes=0))
    assert info.value.code == "trace_quota_violation"


# --------------------------------------------------------------------------- #
# Layer 1c: _trace_result_payload / _attach_trace_artifact_details
# --------------------------------------------------------------------------- #


def test_trace_result_payload_marks_session_ownership(tmp_path: Path) -> None:
    state = _state(tmp_path, artifact_id="art-9", artifact_size=12, active=False)
    payload = TraceMixin._trace_result_payload(_mixin_self(), state, {"recording": False})
    assert payload["session_owned"] is True
    assert payload["artifact_registered"] is True
    assert payload["artifact_pending"] is False
    assert payload["path"] == str(state.path)
    assert payload["requested_path"] == "C:/ignored.trace"


def test_attach_trace_artifact_details_copies_state(tmp_path: Path) -> None:
    state = _state(tmp_path, artifact_id="art-1", artifact_sha256="abc", artifact_size=7)
    error = XdbgRpcError("trace_stop_failed", "stop failed")
    TraceMixin._attach_trace_artifact_details(_mixin_self(), error, state)
    assert error.details["artifact_id"] == "art-1"
    assert error.details["artifact_sha256"] == "abc"
    assert error.details["artifact_size"] == 7


# --------------------------------------------------------------------------- #
# Harness for the self-using helpers and the public lifecycle methods
# --------------------------------------------------------------------------- #


class _TraceService(TraceMixin):
    def __init__(
        self,
        tmp_path: Path,
        *,
        arch: Architecture = Architecture.X64,
        worker: Any = None,
        record_raise: BaseException | None = None,
    ) -> None:
        self.settings = SimpleNamespace(artifact_root=tmp_path)  # type: ignore[assignment]
        self._lock = RLock()
        self._trace_owner = TraceStateOwner()
        self.registry = SimpleNamespace(  # type: ignore[assignment]
            get=lambda sid: SimpleNamespace(require_architecture=lambda: arch)
        )
        self._runtime_obj = SimpleNamespace(lock=RLock(), worker=worker)
        self.records: list[dict[str, Any]] = []
        self._record_raise = record_raise
        self.failed: list[tuple[str, Any]] = []

    def _runtime(self, session_id: str, kind: Any) -> Any:
        return self._runtime_obj

    def _require_current_runtime(self, *args: Any, **kwargs: Any) -> None:
        return None

    def _fail_runtime(self, session_id: str, kind: Any, *, failure: Any = None) -> None:
        self.failed.append((session_id, failure))

    def record_artifact(self, **fields: Any) -> dict[str, Any]:
        if self._record_raise is not None:
            raise self._record_raise
        record = {"id": f"art-{len(self.records) + 1}", **fields}
        self.records.append(record)
        return record


# --------------------------------------------------------------------------- #
# Layer 1d: _new_trace_artifact_path / _finalize_trace_artifact /
#           _finalize_trace_after_worker_loss / _stop_trace_after_failure
# --------------------------------------------------------------------------- #


def test_new_trace_artifact_path_rejects_bad_session_id(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    with pytest.raises(ValueError, match="invalid session id"):
        svc._new_trace_artifact_path("../escape")


def test_new_trace_artifact_path_uses_arch_suffix(tmp_path: Path) -> None:
    x64 = _TraceService(tmp_path, arch=Architecture.X64)._new_trace_artifact_path("s")
    x86 = _TraceService(tmp_path, arch=Architecture.X86)._new_trace_artifact_path("s")
    assert x64.suffix == ".trace64"
    assert x86.suffix == ".trace32"
    assert x64.parent == (tmp_path / "trace" / "s").resolve()


def test_finalize_registers_a_within_quota_artifact(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    state = _state(tmp_path, content=b"trace-bytes")
    svc._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_id == "art-1"
    assert state.artifact_truncated is False
    assert svc.records[0]["kind"] == "run_trace"
    assert state.terminal_reason == "stopped"
    assert state.active is False


def test_finalize_truncates_and_marks_partial_over_quota(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    state = _state(tmp_path, content=b"x" * 40, max_file_bytes=8)
    svc._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_truncated is True
    assert state.terminal_reason == "quota_violation"
    assert svc.records[0]["kind"] == "run_trace_partial"
    assert state.path.stat().st_size == 8


def test_finalize_reports_missing_file(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    state = _state(tmp_path, content=None)
    svc._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_id is None
    assert state.artifact_error == "trace artifact file is missing"


def test_finalize_refuses_artifact_outside_session_root(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    stray = (tmp_path / "outside" / "run.trace64").resolve()
    stray.parent.mkdir(parents=True, exist_ok=True)
    stray.write_bytes(b"data")
    state = _TraceArtifactState(
        session_id="s",
        path=stray,
        requested_path="C:/x",
        max_events=10,
        timeout_ms=10,
        max_file_bytes=1024,
        started_monotonic=0.0,
    )
    svc._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_error == "trace artifact is outside its session-owned root"


def test_finalize_is_idempotent_once_registered(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    state = _state(tmp_path, content=b"abc", artifact_id="already")
    svc._finalize_trace_artifact(state, terminal_reason="stopped")
    assert svc.records == []
    assert state.terminal_reason == "stopped"


def test_finalize_captures_record_artifact_failure(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, record_raise=ValueError("db down"))
    state = _state(tmp_path, content=b"abc")
    svc._finalize_trace_artifact(state, terminal_reason="stopped")
    assert state.artifact_id is None
    assert state.artifact_error == "db down"


def test_finalize_after_worker_loss_finalizes_live_state(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    state = _state(tmp_path, content=b"abc")
    svc._trace_owner.put("s", state)
    svc._finalize_trace_after_worker_loss("s", reason="target_exited")
    assert state.active is False
    assert state.last_status["recording"] is False
    assert state.last_status["failed"] is False
    assert state.artifact_id == "art-1"


def test_finalize_after_worker_loss_flags_unexpected_reason(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    state = _state(tmp_path, content=b"abc")
    svc._trace_owner.put("s", state)
    svc._finalize_trace_after_worker_loss("s", reason="worker_exited")
    assert state.last_status["failed"] is True


def test_finalize_after_worker_loss_ignores_missing_or_registered(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    # No state for this session: nothing to do, must not raise.
    svc._finalize_trace_after_worker_loss("gone", reason="target_exited")
    already = _state(tmp_path, content=b"abc", artifact_id="done")
    svc._trace_owner.put("s", already)
    svc._finalize_trace_after_worker_loss("s", reason="target_exited")
    assert svc.records == []


class _StopWorker:
    def __init__(self, capabilities: tuple[str, ...], reply: Any) -> None:
        self.capabilities = set(capabilities)
        self._reply = reply

    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        if isinstance(self._reply, BaseException):
            raise self._reply
        return self._reply


def test_stop_after_failure_returns_false_without_capability(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    runtime = SimpleNamespace(lock=RLock(), worker=_StopWorker((), {"recording": False}))
    assert svc._stop_trace_after_failure(cast(Any, runtime), _state(tmp_path)) is False


def test_stop_after_failure_returns_false_when_still_recording(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    worker = _StopWorker(("trace.stop",), {"recording": True})
    runtime = SimpleNamespace(lock=RLock(), worker=worker)
    assert svc._stop_trace_after_failure(cast(Any, runtime), _state(tmp_path)) is False


def test_stop_after_failure_true_on_clean_stop(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    state = _state(tmp_path)
    worker = _StopWorker(("trace.stop",), {"recording": False, "stop_reason": "cancelled"})
    runtime = SimpleNamespace(lock=RLock(), worker=worker)
    assert svc._stop_trace_after_failure(cast(Any, runtime), state) is True
    assert state.active is False


def test_stop_after_failure_swallows_worker_exception(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path)
    worker = _StopWorker(("trace.stop",), RuntimeError("dead"))
    runtime = SimpleNamespace(lock=RLock(), worker=worker)
    assert svc._stop_trace_after_failure(cast(Any, runtime), _state(tmp_path)) is False


# --------------------------------------------------------------------------- #
# Layer 2: trace_api_arguments
# --------------------------------------------------------------------------- #


class _ApiArgsService:
    def __init__(self, arch: Architecture = Architecture.X64) -> None:
        self.registry = SimpleNamespace(
            get=lambda sid: SimpleNamespace(require_architecture=lambda: arch)
        )
        self.symbols: Result[dict[str, Any]] | None = None
        self.bp_set: Result[dict[str, Any]] = _ok({"set": True})
        self.removed: list[int] = []
        self.resumes: list[Result[dict[str, Any]]] = []
        self.registers: list[Result[dict[str, Any]]] = []
        self.stacks: list[Result[dict[str, Any]]] = []

    def symbols_resolve(self, sid: str, expr: str, *, timeout: float) -> Result[dict[str, Any]]:
        assert self.symbols is not None
        return self.symbols

    def dynamic_breakpoint_set(
        self, sid: str, addr: int, *, address_space: str = "runtime"
    ) -> Result[dict[str, Any]]:
        return self.bp_set

    def dynamic_breakpoint_remove(self, sid: str, addr: int) -> Result[dict[str, Any]]:
        self.removed.append(addr)
        return _ok({"removed": True})

    def dynamic_resume(
        self, sid: str, *, wait_for_pause: bool = False, timeout: float = 30.0
    ) -> Result[dict[str, Any]]:
        return self.resumes.pop(0)

    def dynamic_registers_read(self, sid: str) -> Result[dict[str, Any]]:
        return self.registers.pop(0)

    def stack_read(
        self, sid: str, *, address: int | None = None, count: int = 32, timeout: float = 30.0
    ) -> Result[dict[str, Any]]:
        return self.stacks.pop(0)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({}, "exactly one of expression or address"),
        ({"address": 0x1000, "max_hits": 0}, "max_hits"),
        ({"address": 0x1000, "argument_count": 99}, "argument_count"),
        ({"address": 0x1000, "timeout": "slow"}, "timeout must be a number"),
        ({"address": 0x1000, "timeout": 0.0}, "timeout must be > 0"),
    ],
)
def test_api_arguments_argument_guards(kwargs: dict[str, Any], message: str) -> None:
    svc = _ApiArgsService()
    result = TraceMixin.trace_api_arguments(cast(TraceMixin, svc), "s", **kwargs)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"
    assert message in result.error.message


def test_api_arguments_x64_register_capture() -> None:
    svc = _ApiArgsService(Architecture.X64)
    svc.resumes = [_ok({}), _ok({})]
    svc.registers = [
        _ok({"rip": 0x1000, "rcx": 1, "rdx": 2}),
        _ok({"rip": 0x1000, "rcx": 3, "rdx": 4}),
    ]
    result = TraceMixin.trace_api_arguments(
        cast(TraceMixin, svc), "s", address=0x1000, max_hits=2, argument_count=2
    )
    assert result.ok is True
    assert result.data is not None
    assert result.data["hit_count"] == 2
    assert result.data["truncated"] is True
    assert result.data["convention"] == "microsoft_x64_integer_registers"
    assert [a["value"] for a in result.data["hits"][0]["arguments"]] == [1, 2]
    assert svc.removed == [0x1000]


def test_api_arguments_x86_stack_capture() -> None:
    svc = _ApiArgsService(Architecture.X86)
    svc.resumes = [_ok({})]
    svc.registers = [_ok({"eip": 0x1000})]
    svc.stacks = [
        _ok({"entries": [{"value": 0}, {"value": 0xA}, {"value": 0xB}], "pointer_size": 4})
    ]
    result = TraceMixin.trace_api_arguments(
        cast(TraceMixin, svc), "s", address=0x1000, max_hits=1, argument_count=2
    )
    assert result.ok is True
    assert result.data is not None
    assert result.data["convention"] == "x86_stack_arguments"
    assert [a["value"] for a in result.data["hits"][0]["arguments"]] == [0xA, 0xB]


def test_api_arguments_resolves_symbol_expression() -> None:
    svc = _ApiArgsService(Architecture.X64)
    svc.symbols = _ok({"address": 0x2000})
    svc.resumes = [_ok({})]
    svc.registers = [_ok({"rip": 0x2000, "rcx": 7})]
    result = TraceMixin.trace_api_arguments(
        cast(TraceMixin, svc), "s", expression="malloc", max_hits=1
    )
    assert result.ok is True
    assert result.data is not None
    assert result.data["target"]["address"] == 0x2000
    assert result.data["target"]["resolution"] == {"address": 0x2000}


def test_api_arguments_passes_through_symbol_failure() -> None:
    svc = _ApiArgsService(Architecture.X64)
    svc.symbols = _err("symbol_not_found")
    result = TraceMixin.trace_api_arguments(cast(TraceMixin, svc), "s", expression="nope")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "symbol_not_found"
    assert svc.removed == []


def test_api_arguments_rejects_non_address_resolution() -> None:
    svc = _ApiArgsService(Architecture.X64)
    svc.symbols = _ok({"address": "0x2000"})
    result = TraceMixin.trace_api_arguments(cast(TraceMixin, svc), "s", expression="weird")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"
    assert "did not return an address" in result.error.message


def test_api_arguments_returns_breakpoint_failure() -> None:
    svc = _ApiArgsService(Architecture.X64)
    svc.bp_set = _err("breakpoint_failed")
    result = TraceMixin.trace_api_arguments(cast(TraceMixin, svc), "s", address=0x1000)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "breakpoint_failed"
    assert svc.removed == []


def test_api_arguments_stops_on_foreign_break() -> None:
    svc = _ApiArgsService(Architecture.X64)
    svc.resumes = [_ok({})]
    svc.registers = [_ok({"rip": 0x9999})]
    result = TraceMixin.trace_api_arguments(cast(TraceMixin, svc), "s", address=0x1000, max_hits=3)
    assert result.ok is True
    assert result.data is not None
    assert result.data["stopped_elsewhere"] is True
    assert result.data["hit_count"] == 0
    assert svc.removed == [0x1000]


def test_api_arguments_breaks_on_resume_failure() -> None:
    svc = _ApiArgsService(Architecture.X64)
    svc.resumes = [_err("resume_failed")]
    result = TraceMixin.trace_api_arguments(cast(TraceMixin, svc), "s", address=0x1000, max_hits=3)
    assert result.ok is True
    assert result.data is not None
    assert result.data["hit_count"] == 0
    assert result.data["stopped_elsewhere"] is False
    assert svc.removed == [0x1000]


# --------------------------------------------------------------------------- #
# Layer 3: trace_start / trace_status / trace_stop against a fake worker
# --------------------------------------------------------------------------- #


class _LifecycleWorker:
    """A minimal x64dbg trace worker: creates the artifact and echoes quotas."""

    def __init__(
        self, capabilities: tuple[str, ...] = ("trace.start", "trace.stop", "trace.status")
    ):
        self.capabilities = set(capabilities)
        self._status: dict[str, Any] | None = None
        self.calls: list[str] = []

    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        self.calls.append(method)
        if method == "trace.start":
            Path(params["path"]).write_bytes(b"")
            self._status = {
                "recording": True,
                "path": params["path"],
                "max_events": params["max_events"],
                "timeout_ms": params["timeout_ms"],
                "max_file_bytes": params["max_file_bytes"],
                "events_written": 0,
                "file_bytes": 0,
                "elapsed_ms": 0,
                "stop_reason": "none",
            }
            return dict(self._status)
        if method == "trace.status":
            assert self._status is not None
            return dict(self._status)
        if method == "trace.stop":
            if self._status is None:
                return {"recording": False, "stop_reason": "stopped"}
            self._status = {**self._status, "recording": False, "stop_reason": "stopped"}
            return dict(self._status)
        raise AssertionError(method)


def test_trace_start_status_stop_happy_path(tmp_path: Path) -> None:
    worker = _LifecycleWorker()
    svc = _TraceService(tmp_path, worker=worker)

    started = svc.trace_start(
        "s", "C:/req.trace", max_events=100, timeout_ms=1000, max_file_bytes=4096
    )
    assert started.ok is True
    assert started.data is not None
    assert started.data["recording"] is True
    assert started.data["artifact_registered"] is False
    artifact_path = Path(started.data["artifact_path"])
    assert artifact_path.is_file()

    status = svc.trace_status("s")
    assert status.ok is True
    assert status.data is not None
    assert status.data["recording"] is True

    stopped = svc.trace_stop("s")
    assert stopped.ok is True
    assert stopped.data is not None
    assert stopped.data["recording"] is False
    assert stopped.data["artifact_registered"] is True
    assert svc.records[0]["kind"] == "run_trace"


def test_trace_start_rejects_bad_parameters(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_LifecycleWorker())
    assert svc.trace_start("s", "").error.code == "invalid_params"  # type: ignore[union-attr]
    assert svc.trace_start("s", "p", max_events=0).error.code == "invalid_params"  # type: ignore[union-attr]
    assert svc.trace_start("s", "p", timeout_ms=0).error.code == "invalid_params"  # type: ignore[union-attr]
    bad_bytes = svc.trace_start("s", "p", max_file_bytes=0)
    assert bad_bytes.error is not None
    assert bad_bytes.error.code == "invalid_params"


def test_trace_start_without_capability_is_unavailable(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_LifecycleWorker(capabilities=()))
    result = svc.trace_start("s", "C:/req.trace")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"
    assert svc.failed == []


def test_trace_start_refuses_second_active_trace(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_LifecycleWorker())
    assert svc.trace_start("s", "C:/a.trace").ok is True
    again = svc.trace_start("s", "C:/b.trace")
    assert again.ok is False
    assert again.error is not None
    assert again.error.code == "already_tracing"


def test_trace_start_reports_insufficient_disk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    svc = _TraceService(tmp_path, worker=_LifecycleWorker())
    monkeypatch.setattr(
        "headless_re_mcp.core.service_trace.shutil.disk_usage",
        lambda _p: SimpleNamespace(total=1, used=1, free=0),
    )
    result = svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "insufficient_disk_space"


def test_trace_stop_without_state_passes_through(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_LifecycleWorker())
    result = svc.trace_stop("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["recording"] is False


def test_trace_status_without_state_passes_through(tmp_path: Path) -> None:
    worker = _LifecycleWorker()
    worker._status = {"recording": False, "stop_reason": "idle"}
    svc = _TraceService(tmp_path, worker=worker)
    result = svc.trace_status("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["recording"] is False


def test_trace_status_enforces_quota_with_service_side_stop(tmp_path: Path) -> None:
    class _QuotaWorker(_LifecycleWorker):
        def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
            self.calls.append(method)
            if method == "trace.start":
                Path(params["path"]).write_bytes(b"")
                self._status = {
                    "recording": True,
                    "path": params["path"],
                    "max_events": params["max_events"],
                    "timeout_ms": params["timeout_ms"],
                    "max_file_bytes": params["max_file_bytes"],
                    "events_written": params["max_events"],
                    "file_bytes": 0,
                    "elapsed_ms": 0,
                    "stop_reason": "none",
                }
                return dict(self._status)
            if method == "trace.status":
                assert self._status is not None
                return dict(self._status)
            if method == "trace.stop":
                assert self._status is not None
                self._status = {**self._status, "recording": False, "stop_reason": "stopped"}
                return dict(self._status)
            raise AssertionError(method)

    worker = _QuotaWorker()
    svc = _TraceService(tmp_path, worker=worker)
    svc.trace_start("s", "C:/req.trace", max_events=5, timeout_ms=1000, max_file_bytes=4096)
    status = svc.trace_status("s")
    assert status.ok is True
    assert status.data is not None
    assert status.data["recording"] is False
    assert "trace.stop" in worker.calls
    assert svc.records[0]["kind"] == "run_trace"


# --------------------------------------------------------------------------- #
# Layer 3b: lifecycle failure handlers
# --------------------------------------------------------------------------- #


class _StartNeverRecordsWorker:
    """trace.start writes a file but reports it never entered recording."""

    def __init__(self) -> None:
        self.capabilities = {"trace.start"}
        self.calls: list[str] = []

    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        self.calls.append(method)
        if method == "trace.start":
            Path(params["path"]).write_bytes(b"partial")
            return {
                "recording": False,
                "path": params["path"],
                "max_events": params["max_events"],
                "timeout_ms": params["timeout_ms"],
                "max_file_bytes": params["max_file_bytes"],
                "events_written": 0,
                "file_bytes": 0,
                "elapsed_ms": 0,
            }
        raise AssertionError(method)


def test_trace_start_failure_finalizes_partial_and_fails_runtime(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StartNeverRecordsWorker())
    result = svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "trace_start_failed"
    # No trace.stop capability means the stop could not be confirmed, so the
    # analyzer is torn down and the bounded partial is still registered.
    assert svc.failed
    assert result.error.details.get("artifact_path")
    assert svc.records[0]["kind"] == "run_trace"


class _StartNoFileWorker:
    def __init__(self) -> None:
        self.capabilities = {"trace.start", "trace.stop"}
        self.calls: list[str] = []

    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        self.calls.append(method)
        if method == "trace.start":
            return {
                "recording": True,
                "path": params["path"],
                "max_events": params["max_events"],
                "timeout_ms": params["timeout_ms"],
                "max_file_bytes": params["max_file_bytes"],
                "events_written": 0,
                "file_bytes": 0,
                "elapsed_ms": 0,
            }
        if method == "trace.stop":
            return {"recording": False, "stop_reason": "stopped"}
        raise AssertionError(method)


def test_trace_start_missing_artifact_is_failure(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StartNoFileWorker())
    result = svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "artifact_missing"


class _StartBoomWorker:
    def __init__(self) -> None:
        self.capabilities = {"trace.start", "trace.stop"}

    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        if method == "trace.start":
            raise RuntimeError("worker crashed")
        if method == "trace.stop":
            return {"recording": False}
        raise AssertionError(method)


def test_trace_start_unexpected_error_terminates_runtime(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StartBoomWorker())
    result = svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"
    assert svc.failed


class _StopBoomWorker(_LifecycleWorker):
    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        if method == "trace.stop":
            raise XdbgRpcError("trace_stop_failed", "stop exploded")
        return super().request(method, params, timeout=timeout)


def test_trace_stop_worker_error_finalizes_partial(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StopBoomWorker())
    svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    result = svc.trace_stop("s")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "trace_stop_failed"
    assert svc.failed
    assert result.error.details.get("artifact_path")


def test_trace_stop_without_capability_is_unavailable(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_LifecycleWorker(capabilities=("trace.start",)))
    result = svc.trace_stop("s")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_trace_status_without_capability_is_unavailable(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_LifecycleWorker(capabilities=("trace.start",)))
    result = svc.trace_status("s")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


class _StatusBoomWorker(_LifecycleWorker):
    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        if method == "trace.status":
            raise XdbgRpcError("rpc_transport_error", "status exploded")
        return super().request(method, params, timeout=timeout)


def test_trace_status_fatal_worker_error_on_active_trace(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StatusBoomWorker())
    svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    result = svc.trace_status("s")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "rpc_transport_error"
    assert svc.failed


class _StopCrashWorker(_LifecycleWorker):
    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        if method == "trace.stop":
            raise RuntimeError("crash")
        return super().request(method, params, timeout=timeout)


def test_trace_stop_unexpected_error_terminates_runtime(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StopCrashWorker())
    svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    result = svc.trace_stop("s")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"
    assert svc.failed


class _StatusCrashWorker(_LifecycleWorker):
    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        if method == "trace.status":
            raise RuntimeError("crash")
        return super().request(method, params, timeout=timeout)


def test_trace_status_unexpected_error_on_active_trace(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StatusCrashWorker())
    svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    result = svc.trace_status("s")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "internal_error"
    assert svc.failed


class _StatusBoomAfterStopWorker(_LifecycleWorker):
    def request(self, method: str, params: Any = None, *, timeout: float | None = None) -> Any:
        already_stopped = self._status is not None and self._status.get("recording") is False
        if method == "trace.status" and already_stopped:
            raise XdbgRpcError("rpc_transport_error", "late status poll")
        return super().request(method, params, timeout=timeout)


def test_trace_status_stale_poll_after_finalize_returns_cached_success(tmp_path: Path) -> None:
    svc = _TraceService(tmp_path, worker=_StatusBoomAfterStopWorker())
    svc.trace_start("s", "C:/req.trace", max_file_bytes=4096)
    svc.trace_stop("s")
    # A status poll after the trace already finalised must not tear down the
    # session; it replays the cached terminal status as a success.
    result = svc.trace_status("s")
    assert result.ok is True
    assert result.data is not None
    assert result.data["recording"] is False
    assert result.data["artifact_registered"] is True
    assert svc.failed == []
