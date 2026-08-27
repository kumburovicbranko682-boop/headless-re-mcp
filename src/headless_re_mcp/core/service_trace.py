"""Bounded instruction tracing and API-argument capture.

Split out of AnalysisService. A trace is the one debugger operation that writes
an unbounded amount of data, so every entry point here carries an explicit event,
byte and time budget, and the artifact is finalised even when the worker dies
mid-trace -- a partial trace with a stop reason is useful, a lost one is not.

Behaviour is unchanged by the move. _TraceArtifactState travels with it and is
imported back by AnalysisService, which owns the state map.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT
from headless_re_mcp.core.models import Architecture, BackendKind, Result, RpcError
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_static import _FATAL_WORKER_ERRORS
from headless_re_mcp.core.session import file_sha256

if TYPE_CHECKING:
    from threading import RLock

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.repository import AnalysisRepository
    from headless_re_mcp.core.runtime_state import TraceStateOwner
    from headless_re_mcp.core.service import _BackendRuntime
    from headless_re_mcp.core.session import SessionRegistry

JsonObject = dict[str, Any]

# Only used by the argument decoder that moved here with the trace surface.
_X64_ARGUMENT_REGISTERS = ("rcx", "rdx", "r8", "r9")

_UINT64_MODULUS = 1 << 64


def normalize_register_signedness(payload: JsonObject | None) -> None:
    """Fold two's-complement register values back to unsigned, in place.

    The native shim serializes every 64-bit register through jansson's signed
    ``json_int_t``, so a register whose high bit is set -- ``rax`` holding a -1
    return value (``0xFFFFFFFFFFFFFFFF``), a packed handle, a pointer with the
    top bit set -- arrives here as a negative Python int. A debugger presents
    register contents as unsigned, and the argument/pointer decoders below read
    these values directly, so a negative ``rcx`` would surface to the AI as a
    negative function argument rather than the address it is. Reinterpret each
    negative register as its unsigned 64-bit value; non-negative values (all of
    x86, ``eflags`` and the debug registers, any user-mode ``rip``) are left
    untouched.
    """
    if not isinstance(payload, dict):
        return
    nested = payload.get("registers")
    bank = nested if isinstance(nested, dict) else payload
    if not isinstance(bank, dict):
        return
    for name, value in bank.items():
        if type(value) is int and value < 0:
            bank[name] = value + _UINT64_MODULUS


@dataclass(slots=True)
class _TraceArtifactState:
    session_id: str
    path: Path
    requested_path: str
    max_events: int
    timeout_ms: int
    max_file_bytes: int
    started_monotonic: float
    active: bool = True
    terminal_reason: str = "none"
    artifact_id: str | None = None
    artifact_sha256: str | None = None
    artifact_size: int | None = None
    artifact_truncated: bool = False
    artifact_error: str | None = None
    last_status: JsonObject = field(default_factory=dict)


def _register_arguments(registers: JsonObject | None, count: int) -> list[JsonObject]:
    """Decode Microsoft x64 integer arguments from a registers payload."""
    if not isinstance(registers, dict) or count <= 0:
        return []
    nested = registers.get("registers")
    bank = nested if isinstance(nested, dict) else registers
    arguments: list[JsonObject] = []
    for index, name in enumerate(_X64_ARGUMENT_REGISTERS[:count]):
        value = bank.get(name)
        usable = isinstance(value, int) and not isinstance(value, bool)
        arguments.append(
            {
                "index": index,
                "source": name,
                "value": value if usable else None,
            }
        )
    return arguments
def _stack_arguments(payload: JsonObject | None, count: int) -> list[JsonObject]:
    """Decode x86 cdecl/stdcall arguments sitting above the return address.

    At a function entry the top of stack holds the return address, so argument i
    lives at slot i+1 of a stack.read starting from the stack pointer.
    """
    if not isinstance(payload, dict) or count <= 0:
        return []
    entries = payload.get("entries")
    if not isinstance(entries, list):
        return []
    raw_width = payload.get("pointer_size")
    width = raw_width if isinstance(raw_width, int) and raw_width > 0 else 4
    arguments: list[JsonObject] = []
    for index in range(count):
        slot = index + 1
        entry = entries[slot] if slot < len(entries) else None
        value = entry.get("value") if isinstance(entry, dict) else None
        usable = isinstance(value, int) and not isinstance(value, bool)
        arguments.append(
            {
                "index": index,
                "source": f"[esp+{slot * width:#x}]",
                "value": value if usable else None,
            }
        )
    return arguments
def _instruction_pointer(registers: JsonObject | None) -> int | None:
    """Read rip/eip/pc from a registers payload without assuming one shape."""
    if not isinstance(registers, dict):
        return None
    nested = registers.get("registers")
    bank = nested if isinstance(nested, dict) else registers
    for name in ("rip", "eip", "pc"):
        candidate = bank.get(name)
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            return candidate
    return None


class TraceMixin:
    """Start, stop and finalise bounded traces."""

    settings: Settings
    registry: SessionRegistry
    repository: AnalysisRepository
    _lock: RLock
    _trace_owner: TraceStateOwner[_TraceArtifactState]

    if TYPE_CHECKING:

        def record_artifact(self, **fields: Any) -> JsonObject: ...

        def _runtime(self, session_id: str, kind: BackendKind) -> _BackendRuntime: ...

        def _require_current_runtime(
            self,
            session_id: str,
            kind: BackendKind,
            runtime: _BackendRuntime,
        ) -> None: ...

        def _fail_runtime(
            self,
            session_id: str,
            kind: BackendKind,
            *,
            failure: BaseException | None = None,
        ) -> None: ...

        def dynamic_registers_read(self, session_id: str) -> Result[JsonObject]: ...

        def dynamic_resume(
            self,
            session_id: str,
            *,
            wait_for_pause: bool = False,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def dynamic_breakpoint_set(
            self,
            session_id: str,
            address: int,
            *,
            address_space: str = "runtime",
        ) -> Result[JsonObject]: ...

        def dynamic_breakpoint_remove(
            self,
            session_id: str,
            address: int,
        ) -> Result[JsonObject]: ...

        def stack_read(
            self,
            session_id: str,
            *,
            address: int | None = None,
            count: int = 32,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def symbols_resolve(
            self,
            session_id: str,
            expression: str,
            *,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

    def trace_start(
        self,
        session_id: str,
        path: str,
        *,
        max_events: int = 10_000,
        timeout_ms: int = 60_000,
        max_file_bytes: int = 16 * 1024 * 1024,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        if not isinstance(path, str) or not path:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="path must be a non-empty string"),
            )
        if type(max_events) is not int or not 1 <= max_events <= 1_000_000:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="max_events out of range"),
            )
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 3_600_000:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="timeout_ms out of range"),
            )
        if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= 256 * 1024 * 1024:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_params", message="max_file_bytes out of range"),
            )
        state: _TraceArtifactState | None = None
        runtime: _BackendRuntime | None = None
        state_registered = False
        try:
            output_path = self._new_trace_artifact_path(session_id)
            free_bytes = shutil.disk_usage(output_path.parent).free
            if free_bytes < max_file_bytes:
                raise XdbgRpcError(
                    "insufficient_disk_space",
                    "available disk space is smaller than the requested trace quota",
                    details={
                        "available_disk_bytes": free_bytes,
                        "required_disk_bytes": max_file_bytes,
                        "artifact_directory": str(output_path.parent),
                    },
                    retryable=True,
                )
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            state = _TraceArtifactState(
                session_id=session_id,
                path=output_path,
                requested_path=path,
                max_events=max_events,
                timeout_ms=timeout_ms,
                max_file_bytes=max_file_bytes,
                started_monotonic=monotonic(),
            )
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "trace.start" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide trace.start",
                        details={"capability": "trace.start"},
                    )
                existing = self._trace_owner.put_if_inactive(
                    session_id,
                    state,
                    is_active=lambda item: item.active,
                )
                if existing is not None:
                    raise XdbgRpcError(
                        "already_tracing",
                        "stop or finalize the active session trace before starting another",
                        details={"path": str(existing.path)},
                    )
                state_registered = True
                native = runtime.worker.request(
                    "trace.start",
                    {
                        # Caller paths are never trusted as output destinations.  Every
                        # run trace is placed in this session's artifact subtree.
                        "path": str(output_path),
                        "max_events": max_events,
                        "timeout_ms": timeout_ms,
                        "max_file_bytes": max_file_bytes,
                    },
                    timeout=min(timeout, 30.0),
                )
                data = self._validate_trace_status(state, native, require_recording=True)
                if not output_path.is_file():
                    raise XdbgRpcError(
                        "artifact_missing",
                        "trace.start did not create the session-owned trace artifact",
                        details={"path": str(output_path)},
                    )
                state.last_status = dict(data)
            return _success(
                self._trace_result_payload(state, data),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            stopped_safely = True
            if runtime is not None and state is not None and state_registered:
                stopped_safely = self._stop_trace_after_failure(runtime, state)
                self._finalize_trace_artifact(state, terminal_reason="start_failed")
                self._attach_trace_artifact_details(exc, state)
            if exc.code in _FATAL_WORKER_ERRORS or not stopped_safely:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if runtime is not None and state is not None and state_registered:
                self._stop_trace_after_failure(runtime, state)
                self._finalize_trace_artifact(state, terminal_reason="start_failed")
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
    def trace_stop(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        state: _TraceArtifactState | None = None
        runtime: _BackendRuntime | None = None
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            state = self._trace_owner.get(session_id)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "trace.stop" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide trace.stop",
                        details={"capability": "trace.stop"},
                    )
                native = runtime.worker.request("trace.stop", timeout=min(timeout, 30.0))
                if state is None:
                    return _success(
                        dict(native),
                        session_id=session_id,
                        backend=BackendKind.X64DBG.value,
                    )
                data = self._validate_trace_status(state, native, require_recording=False)
                if data["recording"] is True:
                    raise XdbgRpcError(
                        "trace_stop_failed",
                        "x64dbg still reports trace recording after trace.stop",
                        details={"path": str(state.path)},
                    )
                state.last_status = dict(data)
                state.active = False
            self._finalize_trace_artifact(
                state,
                terminal_reason=str(data.get("stop_reason") or "cancelled"),
            )
            return _success(
                self._trace_result_payload(state, data),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            # An uncertain stop is unsafe: terminate the analyzer to close the
            # trace handle, then retain and register the bounded partial file.
            if runtime is not None:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None:
                state.active = False
                self._finalize_trace_artifact(state, terminal_reason="stop_failed")
                self._attach_trace_artifact_details(exc, state)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if runtime is not None:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None:
                state.active = False
                self._finalize_trace_artifact(state, terminal_reason="stop_failed")
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
    def trace_status(self, session_id: str, *, timeout: float = 30.0) -> Result[JsonObject]:
        state: _TraceArtifactState | None = None
        runtime: _BackendRuntime | None = None
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            state = self._trace_owner.get(session_id)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "trace.status" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide trace.status",
                        details={"capability": "trace.status"},
                    )
                native = runtime.worker.request("trace.status", timeout=min(timeout, 30.0))
                if state is None:
                    return _success(
                        dict(native),
                        session_id=session_id,
                        backend=BackendKind.X64DBG.value,
                    )
                data = self._validate_trace_status(state, native)
                elapsed_ms = int((monotonic() - state.started_monotonic) * 1000)
                actual_size = state.path.stat().st_size if state.path.is_file() else 0
                if data["recording"] is True and (
                    elapsed_ms >= state.timeout_ms
                    or int(data["events_written"]) >= state.max_events
                    or actual_size >= state.max_file_bytes
                ):
                    # Defense in depth for an older/misbehaving native adapter.
                    # A current adapter normally returns terminal here itself.
                    stopped = runtime.worker.request("trace.stop", timeout=min(timeout, 30.0))
                    data = self._validate_trace_status(
                        state,
                        stopped,
                        require_recording=False,
                    )
                    if data["recording"] is True:
                        raise XdbgRpcError(
                            "trace_quota_enforcement_failed",
                            "trace remained active after a service-side quota stop",
                            details={"path": str(state.path)},
                        )
                    if elapsed_ms >= state.timeout_ms and data.get("stop_reason") in {
                        "none",
                        "cancelled",
                        "stopped",
                    }:
                        data["stop_reason"] = "timeout"
                        data["quota_stopped"] = True
                state.last_status = dict(data)
                state.active = bool(data["recording"])
            if not state.active:
                self._finalize_trace_artifact(
                    state,
                    terminal_reason=str(data.get("stop_reason") or "stopped"),
                )
            return _success(
                self._trace_result_payload(state, data),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except XdbgRpcError as exc:
            if (
                state is not None
                and not state.active
                and state.artifact_id is not None
                and isinstance(state.last_status, dict)
            ):
                # Trace already finalized; do not tear down the debug session on a
                # stale status poll after the debuggee/trace ended.
                return _success(
                    self._trace_result_payload(state, state.last_status),
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                )
            if runtime is not None and (
                exc.code in _FATAL_WORKER_ERRORS
                or (state is not None and state.active)
                or exc.code in {"trace_quota_violation", "trace_quota_enforcement_failed"}
            ):
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None and not state.active:
                self._finalize_trace_artifact(state, terminal_reason="status_failed")
                self._attach_trace_artifact_details(exc, state)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            if (
                state is not None
                and not state.active
                and state.artifact_id is not None
                and isinstance(state.last_status, dict)
            ):
                return _success(
                    self._trace_result_payload(state, state.last_status),
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                )
            if runtime is not None:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            if state is not None:
                state.active = False
                self._finalize_trace_artifact(state, terminal_reason="status_failed")
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
    def _new_trace_artifact_path(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id:
            raise ValueError("invalid session id for trace artifact path")
        session = self.registry.get(session_id)
        directory = self.settings.artifact_root.expanduser().resolve() / "trace" / session_id
        directory.mkdir(parents=True, exist_ok=True)
        suffix = (
            ".trace64" if session.require_architecture() == Architecture.X64 else ".trace32"
        )
        output = (directory / f"run-{uuid4().hex}{suffix}").resolve()
        if output.parent != directory:
            raise ValueError("trace artifact escaped the session artifact directory")
        return output
    def _validate_trace_status(
        self,
        state: _TraceArtifactState,
        payload: JsonObject,
        *,
        require_recording: bool | None = None,
    ) -> JsonObject:
        if not isinstance(payload, dict):
            raise XdbgRpcError("rpc_protocol_error", "x64dbg returned a non-object trace status")
        data = dict(payload)
        if type(data.get("recording")) is not bool:
            raise XdbgRpcError("rpc_protocol_error", "trace status has no boolean recording field")
        if require_recording is True and data["recording"] is not True:
            raise XdbgRpcError("trace_start_failed", "x64dbg did not enter trace recording state")
        if require_recording is False and data["recording"] is not False:
            raise XdbgRpcError("trace_stop_failed", "x64dbg did not leave trace recording state")
        returned_path = data.get("path")
        try:
            resolved_path = Path(str(returned_path)).resolve()
        except (OSError, ValueError, TypeError) as exc:
            raise XdbgRpcError(
                "rpc_protocol_error", "trace status returned an invalid artifact path"
            ) from exc
        if resolved_path != state.path:
            raise XdbgRpcError(
                "rpc_protocol_error",
                "x64dbg trace path does not match the session-owned artifact",
                details={"expected": str(state.path), "actual": str(returned_path)},
            )
        expected = {
            "max_events": state.max_events,
            "timeout_ms": state.timeout_ms,
            "max_file_bytes": state.max_file_bytes,
        }
        for key, value in expected.items():
            # After stop/finalize, some adapters omit the original quota fields.
            if data.get(key) is None:
                data[key] = value
            if type(data.get(key)) is not int or data[key] != value:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    f"trace status returned an invalid {key}",
                    details={"expected": value, "actual": data.get(key)},
                )
        for key in ("events_written", "file_bytes", "elapsed_ms"):
            # Native trace.start historically omits counters until the first sample.
            if data.get(key) is None:
                data[key] = 0
            if type(data.get(key)) is not int or int(data[key]) < 0:
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    f"trace status returned an invalid {key}",
                )
        if not isinstance(data.get("stop_reason"), str) or not data["stop_reason"]:
            data["stop_reason"] = "none"
        actual_size = state.path.stat().st_size if state.path.is_file() else 0
        if (
            int(data["events_written"]) > state.max_events
            or max(int(data["file_bytes"]), actual_size) > state.max_file_bytes
        ):
            raise XdbgRpcError(
                "trace_quota_violation",
                "trace artifact exceeded a hard quota; analyzer will be terminated",
                details={
                    "events_written": data["events_written"],
                    "max_events": state.max_events,
                    "file_bytes": max(int(data["file_bytes"]), actual_size),
                    "max_file_bytes": state.max_file_bytes,
                    "path": str(state.path),
                },
            )
        return data
    def _stop_trace_after_failure(
        self,
        runtime: _BackendRuntime,
        state: _TraceArtifactState,
    ) -> bool:
        try:
            with runtime.lock:
                if "trace.stop" not in runtime.worker.capabilities:
                    return False
                stopped = runtime.worker.request("trace.stop", timeout=5.0)
                if not isinstance(stopped, dict) or stopped.get("recording") is not False:
                    return False
                state.last_status = dict(stopped)
            state.active = False
            return True
        except BaseException:
            return False
    def _finalize_trace_artifact(
        self,
        state: _TraceArtifactState,
        *,
        terminal_reason: str,
    ) -> None:
        with self._lock:
            if state.artifact_id is not None:
                state.active = False
                state.terminal_reason = terminal_reason
                return
            state.active = False
            state.terminal_reason = terminal_reason
            expected_root = (
                self.settings.artifact_root.expanduser().resolve() / "trace" / state.session_id
            )
            if state.path.parent != expected_root:
                state.artifact_error = "trace artifact is outside its session-owned root"
                return
            try:
                if not state.path.is_file():
                    state.artifact_error = "trace artifact file is missing"
                    return
                size = state.path.stat().st_size
                if size > state.max_file_bytes:
                    # The native writer should make this unreachable. Truncate only
                    # after the worker/file handle is closed and mark the artifact as
                    # partial so an over-quota file is never retained or advertised.
                    with state.path.open("r+b") as stream:
                        stream.truncate(state.max_file_bytes)
                    size = state.max_file_bytes
                    state.artifact_truncated = True
                    state.terminal_reason = "quota_violation"
                digest = file_sha256(state.path)
                artifact = self.record_artifact(
                    session_id=state.session_id,
                    kind="run_trace_partial" if state.artifact_truncated else "run_trace",
                    path=state.path,
                    sha256=digest,
                    source="trace",
                    size=size,
                )
                state.artifact_id = str(artifact["id"])
                state.artifact_sha256 = digest
                state.artifact_size = size
                state.artifact_error = None
            except (OSError, ValueError, TypeError, KeyError) as exc:
                state.artifact_error = str(exc)
    def _trace_result_payload(
        self,
        state: _TraceArtifactState,
        native: JsonObject,
    ) -> JsonObject:
        data = dict(native)
        data.update(
            {
                "path": str(state.path),
                "artifact_path": str(state.path),
                "requested_path": state.requested_path,
                "artifact_pending": state.active,
                "artifact_registered": state.artifact_id is not None,
                "artifact_id": state.artifact_id,
                "artifact_sha256": state.artifact_sha256,
                "artifact_size": state.artifact_size,
                "artifact_truncated": state.artifact_truncated,
                "artifact_error": state.artifact_error,
                "terminal_reason": state.terminal_reason,
                "session_owned": True,
            }
        )
        return data
    def _attach_trace_artifact_details(
        self,
        error: XdbgRpcError,
        state: _TraceArtifactState,
    ) -> None:
        error.details.update(
            {
                "artifact_path": str(state.path),
                "artifact_id": state.artifact_id,
                "artifact_sha256": state.artifact_sha256,
                "artifact_size": state.artifact_size,
                "artifact_truncated": state.artifact_truncated,
                "artifact_error": state.artifact_error,
            }
        )
    def _finalize_trace_after_worker_loss(
        self,
        session_id: str,
        *,
        reason: str,
    ) -> None:
        state = self._trace_owner.get(session_id)
        if state is None or state.artifact_id is not None:
            return
        state.active = False
        state.last_status = {
            **state.last_status,
            "recording": False,
            "stop_reason": reason,
            "failed": reason not in {"session_closed", "target_exited"},
        }
        self._finalize_trace_artifact(state, terminal_reason=reason)
    def trace_api_arguments(
        self,
        session_id: str,
        expression: str | None = None,
        *,
        address: int | None = None,
        max_hits: int = 4,
        argument_count: int = 4,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Break on an API and capture its integer arguments on each hit.

        x64 arguments come from the Microsoft register convention and x86
        arguments are read off the stack above the return address. The breakpoint
        is always removed again, and a stop at another address ends the trace
        rather than mislabelling someone else's break as a hit.
        """
        try:
            if (expression is None) == (address is None):
                raise ValueError("provide exactly one of expression or address")
            if isinstance(max_hits, bool) or type(max_hits) is not int or not 1 <= max_hits <= 64:
                raise ValueError("max_hits must be 1..64")
            if (
                isinstance(argument_count, bool)
                or type(argument_count) is not int
                or not 0 <= argument_count <= len(_X64_ARGUMENT_REGISTERS)
            ):
                raise ValueError(
                    f"argument_count must be 0..{len(_X64_ARGUMENT_REGISTERS)}"
                )
            if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
                raise ValueError("timeout must be a number")
            if not 0 < float(timeout) <= MAX_WORKFLOW_TIMEOUT:
                raise ValueError(f"timeout must be > 0 and <= {MAX_WORKFLOW_TIMEOUT}")

            architecture = self.registry.get(session_id).require_architecture()
            decodes_registers = architecture == Architecture.X64
            resolution: JsonObject | None = None
            target_address = address
            if expression is not None:
                resolved = self.symbols_resolve(
                    session_id,
                    expression,
                    timeout=float(timeout),
                )
                if not resolved.ok or resolved.data is None:
                    return resolved
                resolution = resolved.data
                candidate = resolution.get("address")
                if not isinstance(candidate, int) or isinstance(candidate, bool):
                    raise ValueError("symbol resolution did not return an address")
                target_address = candidate
            if target_address is None:
                raise ValueError("unable to determine a trace address")

            armed = self.dynamic_breakpoint_set(session_id, target_address)
            if not armed.ok:
                return armed

            hits: list[JsonObject] = []
            stopped_elsewhere = False
            try:
                for sequence in range(int(max_hits)):
                    resumed = self.dynamic_resume(
                        session_id,
                        wait_for_pause=True,
                        timeout=float(timeout),
                    )
                    if not resumed.ok:
                        break
                    register_result = self.dynamic_registers_read(session_id)
                    registers = register_result.data if register_result.ok else None
                    pointer = _instruction_pointer(registers)
                    if pointer is not None and pointer != target_address:
                        stopped_elsewhere = True
                        break
                    if decodes_registers:
                        arguments = _register_arguments(registers, int(argument_count))
                    else:
                        stack = self.stack_read(
                            session_id,
                            count=int(argument_count) + 1,
                            timeout=float(timeout),
                        )
                        arguments = _stack_arguments(
                            stack.data if stack.ok else None,
                            int(argument_count),
                        )
                    hits.append(
                        {
                            "sequence": sequence,
                            "instruction_pointer": pointer,
                            "arguments": arguments,
                        }
                    )
            finally:
                self.dynamic_breakpoint_remove(session_id, target_address)

            return _success(
                {
                    "target": {
                        "expression": expression,
                        "address": target_address,
                        "resolution": resolution,
                    },
                    "architecture": architecture.value,
                    "convention": (
                        "microsoft_x64_integer_registers"
                        if decodes_registers
                        else "x86_stack_arguments"
                    ),
                    "hits": hits,
                    "hit_count": len(hits),
                    "max_hits": int(max_hits),
                    "truncated": len(hits) >= int(max_hits),
                    "stopped_elsewhere": stopped_elsewhere,
                },
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id)
