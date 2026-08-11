"""Explicit owners for in-process runtime and orchestration state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from threading import RLock
from typing import Generic, TypeVar

from headless_re_mcp.core.models import BackendKind, SessionState
from headless_re_mcp.core.session import SessionRegistry

RuntimeT = TypeVar("RuntimeT")
WorkflowT = TypeVar("WorkflowT")
UnpackT = TypeVar("UnpackT")
TraceT = TypeVar("TraceT")


class BackendRuntimePhase(StrEnum):
    ABSENT = "absent"
    OPENING = "opening"
    READY = "ready"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass(slots=True)
class BackendRuntimeOwner(Generic[RuntimeT]):
    """Own backend workers independently from session lifecycle state."""

    lock: RLock = field(default_factory=RLock)
    items: dict[tuple[str, BackendKind], RuntimeT] = field(default_factory=dict)
    phases: dict[tuple[str, BackendKind], BackendRuntimePhase] = field(default_factory=dict)

    def phase(self, session_id: str, kind: BackendKind) -> BackendRuntimePhase:
        with self.lock:
            return self.phases.get((session_id, kind), BackendRuntimePhase.ABSENT)

    def begin_open(self, session_id: str, kind: BackendKind) -> None:
        with self.lock:
            key = (session_id, kind)
            current = self.phases.get(key, BackendRuntimePhase.ABSENT)
            if key in self.items or current == BackendRuntimePhase.OPENING:
                raise RuntimeError(f"backend runtime is already active: {session_id}/{kind.value}")
            self.phases[key] = BackendRuntimePhase.OPENING

    def get(self, session_id: str, kind: BackendKind) -> RuntimeT | None:
        with self.lock:
            return self.items.get((session_id, kind))

    def put(self, session_id: str, kind: BackendKind, runtime: RuntimeT) -> None:
        with self.lock:
            key = (session_id, kind)
            current = self.phases.get(key, BackendRuntimePhase.ABSENT)
            if current != BackendRuntimePhase.OPENING or key in self.items:
                raise RuntimeError(
                    f"backend runtime cannot become ready from {current.value}: "
                    f"{session_id}/{kind.value}"
                )
            self.items[key] = runtime
            self.phases[key] = BackendRuntimePhase.READY

    def pop(self, session_id: str, kind: BackendKind) -> RuntimeT | None:
        with self.lock:
            key = (session_id, kind)
            runtime = self.items.pop(key, None)
            current = self.phases.get(key, BackendRuntimePhase.ABSENT)
            if runtime is not None or current in {
                BackendRuntimePhase.OPENING,
                BackendRuntimePhase.READY,
                BackendRuntimePhase.FAILED,
            }:
                self.phases[key] = BackendRuntimePhase.CLOSED
            return runtime

    def fail(self, session_id: str, kind: BackendKind) -> RuntimeT | None:
        with self.lock:
            key = (session_id, kind)
            runtime = self.items.pop(key, None)
            self.phases[key] = BackendRuntimePhase.FAILED
            return runtime

    def snapshot(self) -> list[tuple[str, BackendKind, RuntimeT]]:
        """Copy the open runtimes so callers can inspect them without the lock."""
        with self.lock:
            return [(sid, kind, runtime) for (sid, kind), runtime in self.items.items()]

    def is_current(self, session_id: str, kind: BackendKind, runtime: RuntimeT) -> bool:
        with self.lock:
            return self.items.get((session_id, kind)) is runtime

    def pop_session(self, session_id: str) -> list[tuple[BackendKind, RuntimeT]]:
        with self.lock:
            keys = [key for key in self.items if key[0] == session_id]
            result = []
            for sid, kind in keys:
                result.append((kind, self.items.pop((sid, kind))))
                self.phases[(sid, kind)] = BackendRuntimePhase.CLOSED
            return result


@dataclass(slots=True)
class WorkflowStateOwner(Generic[WorkflowT]):
    """Own live and terminal workflow snapshots independently from backends."""

    lock: RLock = field(default_factory=RLock)
    live: dict[str, WorkflowT] = field(default_factory=dict)
    terminal: dict[str, WorkflowT] = field(default_factory=dict)

    def get(self, session_id: str) -> WorkflowT | None:
        with self.lock:
            return self.live.get(session_id)

    def get_terminal(self, session_id: str) -> WorkflowT | None:
        with self.lock:
            return self.terminal.get(session_id)

    def put(self, session_id: str, workflow: WorkflowT) -> None:
        with self.lock:
            self.live[session_id] = workflow
            self.terminal.pop(session_id, None)

    def put_terminal(self, session_id: str, workflow: WorkflowT) -> None:
        with self.lock:
            self.live.pop(session_id, None)
            self.terminal[session_id] = workflow

    def clear_terminal(self, session_id: str) -> None:
        with self.lock:
            self.terminal.pop(session_id, None)

    def fail_live(
        self,
        session_id: str,
        failure: Callable[[WorkflowT], WorkflowT],
    ) -> WorkflowT | None:
        with self.lock:
            workflow = self.live.get(session_id)
            if workflow is None:
                return None
            failed = failure(workflow)
            self.live[session_id] = failed
            return failed

    def clear(self, session_id: str) -> None:
        with self.lock:
            self.live.pop(session_id, None)
            self.terminal.pop(session_id, None)


@dataclass(slots=True)
class UnpackStateOwner(Generic[UnpackT]):
    """Own unpack sessions and their independent protection snapshots."""

    lock: RLock = field(default_factory=RLock)
    sessions: dict[str, UnpackT] = field(default_factory=dict)
    protection_snapshots: dict[str, list[dict[str, object]]] = field(default_factory=dict)

    def get(self, session_id: str) -> UnpackT | None:
        with self.lock:
            return self.sessions.get(session_id)

    def contains(self, session_id: str) -> bool:
        with self.lock:
            return session_id in self.sessions

    def put(self, session_id: str, state: UnpackT) -> None:
        with self.lock:
            self.sessions[session_id] = state

    def get_protection_snapshot(
        self,
        session_id: str,
    ) -> list[dict[str, object]] | None:
        with self.lock:
            snapshot = self.protection_snapshots.get(session_id)
            return None if snapshot is None else [dict(item) for item in snapshot]

    def put_protection_snapshot(
        self,
        session_id: str,
        snapshot: list[dict[str, object]],
    ) -> None:
        with self.lock:
            self.protection_snapshots[session_id] = [dict(item) for item in snapshot]

    def clear(self, session_id: str) -> None:
        with self.lock:
            self.sessions.pop(session_id, None)
            self.protection_snapshots.pop(session_id, None)


@dataclass(slots=True)
class TraceStateOwner(Generic[TraceT]):
    """Own trace artifact lifecycle state independently from backend workers."""

    lock: RLock = field(default_factory=RLock)
    sessions: dict[str, TraceT] = field(default_factory=dict)

    def get(self, session_id: str) -> TraceT | None:
        with self.lock:
            return self.sessions.get(session_id)

    def put(self, session_id: str, state: TraceT) -> None:
        with self.lock:
            self.sessions[session_id] = state

    def put_if_inactive(
        self,
        session_id: str,
        state: TraceT,
        *,
        is_active: Callable[[TraceT], bool],
    ) -> TraceT | None:
        with self.lock:
            existing = self.sessions.get(session_id)
            if existing is not None and is_active(existing):
                return existing
            self.sessions[session_id] = state
            return None

    def clear(self, session_id: str) -> None:
        with self.lock:
            self.sessions.pop(session_id, None)


@dataclass(frozen=True, slots=True)
class DebuggeeSnapshot:
    state: str
    debuggee_pid: int | None
    debugger_pid: int | None


class DebuggeeStateOwner:
    """Translate native debuggee state into the legacy session compatibility view."""

    def __init__(self, registry: SessionRegistry) -> None:
        self._registry = registry
        self._lock = RLock()
        self._snapshots: dict[str, DebuggeeSnapshot] = {}

    def observe(
        self,
        session_id: str,
        state: dict[str, object],
        *,
        debugger_pid: int | None,
    ) -> dict[str, object]:
        target_value = state.get("state")
        target = target_value if isinstance(target_value, str) else "unknown"
        process_id = state.get("process_id")
        debuggee_pid = process_id if isinstance(process_id, int) and process_id > 0 else None
        snapshot = DebuggeeSnapshot(target, debuggee_pid, debugger_pid)
        with self._lock:
            self._snapshots[session_id] = snapshot
        self._project_legacy_session_state(session_id, target)
        self._registry.update_metadata(
            session_id,
            {"debuggee_pid": debuggee_pid, "debugger_pid": debugger_pid},
        )
        return self.annotate(state, snapshot)

    @staticmethod
    def annotate(
        state: dict[str, object],
        snapshot: DebuggeeSnapshot,
    ) -> dict[str, object]:
        annotated = dict(state)
        annotated["debuggee_pid"] = snapshot.debuggee_pid
        annotated["debugger_pid"] = snapshot.debugger_pid
        annotated["pid_note"] = (
            "debuggee_pid is the target process (from debug.state.process_id); "
            "debugger_pid is the x64dbg headless analyzer (BackendHandle.pid)"
        )
        return annotated

    def clear(self, session_id: str) -> None:
        with self._lock:
            self._snapshots.pop(session_id, None)

    def snapshot(self, session_id: str) -> DebuggeeSnapshot | None:
        with self._lock:
            return self._snapshots.get(session_id)

    def _project_legacy_session_state(self, session_id: str, target: str) -> None:
        current = self._registry.get(session_id).state
        if target == "running" and current in {SessionState.READY, SessionState.SUSPENDED}:
            self._registry.transition(session_id, SessionState.RUNNING)
        elif target == "paused" and current in {SessionState.READY, SessionState.RUNNING}:
            self._registry.transition(session_id, SessionState.SUSPENDED)
        elif target == "idle":
            if current == SessionState.RUNNING:
                self._registry.transition(session_id, SessionState.SUSPENDED)
                current = SessionState.SUSPENDED
            if current == SessionState.SUSPENDED:
                self._registry.transition(session_id, SessionState.READY)
