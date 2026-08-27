"""M5 unpack session state machine, timeline, and artifact ledger."""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from math import isfinite
from pathlib import Path
from typing import Any
from uuid import uuid4

JsonObject = dict[str, Any]

# One day: far above any real unpack deadline (the unpack.* tool schemas cap
# timeout at 300-600s) yet comfortably inside the range timedelta can represent.
# The bound matters because create_unpack_session turns timeout_seconds into a
# deadline via ``now + timedelta(seconds=timeout_seconds)``: an inf/huge value
# raises OverflowError and a NaN raises ValueError from deep inside timedelta.
# On the MCP path pydantic's Field(gt=0, le=...) rejects those first, but the
# agent transport invokes the handler straight from model arguments
# (CommandCatalog.invoke -> spec.handler), so an agent-issued timeout reaches
# here unchecked; the OverflowError then escapes the ValueError branch in
# _failure and mints a bogus internal_error incident for what is really
# malformed input. Bound it here so every caller agrees regardless of transport.
_MAX_TIMEOUT_SECONDS: float = 86_400.0


class UnpackPhase(StrEnum):
    """Ordered unpack orchestration phases (M5.1)."""

    DETECTED = "detected"
    RUNNING = "running"
    OEP_CANDIDATE = "oep_candidate"
    DUMPED = "dumped"
    IMPORTS_REBUILT = "imports_rebuilt"
    VERIFIED = "verified"
    REANALYZED = "reanalyzed"
    FAILED = "failed"
    CANCELLED = "cancelled"


_TERMINAL_PHASES = frozenset(
    {UnpackPhase.FAILED, UnpackPhase.CANCELLED, UnpackPhase.REANALYZED}
)


_FORWARD: dict[UnpackPhase, frozenset[UnpackPhase]] = {
    UnpackPhase.DETECTED: frozenset(
        {
            UnpackPhase.RUNNING,
            UnpackPhase.VERIFIED,  # UPX path may skip runtime phases
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
        }
    ),
    UnpackPhase.RUNNING: frozenset(
        {
            UnpackPhase.OEP_CANDIDATE,
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
        }
    ),
    UnpackPhase.OEP_CANDIDATE: frozenset(
        {
            UnpackPhase.DUMPED,
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
        }
    ),
    UnpackPhase.DUMPED: frozenset(
        {
            UnpackPhase.IMPORTS_REBUILT,
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
        }
    ),
    UnpackPhase.IMPORTS_REBUILT: frozenset(
        {
            UnpackPhase.VERIFIED,
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
        }
    ),
    UnpackPhase.VERIFIED: frozenset(
        {
            UnpackPhase.REANALYZED,
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
        }
    ),
    UnpackPhase.REANALYZED: frozenset({UnpackPhase.FAILED, UnpackPhase.CANCELLED}),
    UnpackPhase.FAILED: frozenset(),
    UnpackPhase.CANCELLED: frozenset(),
}


class UnpackSessionError(ValueError):
    """Invalid unpack session transition or configuration."""


@dataclass(frozen=True, slots=True)
class UnpackArtifact:
    kind: str
    path: str
    sha256: str
    phase: UnpackPhase

    def to_dict(self) -> JsonObject:
        return {
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "phase": self.phase.value,
        }


@dataclass(frozen=True, slots=True)
class UnpackTimelineEvent:
    sequence: int
    at: datetime
    phase: UnpackPhase
    event: str
    message: str
    input_sha256: str | None = None
    output_sha256: str | None = None
    details: JsonObject = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return {
            "sequence": self.sequence,
            "at": self.at.isoformat(),
            "phase": self.phase.value,
            "event": self.event,
            "message": self.message,
            "input_sha256": self.input_sha256,
            "output_sha256": self.output_sha256,
            "details": dict(self.details),
            "claims_universal_unpack": False,
        }


@dataclass(frozen=True, slots=True)
class UnpackFailure:
    code: str
    message: str
    details: JsonObject = field(default_factory=dict)
    retryable: bool = False

    def to_dict(self) -> JsonObject:
        return {
            "code": self.code,
            "message": self.message,
            "details": dict(self.details),
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True)
class UnpackSessionState:
    """Per analysis-session unpack orchestration state."""

    unpack_id: str
    session_id: str
    phase: UnpackPhase
    route: str
    created_at: datetime
    updated_at: datetime
    plan: JsonObject = field(default_factory=dict)
    artifacts: tuple[UnpackArtifact, ...] = ()
    timeline: tuple[UnpackTimelineEvent, ...] = ()
    oep_candidates: tuple[JsonObject, ...] = ()
    confirmed_oep_rva: int | None = None
    confirmed_iat_va: int | None = None
    confirmed_iat_size: int | None = None
    module_base: int | None = None
    failure: UnpackFailure | None = None
    timeout_seconds: float = 120.0
    deadline_at: datetime | None = None
    claims_universal_unpack: bool = False

    def to_dict(self) -> JsonObject:
        return {
            "unpack_id": self.unpack_id,
            "session_id": self.session_id,
            "phase": self.phase.value,
            "route": self.route,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "plan": dict(self.plan),
            "artifacts": [item.to_dict() for item in self.artifacts],
            "timeline": [item.to_dict() for item in self.timeline],
            "oep_candidates": [dict(item) for item in self.oep_candidates],
            "confirmed_oep_rva": self.confirmed_oep_rva,
            "confirmed_iat_va": self.confirmed_iat_va,
            "confirmed_iat_size": self.confirmed_iat_size,
            "module_base": self.module_base,
            "failure": self.failure.to_dict() if self.failure is not None else None,
            "timeout_seconds": self.timeout_seconds,
            "deadline_at": self.deadline_at.isoformat() if self.deadline_at else None,
            "claims_universal_unpack": False,
            "terminal": self.phase in _TERMINAL_PHASES,
        }


def create_unpack_session(
    session_id: str,
    *,
    route: str,
    plan: JsonObject | None = None,
    timeout_seconds: float = 120.0,
    input_sha256: str | None = None,
) -> UnpackSessionState:
    if not session_id.strip():
        raise UnpackSessionError("session_id must not be blank")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS
    ):
        raise UnpackSessionError(
            f"timeout_seconds must be > 0 and <= {_MAX_TIMEOUT_SECONDS}"
        )
    now = datetime.now(UTC)
    state = UnpackSessionState(
        unpack_id=uuid4().hex,
        session_id=session_id,
        phase=UnpackPhase.DETECTED,
        route=route,
        created_at=now,
        updated_at=now,
        plan=dict(plan or {}),
        timeout_seconds=timeout_seconds,
        deadline_at=now + timedelta(seconds=timeout_seconds),
    )
    return append_timeline(
        state,
        event="session_created",
        message=f"unpack session created with route={route}",
        input_sha256=input_sha256,
        details={"route": route, "plan": dict(plan or {})},
    )


def can_transition(current: UnpackPhase, target: UnpackPhase) -> bool:
    if current == target:
        return True
    return target in _FORWARD.get(current, frozenset())


def transition(
    state: UnpackSessionState,
    target: UnpackPhase,
    *,
    event: str,
    message: str,
    input_sha256: str | None = None,
    output_sha256: str | None = None,
    details: JsonObject | None = None,
    failure: UnpackFailure | None = None,
) -> UnpackSessionState:
    if state.phase in {UnpackPhase.FAILED, UnpackPhase.CANCELLED}:
        raise UnpackSessionError(
            f"unpack session is terminal ({state.phase.value}); create a new session"
        )
    if not can_transition(state.phase, target):
        raise UnpackSessionError(
            f"cannot transition unpack phase {state.phase.value} -> {target.value}"
        )
    if target == UnpackPhase.FAILED and failure is None:
        failure = UnpackFailure(
            code="unpack_failed",
            message=message or "unpack failed",
            details=dict(details or {}),
        )
    if target != UnpackPhase.FAILED:
        failure = None
    updated = replace(
        state,
        phase=target,
        updated_at=datetime.now(UTC),
        failure=failure,
    )
    return append_timeline(
        updated,
        event=event,
        message=message,
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        details=details,
    )


def append_timeline(
    state: UnpackSessionState,
    *,
    event: str,
    message: str,
    input_sha256: str | None = None,
    output_sha256: str | None = None,
    details: JsonObject | None = None,
) -> UnpackSessionState:
    seq = (state.timeline[-1].sequence + 1) if state.timeline else 1
    entry = UnpackTimelineEvent(
        sequence=seq,
        at=datetime.now(UTC),
        phase=state.phase,
        event=event,
        message=message,
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        details=dict(details or {}),
    )
    return replace(
        state,
        timeline=state.timeline + (entry,),
        updated_at=entry.at,
    )


def add_artifact(
    state: UnpackSessionState,
    *,
    kind: str,
    path: str | Path,
    sha256: str,
    phase: UnpackPhase | None = None,
) -> UnpackSessionState:
    artifact = UnpackArtifact(
        kind=kind,
        path=str(path),
        sha256=sha256,
        phase=phase or state.phase,
    )
    return replace(
        state,
        artifacts=state.artifacts + (artifact,),
        updated_at=datetime.now(UTC),
    )


def check_timeout(
    state: UnpackSessionState,
    *,
    now: datetime | None = None,
) -> UnpackSessionState:
    """Fail non-terminal sessions that have passed ``deadline_at``."""
    if state.phase in _TERMINAL_PHASES:
        return state
    if state.deadline_at is None:
        return state
    current = now if now is not None else datetime.now(UTC)
    if current < state.deadline_at:
        return state
    return fail_unpack_session(
        state,
        code="unpack_timeout",
        message=(
            f"unpack session exceeded timeout of {state.timeout_seconds}s "
            f"(deadline_at={state.deadline_at.isoformat()})"
        ),
        details={
            "deadline_at": state.deadline_at.isoformat(),
            "timeout_seconds": state.timeout_seconds,
            "timed_out_at": current.isoformat(),
        },
        retryable=True,
    )


def ensure_unpack_active(
    state: UnpackSessionState,
    *,
    now: datetime | None = None,
    stage: str | None = None,
) -> tuple[UnpackSessionState, str | None]:
    """Cooperative preempt gate: apply timeout and reject terminal sessions.

    Returns ``(state, error_code)``. ``error_code`` is ``None`` when the session
    may start/continue work. Does **not** roll back artifacts; on fresh timeout
    records ``aborted_by_timeout`` with ``safe_rollback=false``.
    """
    if state.phase == UnpackPhase.CANCELLED:
        return state, "unpack_cancelled"
    if state.phase == UnpackPhase.REANALYZED:
        return state, "invalid_phase"
    if state.phase == UnpackPhase.FAILED:
        code = state.failure.code if state.failure is not None else "unpack_failed"
        return state, code if code == "unpack_timeout" else "invalid_phase"

    checked = check_timeout(state, now=now)
    if checked is state:
        return state, None

    details: JsonObject = {
        "aborted_stage": stage,
        "partial_artifacts_retained": True,
        "safe_rollback": False,
        "preempt": "cooperative",
        "note": (
            "deadline exceeded at API/stage boundary; "
            "in-flight native RPC may still complete; artifacts are retained"
        ),
    }
    checked = append_timeline(
        checked,
        event="aborted_by_timeout",
        message=f"cooperative timeout abort before/at {stage or 'api'}",
        details=details,
    )
    return checked, "unpack_timeout"


def cancel_unpack_session(
    state: UnpackSessionState,
    *,
    reason: str = "cancelled by caller",
    debuggee_paused_attempted: bool = False,
) -> UnpackSessionState:
    if state.phase in _TERMINAL_PHASES:
        return append_timeline(
            state,
            event="cancel_ignored",
            message=f"cancel ignored; already terminal ({state.phase.value})",
        )
    return transition(
        state,
        UnpackPhase.CANCELLED,
        event="cancelled",
        message=reason,
        details={
            "original_input_preserved": True,
            "debuggee_paused_attempted": debuggee_paused_attempted,
            "artifacts_retained": True,
            "safe_rollback": False,
            "note": "cancel does not undo dumps or restore prior memory/file state",
        },
    )


def fail_unpack_session(
    state: UnpackSessionState,
    *,
    code: str,
    message: str,
    details: JsonObject | None = None,
    retryable: bool = False,
) -> UnpackSessionState:
    return transition(
        state,
        UnpackPhase.FAILED,
        event="failed",
        message=message,
        details=details,
        failure=UnpackFailure(
            code=code,
            message=message,
            details=dict(details or {}),
            retryable=retryable,
        ),
    )


def write_timeline_jsonl(state: UnpackSessionState, path: Path) -> str | None:
    """Mirror the timeline as JSONL for readers. Reports failure, never raises.

    Every event here is already inside ``state.to_dict()``, so this file is a
    convenience copy and losing it costs nothing that is not held elsewhere. It
    is written first, though, which meant a full volume failed here and the
    state snapshot that follows never ran -- the record of what the unpack
    actually did, skipped because a duplicate of it could not be made. The
    caller then saw the whole step fail after the dump it was recording had
    already succeeded.

    Nothing reads ``state.json`` back, and that is deliberate: an unpack session
    is bound to a live debuggee, so a restart has nothing to resume into. It is
    the forensic record of a run, not a resume point.
    """
    partial = path.with_suffix(f"{path.suffix}.{uuid4().hex}.partial")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Rewritten whole so readers always see a consistent file.
        with partial.open("w", encoding="utf-8") as handle:
            for item in state.timeline:
                handle.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")
        partial.replace(path)
    except OSError as exc:
        with suppress(OSError):
            partial.unlink()
        return f"{type(exc).__name__}: {exc}"
    return None


def persist_state_snapshot(state: UnpackSessionState, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_text(
        json.dumps(state.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    partial.replace(path)
