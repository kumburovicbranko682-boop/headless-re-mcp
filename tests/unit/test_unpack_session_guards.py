"""Guard-path coverage for the M5 unpack session state machine.

These exercise the fail-closed edges of ``unpack/session``: construction
validation, the same-phase / illegal-target transition rules, the synthesized
failure when transitioning to FAILED without one, the no-deadline timeout
no-op, the cooperative-preempt gate verdicts for already-terminal sessions
(cancelled / reanalyzed / failed, timeout vs other), and the ignored re-cancel
of a terminal session.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionError,
    UnpackSessionState,
    can_transition,
    cancel_unpack_session,
    check_timeout,
    create_unpack_session,
    ensure_unpack_active,
    fail_unpack_session,
    transition,
)


def _running(session_id: str = "sess") -> UnpackSessionState:
    state = create_unpack_session(session_id, route="generic_dynamic")
    return transition(state, UnpackPhase.RUNNING, event="run", message="running")


# --- create_unpack_session ----------------------------------------------


def test_create_rejects_blank_session_id() -> None:
    with pytest.raises(UnpackSessionError, match="session_id"):
        create_unpack_session("   ", route="upx")


def test_create_rejects_non_positive_timeout() -> None:
    with pytest.raises(UnpackSessionError, match="timeout_seconds"):
        create_unpack_session("sess", route="upx", timeout_seconds=0)


# --- can_transition / transition -----------------------------------------


def test_can_transition_same_phase_is_allowed() -> None:
    assert can_transition(UnpackPhase.DUMPED, UnpackPhase.DUMPED) is True
    assert can_transition(UnpackPhase.DETECTED, UnpackPhase.DUMPED) is False


def test_transition_from_terminal_phase_raises() -> None:
    cancelled = cancel_unpack_session(_running())
    with pytest.raises(UnpackSessionError, match="terminal"):
        transition(
            cancelled, UnpackPhase.OEP_CANDIDATE, event="x", message="x"
        )


def test_transition_to_illegal_target_raises() -> None:
    state = create_unpack_session("sess", route="upx")  # DETECTED
    with pytest.raises(UnpackSessionError, match="cannot transition"):
        transition(
            state, UnpackPhase.IMPORTS_REBUILT, event="x", message="x"
        )


def test_transition_to_failed_synthesizes_failure() -> None:
    state = create_unpack_session("sess", route="upx")
    failed = transition(state, UnpackPhase.FAILED, event="failed", message="boom")
    assert failed.phase == UnpackPhase.FAILED
    assert failed.failure is not None
    assert failed.failure.code == "unpack_failed"
    assert failed.failure.message == "boom"


# --- check_timeout -------------------------------------------------------


def test_check_timeout_without_deadline_is_noop() -> None:
    state = replace(create_unpack_session("sess", route="upx"), deadline_at=None)
    assert check_timeout(state) is state


# --- ensure_unpack_active ------------------------------------------------


def test_ensure_active_rejects_cancelled_session() -> None:
    cancelled = cancel_unpack_session(_running())
    out, code = ensure_unpack_active(cancelled)
    assert out is cancelled
    assert code == "unpack_cancelled"


def test_ensure_active_rejects_reanalyzed_session() -> None:
    reanalyzed = replace(
        create_unpack_session("sess", route="upx"), phase=UnpackPhase.REANALYZED
    )
    _out, code = ensure_unpack_active(reanalyzed)
    assert code == "invalid_phase"


def test_ensure_active_surfaces_timeout_failure_code() -> None:
    timed_out = fail_unpack_session(
        _running(), code="unpack_timeout", message="deadline exceeded", retryable=True
    )
    _out, code = ensure_unpack_active(timed_out)
    assert code == "unpack_timeout"


def test_ensure_active_maps_other_failure_to_invalid_phase() -> None:
    other = fail_unpack_session(_running("sess2"), code="dump_failed", message="nope")
    _out, code = ensure_unpack_active(other)
    assert code == "invalid_phase"


# --- cancel_unpack_session -----------------------------------------------


def test_cancel_on_terminal_session_is_ignored() -> None:
    cancelled = cancel_unpack_session(_running())
    again = cancel_unpack_session(cancelled)
    assert again.phase == UnpackPhase.CANCELLED
    assert again.timeline[-1].event == "cancel_ignored"
