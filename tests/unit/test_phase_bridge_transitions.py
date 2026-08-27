"""Branch coverage for M4->M5 phase_bridge close-the-loop helpers.

These exercise the non-happy-path transitions in ``unpack/phase_bridge``:
terminal sessions that retain artifacts without advancing, repeated
dump/rebuild/verify events, the RUNNING->OEP_CANDIDATE hop with and without a
confirmed OEP, the OEP_CANDIDATE->DUMPED catch-up inferences, and phase-skip
timeline notes when a transition is not legal. The bridge never claims
universal unpack success.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from headless_re_mcp.unpack.phase_bridge import (
    note_dump_success,
    note_imports_rebuilt,
    note_verified,
)
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionState,
    add_artifact,
    cancel_unpack_session,
    create_unpack_session,
    fail_unpack_session,
    transition,
)

_FORWARD_PATH = (
    UnpackPhase.RUNNING,
    UnpackPhase.OEP_CANDIDATE,
    UnpackPhase.DUMPED,
    UnpackPhase.IMPORTS_REBUILT,
    UnpackPhase.VERIFIED,
    UnpackPhase.REANALYZED,
)


def _advance_to(target: UnpackPhase) -> UnpackSessionState:
    state = create_unpack_session("sess", route="generic_dynamic")
    for phase in _FORWARD_PATH:
        if state.phase == target:
            break
        state = transition(
            state, phase, event=f"to_{phase.value}", message=f"to {phase.value}"
        )
    return state


def _events(state: UnpackSessionState) -> list[str]:
    return [item.event for item in state.timeline]


# --- note_dump_success ---------------------------------------------------


@pytest.mark.parametrize("terminal", [UnpackPhase.FAILED, UnpackPhase.CANCELLED])
def test_dump_on_terminal_session_retains_but_does_not_advance(
    terminal: UnpackPhase,
) -> None:
    base = _advance_to(UnpackPhase.RUNNING)
    if terminal == UnpackPhase.FAILED:
        state = fail_unpack_session(base, code="boom", message="died")
    else:
        state = cancel_unpack_session(base)
    before_artifacts = len(state.artifacts)

    updated = note_dump_success(state, output_path="C:/tmp/dump.bin", sha256="a" * 64)

    assert updated.phase == terminal
    assert len(updated.artifacts) == before_artifacts
    assert "dump_ignored_terminal" in _events(updated)


def test_dump_on_reanalyzed_session_is_terminal() -> None:
    state = _advance_to(UnpackPhase.REANALYZED)
    updated = note_dump_success(state, output_path="C:/tmp/d.bin", sha256="a" * 64)
    assert updated.phase == UnpackPhase.REANALYZED
    assert "dump_ignored_terminal" in _events(updated)


def test_dump_again_when_already_dumped_records_extra_artifact() -> None:
    state = _advance_to(UnpackPhase.DUMPED)
    updated = note_dump_success(state, output_path="C:/tmp/again.bin", sha256="b" * 64)
    assert updated.phase == UnpackPhase.DUMPED
    assert "module_dumped_again" in _events(updated)
    assert sum(1 for a in updated.artifacts if a.kind == "module_dump") == 1


def test_dump_from_running_without_confirmed_oep_hops_via_candidate() -> None:
    state = _advance_to(UnpackPhase.RUNNING)
    assert state.confirmed_oep_rva is None
    updated = note_dump_success(state, output_path="C:/tmp/d.bin", sha256="c" * 64)
    assert updated.phase == UnpackPhase.DUMPED
    events = _events(updated)
    assert "dump_without_confirmed_oep" in events
    assert "dump_implies_oep_candidate" in events
    assert "module_dumped" in events


def test_dump_from_running_with_confirmed_oep_uses_confirmed_hop() -> None:
    state = replace(_advance_to(UnpackPhase.RUNNING), confirmed_oep_rva=0x1000)
    updated = note_dump_success(
        state, output_path="C:/tmp/d.bin", sha256="d" * 64, module_base=0x140000000
    )
    assert updated.phase == UnpackPhase.DUMPED
    events = _events(updated)
    assert "oep_confirmed_pre_dump" in events
    assert "dump_without_confirmed_oep" not in events
    assert updated.module_base == 0x140000000


def test_dump_when_transition_not_legal_records_phase_skip() -> None:
    # DETECTED cannot advance directly to DUMPED and is not RUNNING/DUMPED.
    state = create_unpack_session("sess", route="generic_dynamic")
    assert state.phase == UnpackPhase.DETECTED
    updated = note_dump_success(state, output_path="C:/tmp/d.bin", sha256="e" * 64)
    assert updated.phase == UnpackPhase.DETECTED
    assert "dump_phase_skipped" in _events(updated)
    assert any(a.kind == "module_dump" for a in updated.artifacts)


# --- note_imports_rebuilt ------------------------------------------------


def test_rebuild_from_oep_candidate_with_dump_infers_dumped() -> None:
    state = _advance_to(UnpackPhase.OEP_CANDIDATE)
    state = add_artifact(
        state, kind="module_dump", path="C:/tmp/dump.bin", sha256="a" * 64
    )
    updated = note_imports_rebuilt(
        state, output_path="C:/tmp/rebuilt.exe", sha256="f" * 64
    )
    assert updated.phase == UnpackPhase.IMPORTS_REBUILT
    events = _events(updated)
    assert "dump_inferred" in events
    assert "imports_rebuilt" in events


def test_rebuild_from_oep_candidate_without_dump_implies_dumped() -> None:
    state = _advance_to(UnpackPhase.OEP_CANDIDATE)
    assert not any(a.kind == "module_dump" for a in state.artifacts)
    updated = note_imports_rebuilt(
        state, output_path="C:/tmp/rebuilt.exe", sha256="f" * 64
    )
    assert updated.phase == UnpackPhase.IMPORTS_REBUILT
    assert "rebuild_implies_dumped" in _events(updated)


def test_rebuild_again_when_already_rebuilt_records_extra() -> None:
    state = _advance_to(UnpackPhase.IMPORTS_REBUILT)
    updated = note_imports_rebuilt(
        state, output_path="C:/tmp/again.exe", sha256="g" * 64, kind="iat_rebuilt"
    )
    assert updated.phase == UnpackPhase.IMPORTS_REBUILT
    assert "imports_rebuilt_again" in _events(updated)
    assert any(a.kind == "iat_rebuilt" for a in updated.artifacts)


def test_rebuild_when_transition_not_legal_records_phase_skip() -> None:
    # RUNNING is neither OEP_CANDIDATE nor DUMPED, so rebuild cannot advance.
    state = _advance_to(UnpackPhase.RUNNING)
    updated = note_imports_rebuilt(
        state, output_path="C:/tmp/rebuilt.exe", sha256="h" * 64
    )
    assert updated.phase == UnpackPhase.RUNNING
    assert "imports_rebuild_phase_skipped" in _events(updated)
    assert any(a.kind == "pe_rebuilt" for a in updated.artifacts)


# --- note_verified -------------------------------------------------------


def test_verify_again_when_already_verified_records_extra() -> None:
    state = _advance_to(UnpackPhase.VERIFIED)
    updated = note_verified(state, path="C:/tmp/rebuilt.exe", sha256="i" * 64)
    assert updated.phase == UnpackPhase.VERIFIED
    assert "verified_again" in _events(updated)


def test_verify_reanalyzed_advances_to_reanalyzed() -> None:
    state = _advance_to(UnpackPhase.IMPORTS_REBUILT)
    updated = note_verified(
        state, path="C:/tmp/rebuilt.exe", sha256="j" * 64, reanalyzed=True
    )
    assert updated.phase == UnpackPhase.REANALYZED
    events = _events(updated)
    assert "verified" in events
    assert "ida_reanalyzed" in events


def test_verify_without_sha_skips_artifact_ledger() -> None:
    state = _advance_to(UnpackPhase.IMPORTS_REBUILT)
    before = len(state.artifacts)
    updated = note_verified(state, path="C:/tmp/rebuilt.exe", sha256=None)
    assert updated.phase == UnpackPhase.VERIFIED
    assert len(updated.artifacts) == before
    assert not any(a.kind == "verified_pe" for a in updated.artifacts)
