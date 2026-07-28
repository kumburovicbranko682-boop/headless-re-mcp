"""Bridge M4 dump/rebuild/verify results into M5 unpack session phases.

Pure helpers so service methods can advance state without duplicating transition logic.
Never claims universal unpack success.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionState,
    add_artifact,
    append_timeline,
    can_transition,
    transition,
)

JsonObject = dict[str, Any]


def note_dump_success(
    state: UnpackSessionState,
    *,
    output_path: str | Path,
    sha256: str,
    module_base: int | None = None,
) -> UnpackSessionState:
    """Advance to DUMPED when a module dump artifact is produced."""
    from dataclasses import replace

    path = str(output_path)
    if state.phase in {UnpackPhase.FAILED, UnpackPhase.CANCELLED, UnpackPhase.REANALYZED}:
        return append_timeline(
            state,
            event="dump_ignored_terminal",
            message=f"dump artifact retained but phase stays {state.phase.value}",
            output_sha256=sha256,
            details={"path": path},
        )
    updated = state
    if module_base is not None:
        updated = replace(updated, module_base=module_base)

    if updated.phase == UnpackPhase.DUMPED:
        updated = append_timeline(
            updated,
            event="module_dumped_again",
            message="additional dump artifact recorded",
            output_sha256=sha256,
            details={"path": path},
        )
        return add_artifact(
            updated,
            kind="module_dump",
            path=path,
            sha256=sha256,
            phase=UnpackPhase.DUMPED,
        )

    # Hop RUNNING -> OEP_CANDIDATE first (graph does not allow RUNNING -> DUMPED).
    if updated.phase == UnpackPhase.RUNNING:
        if updated.confirmed_oep_rva is None:
            updated = append_timeline(
                updated,
                event="dump_without_confirmed_oep",
                message="dump recorded without confirmed OEP; advancing via oep_candidate",
                output_sha256=sha256,
            )
            hop_event = "dump_implies_oep_candidate"
            hop_message = (
                "dump requested while running; marking oep_candidate before dumped"
            )
        else:
            hop_event = "oep_confirmed_pre_dump"
            hop_message = "advancing running session with confirmed OEP before dump"
        updated = transition(
            updated,
            UnpackPhase.OEP_CANDIDATE,
            event=hop_event,
            message=hop_message,
            details={"confirmed_oep_rva": updated.confirmed_oep_rva},
        )

    if can_transition(updated.phase, UnpackPhase.DUMPED) and updated.phase != UnpackPhase.DUMPED:
        updated = transition(
            updated,
            UnpackPhase.DUMPED,
            event="module_dumped",
            message="module dump artifact written",
            output_sha256=sha256,
            details={"path": path, "module_base": module_base},
        )
    elif updated.phase != UnpackPhase.DUMPED:
        updated = append_timeline(
            updated,
            event="dump_phase_skipped",
            message=f"dump ok but cannot transition from {updated.phase.value} to dumped",
            output_sha256=sha256,
            details={"path": path},
        )
    return add_artifact(
        updated,
        kind="module_dump",
        path=path,
        sha256=sha256,
        phase=UnpackPhase.DUMPED,
    )


def note_imports_rebuilt(
    state: UnpackSessionState,
    *,
    output_path: str | Path,
    sha256: str,
    kind: str = "pe_rebuilt",
) -> UnpackSessionState:
    """Advance to IMPORTS_REBUILT after IAT/PE rebuild produced an artifact."""
    path = str(output_path)
    updated = state
    has_dump = any(item.kind == "module_dump" for item in updated.artifacts)

    if updated.phase == UnpackPhase.OEP_CANDIDATE and has_dump:
        updated = transition(
            updated,
            UnpackPhase.DUMPED,
            event="dump_inferred",
            message="dump artifact present; catching up phase to dumped",
            details={"artifact_kinds": [item.kind for item in updated.artifacts]},
        )
    elif updated.phase == UnpackPhase.OEP_CANDIDATE:
        updated = transition(
            updated,
            UnpackPhase.DUMPED,
            event="rebuild_implies_dumped",
            message="imports rebuild implies a dump input; marking dumped",
            details={"path": path},
        )

    if (
        updated.phase == UnpackPhase.DUMPED
        and can_transition(updated.phase, UnpackPhase.IMPORTS_REBUILT)
    ):
        updated = transition(
            updated,
            UnpackPhase.IMPORTS_REBUILT,
            event="imports_rebuilt",
            message="import tables rebuilt into artifact",
            output_sha256=sha256,
            details={"path": path, "kind": kind},
        )
    elif updated.phase == UnpackPhase.IMPORTS_REBUILT:
        updated = append_timeline(
            updated,
            event="imports_rebuilt_again",
            message="additional rebuilt PE recorded",
            output_sha256=sha256,
            details={"path": path, "kind": kind},
        )
    else:
        updated = append_timeline(
            updated,
            event="imports_rebuild_phase_skipped",
            message=(
                f"rebuild ok but cannot transition from {updated.phase.value} "
                "to imports_rebuilt"
            ),
            output_sha256=sha256,
            details={"path": path, "kind": kind},
        )
    return add_artifact(
        updated,
        kind=kind,
        path=path,
        sha256=sha256,
        phase=UnpackPhase.IMPORTS_REBUILT,
    )


def note_verified(
    state: UnpackSessionState,
    *,
    path: str | Path,
    sha256: str | None = None,
    reanalyzed: bool = False,
) -> UnpackSessionState:
    """Advance to VERIFIED / REANALYZED after unpack.verify."""
    target_path = str(path)
    updated = state
    if can_transition(updated.phase, UnpackPhase.VERIFIED):
        # Hop through missing phases with explicit timeline notes (honest shortcuts).
        if updated.phase == UnpackPhase.OEP_CANDIDATE:
            updated = transition(
                updated,
                UnpackPhase.DUMPED,
                event="verify_implies_dumped",
                message="verify without dumped phase; recording implied dump",
                details={"path": target_path},
            )
        if updated.phase == UnpackPhase.DUMPED:
            updated = transition(
                updated,
                UnpackPhase.IMPORTS_REBUILT,
                event="verify_implies_imports",
                message="verify without imports_rebuilt; recording implied rebuild",
                details={"path": target_path},
            )
        if updated.phase == UnpackPhase.IMPORTS_REBUILT:
            updated = transition(
                updated,
                UnpackPhase.VERIFIED,
                event="verified",
                message="rebuilt PE structural verify completed",
                output_sha256=sha256,
                details={"path": target_path},
            )
    elif updated.phase == UnpackPhase.VERIFIED:
        updated = append_timeline(
            updated,
            event="verified_again",
            message="additional verify recorded",
            output_sha256=sha256,
            details={"path": target_path},
        )
    else:
        updated = append_timeline(
            updated,
            event="verify_phase_skipped",
            message=f"verify ok but cannot transition from {updated.phase.value}",
            output_sha256=sha256,
            details={"path": target_path},
        )
    if reanalyzed and can_transition(updated.phase, UnpackPhase.REANALYZED):
        updated = transition(
            updated,
            UnpackPhase.REANALYZED,
            event="ida_reanalyzed",
            message="verify opened IDA idalib on rebuilt artifact",
            output_sha256=sha256,
            details={"path": target_path},
        )
    if sha256:
        updated = add_artifact(
            updated,
            kind="verified_pe",
            path=target_path,
            sha256=sha256,
            phase=updated.phase,
        )
    return updated
