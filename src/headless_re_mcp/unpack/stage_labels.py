"""Fail-closed dump / rebuild / runnable stage labels.

UI-visible or PE-parseable artifacts must not be labeled runnable unless an
explicit gate passes. Tools never claim universal unpack success.
"""

from __future__ import annotations

from typing import Any

JsonObject = dict[str, Any]

STAGE_DUMPED = "dumped"
STAGE_IAT_REBUILT = "iat-rebuilt"
STAGE_RUNNABLE = "runnable"

_ALLOWED_KINDS = frozenset(
    {
        "module_dump",
        "iat_rebuilt",
        "pe_rebuilt",
        "scylla_iat_rebuilt",
        "verified_pe",
        "runnable_pe",
    }
)


def stage_for_artifact_kind(kind: str) -> str:
    """Map artifact kind to public stage label (never invents runnable)."""
    key = str(kind or "")
    if key == "runnable_pe":
        return STAGE_RUNNABLE
    if key in {"iat_rebuilt", "pe_rebuilt", "scylla_iat_rebuilt"}:
        return STAGE_IAT_REBUILT
    if key in {"module_dump", "verified_pe"}:
        # verified_pe is structural only — still not runnable.
        return STAGE_DUMPED if key == "module_dump" else STAGE_IAT_REBUILT
    return STAGE_DUMPED


def gate_stage_upgrade(
    *,
    current_stage: str,
    target_stage: str,
    rebuild_allowed: bool | None = None,
    pe_verify_ok: bool | None = None,
    ui_gate_matched: bool | None = None,
    pause_iat_ready: bool | None = None,
) -> JsonObject:
    """Decide whether a stage label may advance. Fail-closed for runnable."""
    order = {STAGE_DUMPED: 0, STAGE_IAT_REBUILT: 1, STAGE_RUNNABLE: 2}
    cur = str(current_stage or STAGE_DUMPED)
    tgt = str(target_stage or STAGE_DUMPED)
    reasons: list[str] = []
    allowed = True
    if tgt not in order or cur not in order:
        allowed = False
        reasons.append("unknown_stage")
    elif order[tgt] < order[cur]:
        allowed = False
        reasons.append("downgrade_forbidden")
    elif order[tgt] == order[cur]:
        allowed = True
        reasons.append("same_stage")
    else:
        if tgt == STAGE_IAT_REBUILT:
            if rebuild_allowed is False:
                allowed = False
                reasons.append("rebuild_gate_blocked")
            if pe_verify_ok is False:
                allowed = False
                reasons.append("pe_verify_failed")
            if pause_iat_ready is False:
                allowed = False
                reasons.append("pause_not_iat_ready")
        if tgt == STAGE_RUNNABLE:
            # Runnable requires UI gate match + structural PE ok + rebuild allowed.
            if ui_gate_matched is not True:
                allowed = False
                reasons.append("ui_gate_not_matched")
            if pe_verify_ok is not True:
                allowed = False
                reasons.append("pe_verify_not_ok")
            if rebuild_allowed is False:
                allowed = False
                reasons.append("rebuild_gate_blocked")
            if pause_iat_ready is False:
                allowed = False
                reasons.append("pause_not_iat_ready")
    return {
        "allowed": allowed,
        "current_stage": cur,
        "target_stage": tgt,
        "reasons": reasons,
        "claims_universal_unpack": False,
        "note": (
            "UI visible / dumped does not imply IAT-ready or runnable; "
            "runnable requires explicit gates"
        ),
    }


def resolve_artifact_kind_for_stage(
    *,
    target_stage: str,
    preferred_kind: str,
    upgrade_gate: JsonObject,
) -> str:
    """Return artifact kind only if upgrade gate allows; else keep non-runnable kind."""
    preferred = str(preferred_kind or "module_dump")
    if not upgrade_gate.get("allowed"):
        if preferred == "runnable_pe":
            return "verified_pe"
        return preferred if preferred in _ALLOWED_KINDS else "module_dump"
    if target_stage == STAGE_RUNNABLE:
        return "runnable_pe"
    if target_stage == STAGE_IAT_REBUILT:
        if preferred in {"iat_rebuilt", "pe_rebuilt", "scylla_iat_rebuilt", "verified_pe"}:
            return preferred
        return "iat_rebuilt"
    return "module_dump"