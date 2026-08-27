"""Focused coverage for fail-closed stage-label mapping and upgrade gating.

These exercise the pure-logic honesty rules in ``unpack/stage_labels``: artifact
kind → public stage mapping, the downgrade/same-stage/unknown branches of the
upgrade gate, every fail-closed reason for the IAT-rebuilt and runnable targets,
and how ``resolve_artifact_kind_for_stage`` refuses to invent a runnable kind.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.unpack.stage_labels import (
    STAGE_DUMPED,
    STAGE_IAT_REBUILT,
    STAGE_RUNNABLE,
    gate_stage_upgrade,
    resolve_artifact_kind_for_stage,
    stage_for_artifact_kind,
)


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("runnable_pe", STAGE_RUNNABLE),
        ("iat_rebuilt", STAGE_IAT_REBUILT),
        ("pe_rebuilt", STAGE_IAT_REBUILT),
        ("scylla_iat_rebuilt", STAGE_IAT_REBUILT),
        ("module_dump", STAGE_DUMPED),
        # verified_pe is structural only — mapped to iat-rebuilt, never runnable.
        ("verified_pe", STAGE_IAT_REBUILT),
        ("something_unknown", STAGE_DUMPED),
        ("", STAGE_DUMPED),
    ],
)
def test_stage_for_artifact_kind_mapping(kind: str, expected: str) -> None:
    assert stage_for_artifact_kind(kind) == expected


def test_stage_for_artifact_kind_handles_non_str() -> None:
    # Falsy / non-string coerces to "" then falls through to dumped.
    assert stage_for_artifact_kind(None) == STAGE_DUMPED  # type: ignore[arg-type]


def test_gate_unknown_stage_is_blocked() -> None:
    result = gate_stage_upgrade(current_stage="dumped", target_stage="teleported")
    assert result["allowed"] is False
    assert "unknown_stage" in result["reasons"]
    assert result["claims_universal_unpack"] is False


def test_gate_unknown_current_stage_is_blocked() -> None:
    result = gate_stage_upgrade(current_stage="mystery", target_stage=STAGE_RUNNABLE)
    assert result["allowed"] is False
    assert "unknown_stage" in result["reasons"]


def test_gate_downgrade_forbidden() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_RUNNABLE,
        target_stage=STAGE_DUMPED,
    )
    assert result["allowed"] is False
    assert "downgrade_forbidden" in result["reasons"]


def test_gate_same_stage_allowed() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_IAT_REBUILT,
        target_stage=STAGE_IAT_REBUILT,
    )
    assert result["allowed"] is True
    assert "same_stage" in result["reasons"]


def test_gate_defaults_blank_stages_to_dumped_same_stage() -> None:
    result = gate_stage_upgrade(current_stage="", target_stage="")
    assert result["current_stage"] == STAGE_DUMPED
    assert result["target_stage"] == STAGE_DUMPED
    assert result["allowed"] is True
    assert "same_stage" in result["reasons"]


def test_gate_iat_upgrade_clean_is_allowed() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_DUMPED,
        target_stage=STAGE_IAT_REBUILT,
    )
    assert result["allowed"] is True
    assert result["reasons"] == []


def test_gate_iat_upgrade_blocked_by_rebuild_gate() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_DUMPED,
        target_stage=STAGE_IAT_REBUILT,
        rebuild_allowed=False,
    )
    assert result["allowed"] is False
    assert "rebuild_gate_blocked" in result["reasons"]


def test_gate_iat_upgrade_blocked_by_pe_verify() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_DUMPED,
        target_stage=STAGE_IAT_REBUILT,
        pe_verify_ok=False,
    )
    assert result["allowed"] is False
    assert "pe_verify_failed" in result["reasons"]


def test_gate_iat_upgrade_blocked_by_pause_not_ready() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_DUMPED,
        target_stage=STAGE_IAT_REBUILT,
        pause_iat_ready=False,
    )
    assert result["allowed"] is False
    assert "pause_not_iat_ready" in result["reasons"]


def test_gate_iat_upgrade_accumulates_all_reasons() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_DUMPED,
        target_stage=STAGE_IAT_REBUILT,
        rebuild_allowed=False,
        pe_verify_ok=False,
        pause_iat_ready=False,
    )
    assert result["allowed"] is False
    assert set(result["reasons"]) == {
        "rebuild_gate_blocked",
        "pe_verify_failed",
        "pause_not_iat_ready",
    }


def test_gate_runnable_requires_all_gates() -> None:
    # No optional gates supplied — every runnable precondition fails closed.
    result = gate_stage_upgrade(
        current_stage=STAGE_IAT_REBUILT,
        target_stage=STAGE_RUNNABLE,
    )
    assert result["allowed"] is False
    assert "ui_gate_not_matched" in result["reasons"]
    assert "pe_verify_not_ok" in result["reasons"]


def test_gate_runnable_blocked_by_rebuild_and_pause() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_IAT_REBUILT,
        target_stage=STAGE_RUNNABLE,
        ui_gate_matched=True,
        pe_verify_ok=True,
        rebuild_allowed=False,
        pause_iat_ready=False,
    )
    assert result["allowed"] is False
    assert "rebuild_gate_blocked" in result["reasons"]
    assert "pause_not_iat_ready" in result["reasons"]


def test_gate_runnable_clean_upgrade_from_dumped() -> None:
    result = gate_stage_upgrade(
        current_stage=STAGE_DUMPED,
        target_stage=STAGE_RUNNABLE,
        ui_gate_matched=True,
        pe_verify_ok=True,
        rebuild_allowed=True,
        pause_iat_ready=True,
    )
    assert result["allowed"] is True
    assert result["reasons"] == []


def _allowed_gate(target: str) -> dict[str, object]:
    return {"allowed": True, "target_stage": target}


def _blocked_gate() -> dict[str, object]:
    return {"allowed": False}


def test_resolve_blocked_downgrades_runnable_to_verified_pe() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_RUNNABLE,
        preferred_kind="runnable_pe",
        upgrade_gate=_blocked_gate(),
    )
    assert kind == "verified_pe"


def test_resolve_blocked_keeps_allowed_preferred_kind() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_IAT_REBUILT,
        preferred_kind="pe_rebuilt",
        upgrade_gate=_blocked_gate(),
    )
    assert kind == "pe_rebuilt"


def test_resolve_blocked_unknown_preferred_falls_back_to_module_dump() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_IAT_REBUILT,
        preferred_kind="not_a_kind",
        upgrade_gate=_blocked_gate(),
    )
    assert kind == "module_dump"


def test_resolve_blocked_blank_preferred_defaults_to_module_dump() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_IAT_REBUILT,
        preferred_kind="",
        upgrade_gate=_blocked_gate(),
    )
    assert kind == "module_dump"


def test_resolve_allowed_runnable_returns_runnable_pe() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_RUNNABLE,
        preferred_kind="module_dump",
        upgrade_gate=_allowed_gate(STAGE_RUNNABLE),
    )
    assert kind == "runnable_pe"


def test_resolve_allowed_iat_keeps_specific_preferred() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_IAT_REBUILT,
        preferred_kind="scylla_iat_rebuilt",
        upgrade_gate=_allowed_gate(STAGE_IAT_REBUILT),
    )
    assert kind == "scylla_iat_rebuilt"


def test_resolve_allowed_iat_generic_preferred_becomes_iat_rebuilt() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_IAT_REBUILT,
        preferred_kind="module_dump",
        upgrade_gate=_allowed_gate(STAGE_IAT_REBUILT),
    )
    assert kind == "iat_rebuilt"


def test_resolve_allowed_dumped_target_returns_module_dump() -> None:
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_DUMPED,
        preferred_kind="iat_rebuilt",
        upgrade_gate=_allowed_gate(STAGE_DUMPED),
    )
    assert kind == "module_dump"
