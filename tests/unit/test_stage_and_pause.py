from __future__ import annotations

import pytest

from headless_re_mcp.unpack.pause_quality import assess_pause_quality
from headless_re_mcp.unpack.recommend import recommend_unpack_route
from headless_re_mcp.unpack.stage_labels import (
    STAGE_DUMPED,
    STAGE_IAT_REBUILT,
    STAGE_RUNNABLE,
    gate_stage_upgrade,
    resolve_artifact_kind_for_stage,
    stage_for_artifact_kind,
)


def test_ui_visible_not_enough_for_iat_ready() -> None:
    pause = assess_pause_quality(
        ui_visible=True,
        layout="junk",
        rebuild_allowed=False,
        recoverability="iat_insufficient",
    )
    assert pause["iat_ready"] is False
    assert pause["quality"] == "ui_visible_not_iat_ready"


def test_vm_coupled_quality() -> None:
    pause = assess_pause_quality(
        ui_visible=True,
        layout="half_sparse",
        rebuild_allowed=False,
        recoverability="vm_coupled_dump_only",
        still_vm_stub_count=300,
        api_call_site_count=10,
    )
    assert pause["quality"] == "vm_coupled_dump_only"
    assert pause["iat_ready"] is False


def test_code_not_ready_blocks_iat() -> None:
    pause = assess_pause_quality(
        layout="half_sparse",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        code_nonzero_ratio=0.0,
    )
    assert pause["iat_ready"] is False
    assert pause["quality"] == "code_not_ready"


def test_runnable_requires_ui_and_pe() -> None:
    blocked = gate_stage_upgrade(
        current_stage=STAGE_IAT_REBUILT,
        target_stage=STAGE_RUNNABLE,
        pe_verify_ok=True,
        ui_gate_matched=False,
    )
    assert blocked["allowed"] is False
    allowed = gate_stage_upgrade(
        current_stage=STAGE_IAT_REBUILT,
        target_stage=STAGE_RUNNABLE,
        pe_verify_ok=True,
        ui_gate_matched=True,
    )
    assert allowed["allowed"] is True
    kind = resolve_artifact_kind_for_stage(
        target_stage=STAGE_RUNNABLE,
        preferred_kind="runnable_pe",
        upgrade_gate=blocked,
    )
    assert kind == "verified_pe"


def test_bounded_dynamic_defaults_vm_coupled_hint() -> None:
    rec = recommend_unpack_route(
        [{"category": "protector", "name": "VMProtect", "summary": "vmp"}]
    )
    assert rec.route == "bounded_dynamic"
    assert rec.recoverability_hint == "vm_coupled_dump_only"


def test_dumped_stage_constant() -> None:
    assert STAGE_DUMPED == "dumped"


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        # Only the explicitly runnable kind earns the runnable label.
        ("runnable_pe", STAGE_RUNNABLE),
        # verified_pe is structural only -- it must not read as runnable.
        ("verified_pe", STAGE_IAT_REBUILT),
        ("iat_rebuilt", STAGE_IAT_REBUILT),
        ("pe_rebuilt", STAGE_IAT_REBUILT),
        ("scylla_iat_rebuilt", STAGE_IAT_REBUILT),
        ("module_dump", STAGE_DUMPED),
        # Anything unrecognised -- including empty -- is the lowest, safest stage.
        ("something_new", STAGE_DUMPED),
        ("", STAGE_DUMPED),
    ],
)
def test_stage_for_artifact_kind_never_invents_runnable(kind: str, expected: str) -> None:
    """The label map backs the documented ``claims_universal_unpack=false`` promise.

    Runnable is reachable from exactly one kind (``runnable_pe``); every other
    kind, and any unknown one, resolves at or below IAT-rebuilt. A future kind
    added without a mapping must fall through to ``dumped`` rather than silently
    inheriting a higher stage.
    """
    assert stage_for_artifact_kind(kind) == expected


def test_gate_rejects_downgrade_same_stage_and_unknown_stage() -> None:
    downgrade = gate_stage_upgrade(
        current_stage=STAGE_RUNNABLE, target_stage=STAGE_IAT_REBUILT
    )
    assert downgrade["allowed"] is False
    assert "downgrade_forbidden" in downgrade["reasons"]

    same = gate_stage_upgrade(
        current_stage=STAGE_IAT_REBUILT, target_stage=STAGE_IAT_REBUILT
    )
    assert same["allowed"] is True
    assert "same_stage" in same["reasons"]

    unknown = gate_stage_upgrade(current_stage=STAGE_DUMPED, target_stage="teleported")
    assert unknown["allowed"] is False
    assert "unknown_stage" in unknown["reasons"]


def _runnable_gate(**overrides: object) -> dict[str, object]:
    """A runnable upgrade with every gate passing, minus whatever is overridden."""
    signals: dict[str, object] = {
        "ui_gate_matched": True,
        "pe_verify_ok": True,
        "rebuild_allowed": True,
        "pause_iat_ready": True,
    }
    signals.update(overrides)
    return gate_stage_upgrade(
        current_stage=STAGE_IAT_REBUILT,
        target_stage=STAGE_RUNNABLE,
        **signals,  # type: ignore[arg-type]
    )


def test_runnable_upgrade_allowed_only_when_every_signal_passes() -> None:
    assert _runnable_gate()["allowed"] is True


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"ui_gate_matched": False}, "ui_gate_not_matched"),
        # None is "not confirmed", which for the runnable gate is not good enough.
        ({"ui_gate_matched": None}, "ui_gate_not_matched"),
        ({"pe_verify_ok": False}, "pe_verify_not_ok"),
        ({"pe_verify_ok": None}, "pe_verify_not_ok"),
        ({"rebuild_allowed": False}, "rebuild_gate_blocked"),
        ({"pause_iat_ready": False}, "pause_not_iat_ready"),
    ],
)
def test_runnable_gate_fails_closed_on_each_missing_signal(
    override: dict[str, object], reason: str
) -> None:
    """Any single unmet gate blocks the runnable label, with a naming reason."""
    result = _runnable_gate(**override)
    assert result["allowed"] is False
    assert reason in result["reasons"]


def test_resolve_kind_honors_the_gate_in_both_directions() -> None:
    runnable_ok = _runnable_gate()
    assert (
        resolve_artifact_kind_for_stage(
            target_stage=STAGE_RUNNABLE,
            preferred_kind="runnable_pe",
            upgrade_gate=runnable_ok,
        )
        == "runnable_pe"
    )

    iat_ok = gate_stage_upgrade(
        current_stage=STAGE_DUMPED,
        target_stage=STAGE_IAT_REBUILT,
        rebuild_allowed=True,
        pe_verify_ok=True,
        pause_iat_ready=True,
    )
    assert iat_ok["allowed"] is True
    assert (
        resolve_artifact_kind_for_stage(
            target_stage=STAGE_IAT_REBUILT, preferred_kind="pe_rebuilt", upgrade_gate=iat_ok
        )
        == "pe_rebuilt"
    )
    # An allowed IAT upgrade with an unrecognised preferred kind normalises to
    # the canonical iat_rebuilt kind rather than passing the unknown through.
    assert (
        resolve_artifact_kind_for_stage(
            target_stage=STAGE_IAT_REBUILT, preferred_kind="mystery", upgrade_gate=iat_ok
        )
        == "iat_rebuilt"
    )
    # A blocked gate with an unrecognised preferred kind falls back to the
    # lowest, non-runnable kind.
    blocked = _runnable_gate(ui_gate_matched=False)
    assert (
        resolve_artifact_kind_for_stage(
            target_stage=STAGE_RUNNABLE, preferred_kind="mystery", upgrade_gate=blocked
        )
        == "module_dump"
    )


def test_resolve_kind_strips_runnable_when_a_malformed_gate_omits_allowed() -> None:
    """A gate dict without an ``allowed`` key must read as not-allowed (fail-closed)."""
    assert (
        resolve_artifact_kind_for_stage(
            target_stage=STAGE_RUNNABLE, preferred_kind="runnable_pe", upgrade_gate={}
        )
        == "verified_pe"
    )
