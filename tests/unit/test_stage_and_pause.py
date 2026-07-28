from __future__ import annotations

from headless_re_mcp.unpack.pause_quality import assess_pause_quality
from headless_re_mcp.unpack.recommend import recommend_unpack_route
from headless_re_mcp.unpack.stage_labels import (
    STAGE_DUMPED,
    STAGE_IAT_REBUILT,
    STAGE_RUNNABLE,
    gate_stage_upgrade,
    resolve_artifact_kind_for_stage,
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
