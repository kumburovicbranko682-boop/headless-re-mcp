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


def test_stub_call_dominance_is_not_overridden_by_the_iat_gate() -> None:
    """A recoverable import gate must not resurrect readiness over stub coupling.

    ``gate_iat_rebuild`` decides ``iat_recoverable`` from import-slot analysis
    and a stub ratio measured against the *import count*. ``pause_quality`` adds
    an independent, fail-closed signal from the code scan: when E8 calls into VM
    stubs dominate the FF15/FF25 API call sites, the dump is still VM-coupled
    even though slots resolved (see stub_calls). The final "gate ok" branch used
    to set ``iat_ready = True`` unconditionally, discarding that veto while
    leaving its reason in the list -- an over-optimistic, self-contradicting
    result that then flowed into stage upgrade. Readiness must stay blocked.
    """
    pause = assess_pause_quality(
        layout="half_sparse",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        still_vm_stub_count=50,
        api_call_site_count=10,
        resolved_ratio=0.9,
        code_nonzero_ratio=0.9,
    )
    assert pause["iat_ready"] is False
    assert "stub_calls_dominate_api_sites" in pause["reasons"]
    assert pause["quality"] != "iat_ready"


def test_low_resolved_ratio_is_not_overridden_by_the_iat_gate() -> None:
    """A half-sparse layout can be ``iat_recoverable`` yet resolve few slots.

    ``half_sparse`` only needs at least eight API slots and an alternating
    api/null pattern -- not a high overall resolved ratio -- so the gate can
    report ``iat_recoverable`` while most of the window is unresolved.
    ``pause_quality`` flags ``resolved_ratio < 0.25`` as a hard block, and the
    old override wrongly flipped it back to ready. The block must survive.
    """
    pause = assess_pause_quality(
        layout="half_sparse",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        resolved_ratio=0.1,
        code_nonzero_ratio=0.9,
    )
    assert pause["iat_ready"] is False
    assert "resolved_ratio_low" in pause["reasons"]


def test_clean_iat_gate_still_confirms_ui_visible_readiness() -> None:
    """With no fail-closed signal, a clean gate still lifts the UI-only caveat.

    This is the intended positive path the override serves: UI visibility alone
    is not enough, but once the import gate checks out and nothing else objects,
    readiness holds and the soft caveat is replaced by the affirmative note.
    """
    pause = assess_pause_quality(
        ui_visible=True,
        layout="dense",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        still_vm_stub_count=1,
        api_call_site_count=40,
        resolved_ratio=0.9,
        code_nonzero_ratio=0.9,
    )
    assert pause["iat_ready"] is True
    assert "ui_visible_and_iat_gate_ok" in pause["reasons"]
    assert "ui_visible_only_not_sufficient" not in pause["reasons"]


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
