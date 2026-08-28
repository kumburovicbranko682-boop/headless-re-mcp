"""The IAT rebuild gate confirming recoverability must not overturn the pause
gate's own independent hard vetoes.

``gate_iat_rebuild`` scores stub coupling against the IAT ``api_count`` while
``assess_pause_quality`` compares ``still_vm_stub_count`` against the wholly
separate ``api_call_site_count`` (FF15/FF25 sites) reported by ``stub_calls``.
Those denominators are different measurements, so the gate can honestly report
``iat_recoverable`` while the pause gate independently detects that stub calls
dominate the real call sites. The pause gate is a fail-closed second opinion:
when it fires a hard veto, the result must stay ``iat_ready=False`` and must not
disagree with its own ``reasons`` list.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.unpack.pause_quality import assess_pause_quality

_HARD_VETO_REASONS = {
    "stub_calls_dominate_api_sites",
    "resolved_ratio_low",
    "layout=junk",
    "layout=empty",
    "layout=fragmented",
}


def test_stub_dominance_survives_recoverable_gate() -> None:
    # A dense IAT resolves (gate says recoverable), yet the dump has many E8 stub
    # calls against only a handful of real API call sites. The pause gate must
    # keep refusing instead of silently flipping to ready.
    pause = assess_pause_quality(
        ui_visible=None,
        layout="dense",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        still_vm_stub_count=20,
        api_call_site_count=5,
    )
    assert pause["iat_ready"] is False
    assert "stub_calls_dominate_api_sites" in pause["reasons"]
    assert pause["quality"] == "observe_only"


def test_resolved_ratio_low_survives_recoverable_gate() -> None:
    pause = assess_pause_quality(
        layout="half_sparse",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        resolved_ratio=0.1,
    )
    assert pause["iat_ready"] is False
    assert "resolved_ratio_low" in pause["reasons"]


def test_junk_layout_survives_recoverable_gate() -> None:
    pause = assess_pause_quality(
        layout="junk",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
    )
    assert pause["iat_ready"] is False
    assert "layout=junk" in pause["reasons"]


def test_ui_visible_reason_still_relabelled_when_truly_ready() -> None:
    # Control: gate recoverable AND no hard veto -> the soft "ui visible is not
    # enough" caveat is resolved and relabelled, and readiness holds.
    pause = assess_pause_quality(
        ui_visible=True,
        layout="dense",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        still_vm_stub_count=1,
        api_call_site_count=50,
        resolved_ratio=0.9,
    )
    assert pause["iat_ready"] is True
    assert "ui_visible_and_iat_gate_ok" in pause["reasons"]
    assert "ui_visible_only_not_sufficient" not in pause["reasons"]
    assert pause["quality"] == "iat_ready"


def test_clean_recoverable_pause_is_ready() -> None:
    # Control: no signals of any concern -> ready, no relabel needed.
    pause = assess_pause_quality(
        layout="dense",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        resolved_ratio=0.9,
    )
    assert pause["iat_ready"] is True
    assert pause["quality"] == "iat_ready"
    assert "ui_visible_and_iat_gate_ok" not in pause["reasons"]


def test_stub_dominance_with_ui_visible_reports_ui_not_ready() -> None:
    # When the caller also saw a UI window, the honest quality label is
    # "ui_visible_not_iat_ready", not a bare "observe_only".
    pause = assess_pause_quality(
        ui_visible=True,
        layout="dense",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        still_vm_stub_count=20,
        api_call_site_count=5,
    )
    assert pause["iat_ready"] is False
    assert pause["quality"] == "ui_visible_not_iat_ready"
    # The soft caveat must not be relabelled as "gate ok" while a hard veto holds.
    assert "ui_visible_and_iat_gate_ok" not in pause["reasons"]


def test_packed_ep_is_soft_and_does_not_block_ready() -> None:
    # oep_role still pointing at a packed entry point is recorded as an
    # informational reason but does not by itself refuse readiness.
    pause = assess_pause_quality(
        layout="dense",
        rebuild_allowed=True,
        recoverability="iat_recoverable",
        resolved_ratio=0.9,
        oep_role="packed_ep",
    )
    assert pause["iat_ready"] is True
    assert "oep_still_packed_ep" in pause["reasons"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {
            "layout": "dense",
            "rebuild_allowed": True,
            "recoverability": "iat_recoverable",
            "still_vm_stub_count": 20,
            "api_call_site_count": 5,
        },
        {
            "layout": "half_sparse",
            "rebuild_allowed": True,
            "recoverability": "iat_recoverable",
            "resolved_ratio": 0.1,
        },
        {
            "layout": "junk",
            "rebuild_allowed": True,
            "recoverability": "iat_recoverable",
        },
        {
            "ui_visible": True,
            "layout": "dense",
            "rebuild_allowed": True,
            "recoverability": "iat_recoverable",
            "resolved_ratio": 0.9,
        },
    ],
)
def test_ready_never_disagrees_with_hard_veto_reasons(kwargs: dict) -> None:
    # Invariant: whenever the pause gate claims readiness, none of its hard-veto
    # reasons may remain in the list.
    pause = assess_pause_quality(**kwargs)
    if pause["iat_ready"] is True:
        assert not (_HARD_VETO_REASONS & set(pause["reasons"]))
