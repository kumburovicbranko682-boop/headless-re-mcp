"""Coverage for the pause-quality gate's less-travelled reason branches.

``assess_pause_quality`` is pure. These pin the two branches the broader suite
did not reach: flagging a still-packed OEP role, and the note added when the
IAT gate passes while a UI window is already visible.
"""

from __future__ import annotations

from headless_re_mcp.unpack.pause_quality import assess_pause_quality


def test_packed_oep_role_is_flagged_without_blocking_readiness() -> None:
    result = assess_pause_quality(oep_role="packed_ep")
    assert "oep_still_packed_ep" in result["reasons"]
    # A packed-EP note alone does not force observe-only.
    assert result["iat_ready"] is True
    assert result["claims_universal_unpack"] is False


def test_iat_gate_ok_with_ui_visible_records_the_combined_note() -> None:
    result = assess_pause_quality(
        ui_visible=True,
        rebuild_allowed=True,
        recoverability="iat_recoverable",
    )
    assert result["iat_ready"] is True
    # The UI-only caveat is dropped once the gate passes...
    assert "ui_visible_only_not_sufficient" not in result["reasons"]
    # ...and replaced with the combined, honest note.
    assert "ui_visible_and_iat_gate_ok" in result["reasons"]
    assert result["quality"] == "iat_ready"


def test_ui_visible_alone_stays_not_sufficient() -> None:
    result = assess_pause_quality(ui_visible=True)
    assert "ui_visible_only_not_sufficient" in result["reasons"]
    assert "ui_visible_and_iat_gate_ok" not in result["reasons"]


def test_low_resolved_ratio_blocks_readiness() -> None:
    result = assess_pause_quality(resolved_ratio=0.1)
    assert "resolved_ratio_low" in result["reasons"]
    assert result["iat_ready"] is False
    assert result["quality"] == "observe_only"


def test_iat_gate_ok_without_ui_visible_adds_no_ui_note() -> None:
    # Same gate as the UI-visible case, but no window is up: the combined note
    # is only for the UI-visible path, so it must not appear here.
    result = assess_pause_quality(
        rebuild_allowed=True,
        recoverability="iat_recoverable",
    )
    assert result["iat_ready"] is True
    assert result["quality"] == "iat_ready"
    assert "ui_visible_and_iat_gate_ok" not in result["reasons"]
