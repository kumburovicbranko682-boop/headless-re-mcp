"""Autonomy decision serialization and blank entries in effect lists."""

from __future__ import annotations

from headless_re_mcp.agent.autonomy import AutoApproval, _effects
from headless_re_mcp.tools.catalog import ToolEffect


def test_an_approval_decision_serializes_to_plain_json() -> None:
    # The decision is surfaced to callers (and logs) as a JSON object; the
    # shape is exactly the two fields, with the bool kept as a bool.
    decision = AutoApproval(approved=False, reason="state_change requires consent")

    assert decision.as_json() == {
        "approved": False,
        "reason": "state_change requires consent",
    }


def test_blank_effect_names_are_skipped_while_unknown_ones_still_raise() -> None:
    # Config files with a trailing comma produce empty strings in the effect
    # list. Those are noise, not policy, so they are dropped -- but a real
    # typo must still be rejected loudly rather than silently ignored.
    assert _effects(["", "  ", "read_only"]) == frozenset({ToolEffect.READ_ONLY})
