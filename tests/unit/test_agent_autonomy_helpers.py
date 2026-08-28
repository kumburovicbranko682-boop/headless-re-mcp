"""Small-helper coverage for the agent autonomy policy.

``test_agent_autonomy.py`` drives the policy decisions end to end. These pin two
helpers the decision tests do not reach directly: ``AutoApproval.as_json`` (the
policy result is asserted as an object elsewhere, never serialized) and
``_effects`` skipping blank entries in an effect list rather than trying to
resolve an empty string into a ToolEffect. A separate file keeps this off the
heavily-edited ``test_agent_autonomy.py``.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.agent.autonomy import AutoApproval, _effects
from headless_re_mcp.tools.catalog import ToolEffect


def test_auto_approval_serializes_to_a_plain_object() -> None:
    approved = AutoApproval(approved=True, reason="read-only tool")
    assert approved.as_json() == {"approved": True, "reason": "read-only tool"}

    denied = AutoApproval(approved=False, reason="write not allowlisted")
    assert denied.as_json() == {"approved": False, "reason": "write not allowlisted"}


def test_effects_skips_blank_entries_and_resolves_the_rest() -> None:
    # An empty or whitespace-only entry is dropped before it can be resolved,
    # so a stray "" in a config list does not blow up the whole policy load.
    resolved = _effects(["", "  ", "read_only", "FILE_WRITE"])
    assert resolved == frozenset({ToolEffect.READ_ONLY, ToolEffect.FILE_WRITE})


def test_effects_still_rejects_a_non_blank_unknown_effect() -> None:
    with pytest.raises(ValueError, match="unknown tool effect 'nope'"):
        _effects(["read_only", "nope"])
