"""Guard/edge coverage for bounded conversation compaction.

``test_agent_context_bounds.py`` covers the sizing invariants. These pin the
remaining branches of ``agent/context.py``: the cyclic-message size fallback,
arguments that already fit, a non-dict tool_call entry being skipped, the
no-system-prompt reservation path, and an oversized orphan tool-call turn that
stays too big even after shrinking.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.agent.context import (
    _message_size,
    _shrink,
    _shrink_arguments,
    compact_messages,
)


def test_message_size_treats_a_cyclic_message_as_over_budget() -> None:
    cyclic: dict[str, Any] = {"role": "assistant"}
    cyclic["self"] = cyclic  # json.dumps raises ValueError on the circular ref
    assert _message_size(cyclic) == 1 << 60


def test_shrink_arguments_returns_input_unchanged_when_it_already_fits() -> None:
    assert _shrink_arguments("small", 100) == "small"


def test_shrink_skips_non_dict_tool_call_entries() -> None:
    item = {
        "role": "assistant",
        "content": "C" * 500,
        "tool_calls": [
            "not-a-call",
            {
                "id": "keep",
                "type": "function",
                "function": {"name": "session.get", "arguments": "A" * 500},
            },
        ],
    }

    trimmed = _shrink(item, 100)

    calls = trimmed["tool_calls"]
    assert isinstance(calls, list)
    assert len(calls) == 1, "the non-dict entry must be dropped, not carried through"
    assert calls[0]["function"]["name"] == "session.get"


def test_compaction_without_a_system_prompt_still_bounds_the_tail() -> None:
    # No role="system" message: the system-prompt reservation branch is skipped
    # and only the omission notice is reserved.
    messages = [
        {"role": "user", "content": "old task"},
        {"role": "user", "content": "latest:" + "x" * 40_000},
    ]

    compacted = compact_messages(messages, threshold_percent=10, max_chars=20_000)

    assert compacted[0]["role"] == "system"  # the omission notice
    assert "compacted" in compacted[0]["content"]
    assert any(str(item.get("content", "")).startswith("latest:") for item in compacted)


def test_oversized_orphan_tool_call_turn_collapses_to_the_notice() -> None:
    # A single assistant turn whose tool_calls stay larger than the budget even
    # after shrinking, with no user task to fall back to: it is dropped and the
    # frame is just the honest omission notice.
    big = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": f"c{i}",
                "type": "function",
                "function": {"name": "t", "arguments": "A" * 80},
            }
            for i in range(400)
        ],
    }

    compacted = compact_messages([big], threshold_percent=10, max_chars=20_000)

    assert len(compacted) == 1
    assert compacted[0]["role"] == "system"
    assert "compacted" in compacted[0]["content"]
