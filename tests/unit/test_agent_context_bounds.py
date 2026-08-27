from __future__ import annotations

import json

from headless_re_mcp.agent.context import (
    _message_size,
    _shrink,
    _shrink_arguments,
    compact_messages,
)


def test_compaction_counts_tool_call_arguments_toward_the_context_budget() -> None:
    """Arguments are request context even though they are not message content.

    A single call at the orchestrator's 256 KiB argument ceiling previously
    counted as zero characters here.  With an 8,000-character budget the full
    262 KiB request was therefore returned unchanged, and every later round
    sent it again.
    """
    messages = [
        {"role": "system", "content": "Use the catalog."},
        {"role": "user", "content": "Inspect the sample."},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call-large",
                    "type": "function",
                    "function": {
                        "name": "session.get",
                        "arguments": "x" * 262_144,
                    },
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call-large", "content": "{}"},
    ]

    before = len(json.dumps(messages, separators=(",", ":")))
    compacted = compact_messages(messages, threshold_percent=10, max_chars=20_000)
    after = len(json.dumps(compacted, separators=(",", ":")))

    assert before > 262_000
    assert after < 8_000, f"8,000-character budget still produced {after} characters"
    assert compacted != messages, "the oversized non-content fields must trigger compaction"
    assert any(item.get("role") == "user" for item in compacted), "keep the task"


def test_compaction_reserves_room_for_its_own_system_messages() -> None:
    """The tail may not consume space the compactor adds afterwards.

    Measured with an 8,000-character budget: the selected tail fit by itself,
    then the preserved system prompt and compaction notice made the final wire
    request 8,115 characters. A request reported as bounded was still over the
    provider boundary.
    """
    messages = [
        {"role": "system", "content": "fixed system instruction"},
        {"role": "user", "content": "old:" + "o" * 1_000},
        {"role": "user", "content": "latest:" + "x" * 7_900},
    ]

    compacted = compact_messages(messages, threshold_percent=10, max_chars=20_000)
    wire_chars = len(
        json.dumps(compacted, ensure_ascii=False, separators=(",", ":"))
    )

    assert wire_chars <= 8_000, f"8,000-character budget produced {wire_chars}"
    assert str(compacted[-1].get("content", "")).startswith("latest:")


def test_message_size_treats_a_cyclic_message_as_larger_than_any_budget() -> None:
    """A message the encoder cannot serialize must not crash the compactor.

    A tool result can carry a cyclic or pathologically nested structure;
    json.dumps raises on it. The size probe classifies that as over any useful
    budget (so the compactor drops or shrinks it) instead of raising while it is
    trying to enforce the boundary.
    """
    item: dict[str, object] = {"role": "assistant", "content": "x"}
    item["self"] = item
    assert _message_size(item) == 1 << 60


def test_shrink_arguments_leaves_arguments_that_already_fit() -> None:
    assert _shrink_arguments("small-args", 100) == "small-args"


def test_shrink_skips_a_malformed_tool_call_entry() -> None:
    """tool_calls may contain junk; a non-dict entry is dropped, not fatal.

    When shrinking a large assistant turn the compactor rebuilds each tool_call
    slimmer, but a provider echo or a corrupt row can leave a non-dict in the
    list. It is skipped so the well-formed calls still survive the shrink.
    """
    item = {
        "role": "assistant",
        "content": "c" * 400,
        "tool_calls": [
            "not-a-dict",
            {
                "id": "call-1",
                "type": "function",
                "function": {"name": "session.get", "arguments": "a" * 600},
            },
        ],
    }
    shrunk = _shrink(item, 120)
    calls = shrunk["tool_calls"]
    assert isinstance(calls, list)
    assert [call["id"] for call in calls] == ["call-1"]


def test_compaction_without_a_system_prompt_still_bounds_the_wire() -> None:
    """A thread can reach the compactor with no system message at all.

    The reserved-space calculation adds the preserved system prompt only when
    one exists; with none, it reserves just its own notice and still keeps the
    result under budget. Nothing should be prepended that was not there.
    """
    messages = [
        {"role": "user", "content": "old:" + "o" * 2_000},
        {"role": "user", "content": "latest:" + "x" * 9_000},
    ]

    compacted = compact_messages(messages, threshold_percent=10, max_chars=20_000)
    wire_chars = len(json.dumps(compacted, ensure_ascii=False, separators=(",", ":")))

    assert wire_chars <= 8_000
    assert not any(item.get("role") == "system" and "compacted" not in str(item.get("content"))
                   for item in compacted), "no original system prompt existed to preserve"
    assert str(compacted[-1].get("content", "")).startswith("latest:")


def test_compaction_drops_a_turn_whose_tool_calls_cannot_be_shrunk_to_fit() -> None:
    """A turn dominated by tool-call arguments is dropped, not truncated wrong.

    Shrinking content cannot make a message with hundreds of tool calls fit,
    because the arguments are request context that content-trimming never
    touches and each call has a floor size. Rather than truncate an old
    instruction into a different call, the compactor drops that turn and keeps
    the recent task, which is what lets the run continue instead of dying on a
    provider 400.
    """
    huge_calls = [
        {
            "id": f"call-{index}",
            "type": "function",
            "function": {"name": "session.get", "arguments": "a" * 200},
        }
        for index in range(500)
    ]
    messages = [
        {"role": "system", "content": "system instruction"},
        {"role": "user", "content": "the real task to keep"},
        {"role": "assistant", "content": "c" * 50, "tool_calls": huge_calls},
    ]

    compacted = compact_messages(messages, threshold_percent=10, max_chars=20_000)

    assert any(
        item.get("role") == "user" and "real task" in str(item.get("content"))
        for item in compacted
    ), "the recent task must survive"
    assert not any(item.get("role") == "assistant" for item in compacted), (
        "the un-shrinkable tool-call turn must be dropped, not truncated"
    )
    wire_chars = len(json.dumps(compacted, ensure_ascii=False, separators=(",", ":")))
    assert wire_chars <= 8_000
