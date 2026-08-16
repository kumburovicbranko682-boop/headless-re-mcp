from __future__ import annotations

import json

from headless_re_mcp.agent.context import compact_messages


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
