from __future__ import annotations

import json

from headless_re_mcp.agent.context import bounded_tool_result, compact_messages


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


def test_a_surrogate_in_a_tool_result_is_replaced_not_fatal() -> None:
    """Hostile binary strings reach tool results as unpaired surrogates.

    json.loads accepts a lone \\ud800 escape in backend JSON, and this
    function's own size check encodes the result before any bound applies,
    so the target's data crashed the size check itself -- an
    incident-labelled run failure. The bounded result must come back UTF-8
    encodable, because the conversation, the store, and httpx all encode it
    again.
    """
    bounded, truncated = bounded_tool_result(
        {"ok": True, "data": {"note": "from \ud800 the binary"}}
    )

    assert truncated is False
    json.dumps(bounded, ensure_ascii=False).encode("utf-8")
    note = bounded["data"]["note"]
    assert "\ud800" not in note
    assert note.startswith("from ") and note.endswith(" the binary")


def test_an_oversized_surrogate_result_still_truncates_cleanly() -> None:
    bounded, truncated = bounded_tool_result(
        {"ok": True, "data": {"blob": "\ud800" + "x" * 40_000}}, max_bytes=1_024
    )

    assert truncated is True
    assert bounded["ok"] is True
    json.dumps(bounded, ensure_ascii=False).encode("utf-8")
