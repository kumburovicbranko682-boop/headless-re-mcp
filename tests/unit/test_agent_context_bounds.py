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


def _unanswered_call_ids(messages: list[dict]) -> list[str]:
    """Tool-call ids no role="tool" message answers -- each one is a provider 400."""
    answered = {
        str(item.get("tool_call_id") or "")
        for item in messages
        if item.get("role") == "tool"
    }
    return [
        str(call.get("id"))
        for item in messages
        if item.get("role") == "assistant"
        for call in item.get("tool_calls") or []
        if str(call.get("id")) not in answered
    ]


def test_a_dropped_oversized_tool_result_leaves_its_call_answered() -> None:
    """The wire request may not end on an assistant turn with an open tool call.

    A tool result's content is measured JSON-encoded, so escape-heavy output
    (control characters encode six-to-one) can exceed the tail budget even
    after the shrink cut the string to half of it. The selection loop then
    drops that newest result -- but the small assistant turn that called for it
    survives, and an OpenAI-compatible provider 400s on a ``tool_calls``
    message with no tool message answering each id, killing the run. The call
    must come back answered, by a stub that says the result was omitted.
    """
    messages = [
        {"role": "system", "content": "persona"},
        {"role": "user", "content": "unpack the bundle"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "web.script.source", "arguments": "{}"},
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "\x01" * 40_000},
    ]

    compacted = compact_messages(messages, threshold_percent=10)

    assert _unanswered_call_ids(compacted) == []
    stub = next(item for item in compacted if item.get("role") == "tool")
    assert stub["tool_call_id"] == "call_1"
    assert "omitted" in str(stub["content"])
    assert "\x01" not in json.dumps(compacted), "the oversized result itself stays dropped"


def test_a_partially_answered_turn_keeps_real_results_and_stubs_the_rest() -> None:
    """Only the dropped call gets a stub; surviving results pass through verbatim.

    One assistant turn can make several calls of which only one result was too
    large to keep. The genuine result must survive untouched and the stub must
    answer exactly the missing id, in the position the dropped result held.
    """
    messages = [
        {"role": "system", "content": "persona"},
        {"role": "user", "content": "task"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "call_a", "type": "function", "function": {"name": "t", "arguments": "{}"}},
                {"id": "call_b", "type": "function", "function": {"name": "t", "arguments": "{}"}},
            ],
        },
        {"role": "tool", "tool_call_id": "call_a", "content": "genuine result"},
        {"role": "tool", "tool_call_id": "call_b", "content": "\x01" * 40_000},
    ]

    compacted = compact_messages(messages, threshold_percent=10)

    assert _unanswered_call_ids(compacted) == []
    tools = [item for item in compacted if item.get("role") == "tool"]
    assert [item["tool_call_id"] for item in tools] == ["call_a", "call_b"]
    assert tools[0]["content"] == "genuine result"
    assert "omitted" in str(tools[1]["content"])


def test_an_answered_tail_gains_no_stubs() -> None:
    """When every kept call kept its result, the repair must add nothing."""
    messages = [
        {"role": "system", "content": "persona"},
        {"role": "user", "content": "old turn " + "o" * 9_000},
        {"role": "user", "content": "task"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"id": "call_1", "type": "function", "function": {"name": "t", "arguments": "{}"}}
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": "kept result"},
    ]

    compacted = compact_messages(messages, threshold_percent=10)

    tools = [item for item in compacted if item.get("role") == "tool"]
    assert tools == [{"role": "tool", "tool_call_id": "call_1", "content": "kept result"}]
    assert _unanswered_call_ids(compacted) == []
