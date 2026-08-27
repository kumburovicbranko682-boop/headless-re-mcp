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


def test_a_thread_rebuilt_from_the_store_sends_no_orphan_tool_results() -> None:
    """Under budget is also a wire path, and it carried orphans to the provider.

    The store persists an assistant turn's visible text but never its
    tool_calls (and nothing at all for a turn that only called tools), so the
    conversation the orchestrator rebuilds for the next run of a thread has
    every stored tool result answering a call the request no longer makes. An
    OpenAI-compatible API 400s on that. The existing guard only ran once the
    thread outgrew the compaction budget -- a short thread with one tool call
    behind it failed on its second run, before it had said anything.
    """
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "analyze the sample"},
        # Exactly what _run_loop rebuilds: the tool result survived in the
        # store, the assistant tool_calls that opened it did not.
        {"role": "tool", "tool_call_id": "past-call", "content": '{"ok": true}'},
        {"role": "assistant", "content": "Found the entrypoint."},
    ]

    compacted = compact_messages(messages, threshold_percent=80)

    assert [item["role"] for item in compacted] == ["system", "user", "assistant"]
    assert compacted[-1]["content"] == "Found the entrypoint."


def test_the_orphan_filter_keeps_a_whole_batch_of_parallel_tool_results() -> None:
    """One assistant turn answering several calls is the legitimate shape.

    The second result's immediate predecessor is another tool message, not the
    assistant that opened both calls; a filter keyed on adjacency alone would
    drop it and manufacture the very 400 it exists to prevent.
    """
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "go"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "a", "type": "function", "function": {"name": "f", "arguments": "{}"}},
                {"id": "b", "type": "function", "function": {"name": "g", "arguments": "{}"}},
            ],
        },
        {"role": "tool", "tool_call_id": "a", "content": "{}"},
        {"role": "tool", "tool_call_id": "b", "content": "{}"},
    ]

    assert compact_messages(messages, threshold_percent=80) == messages


def test_a_non_tool_turn_closes_the_window_a_tool_result_may_answer() -> None:
    """A result arriving after the conversation moved on no longer has a call.

    The ids an assistant turn opened stop being current once any non-tool
    message intervenes; a tool message past that point would reach the provider
    claiming a call the request's most recent turns do not make.
    """
    messages = [
        {"role": "system", "content": "sys"},
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "a", "type": "function", "function": {"name": "f", "arguments": "{}"}},
            ],
        },
        {"role": "tool", "tool_call_id": "a", "content": "first"},
        {"role": "assistant", "content": "summarised"},
        {"role": "tool", "tool_call_id": "a", "content": "stale"},
    ]

    compacted = compact_messages(messages, threshold_percent=80)

    kept_tools = [item["content"] for item in compacted if item["role"] == "tool"]
    assert kept_tools == ["first"]


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
