from __future__ import annotations

import json

from headless_re_mcp.agent.context import compact_messages, rebuild_provider_messages

JsonObject = dict[str, object]


def _offered_call_ids(messages: list[JsonObject]) -> set[str]:
    offered: set[str] = set()
    for message in messages:
        if message.get("role") == "assistant":
            for call in message.get("tool_calls") or []:  # type: ignore[union-attr]
                offered.add(str(call["id"]))
    return offered


def _assert_valid_tool_pairing(messages: list[JsonObject]) -> None:
    """Every tool message answers a preceding call; every call is answered.

    Both halves are hard provider constraints: an OpenAI-compatible API 400s on
    a tool message with no matching assistant tool_call, and equally on an
    assistant tool_call left without a tool response.
    """
    offered = _offered_call_ids(messages)
    answered = {
        str(message.get("tool_call_id"))
        for message in messages
        if message.get("role") == "tool"
    }
    orphans = [
        message.get("tool_call_id")
        for message in messages
        if message.get("role") == "tool" and str(message.get("tool_call_id")) not in offered
    ]
    assert not orphans, f"tool results with no preceding tool_call: {orphans}"
    dangling = [call_id for call_id in offered if call_id not in answered]
    assert not dangling, f"tool_calls with no tool response: {dangling}"


def test_rebuild_reattaches_tool_calls_so_a_replayed_result_is_not_orphaned() -> None:
    """A continued mission must not resend a tool result the provider 400s on.

    The store keeps a run's tool result as a role="tool" row with only its
    tool_call_id -- the assistant tool_calls that named it are not persisted.
    Replayed on the mission's next run that row is an orphan, which the provider
    rejects, so the run and the mission die on their second attempt.
    """
    stored = [
        {"role": "user", "content": "continuation contract attempt 1"},
        {"role": "assistant", "content": "working on it"},
        {"role": "tool", "content": '{"ok": true}', "tool_call_id": "call1"},
        {"role": "user", "content": "continuation contract attempt 2"},
    ]

    rebuilt = rebuild_provider_messages(stored)

    _assert_valid_tool_pairing(rebuilt)
    assistant = next(item for item in rebuilt if item.get("role") == "assistant")
    assert assistant["content"] == "working on it", "the visible text must survive"
    assert [call["id"] for call in assistant["tool_calls"]] == ["call1"]  # type: ignore[index]


def test_rebuild_inserts_an_assistant_turn_when_the_answer_had_no_visible_text() -> None:
    """A tool call with no spoken text stored nothing to hang the call on.

    The orchestrator only stores an assistant message when the turn produced
    visible text, so a pure tool-call turn leaves the result following a user
    message. There is no assistant row to merge onto, so one has to be inserted.
    """
    stored = [
        {"role": "user", "content": "contract"},
        {"role": "tool", "content": "result", "tool_call_id": "c1"},
    ]

    rebuilt = rebuild_provider_messages(stored)

    _assert_valid_tool_pairing(rebuilt)
    assert [item["role"] for item in rebuilt] == ["user", "assistant", "tool"]
    assert rebuilt[1]["content"] is None


def test_rebuild_pairs_every_tool_in_a_multi_call_turn() -> None:
    """One assistant turn can answer with several tools; all must be paired."""
    stored = [
        {"role": "assistant", "content": "two things"},
        {"role": "tool", "content": "r1", "tool_call_id": "c1"},
        {"role": "tool", "content": "r2", "tool_call_id": "c2"},
    ]

    rebuilt = rebuild_provider_messages(stored)

    _assert_valid_tool_pairing(rebuilt)
    assistant = next(item for item in rebuilt if item.get("role") == "assistant")
    assert [call["id"] for call in assistant["tool_calls"]] == ["c1", "c2"]  # type: ignore[index]


def test_rebuild_handles_a_leading_tool_row_from_retention_trimming() -> None:
    """Message retention can drop the turn a tool result answered.

    The store trims a long thread's oldest messages, which can leave a tool row
    at the very front. Rebuilding must still put an assistant tool_call before
    it rather than emit a conversation that opens on an orphan.
    """
    stored = [
        {"role": "tool", "content": "r", "tool_call_id": "c9"},
        {"role": "assistant", "content": "final answer"},
    ]

    rebuilt = rebuild_provider_messages(stored)

    _assert_valid_tool_pairing(rebuilt)
    assert rebuilt[0]["role"] == "assistant"


def test_rebuild_gives_an_idless_tool_row_a_generated_id() -> None:
    """A tool row without an id still has to be pairable.

    The store always writes one, but the rebuild is the boundary that keeps the
    request valid, so it must not depend on that and emit an unpairable turn.
    """
    stored = [
        {"role": "assistant", "content": "x"},
        {"role": "tool", "content": "r", "tool_call_id": None},
    ]

    rebuilt = rebuild_provider_messages(stored)

    _assert_valid_tool_pairing(rebuilt)


def test_rebuild_leaves_a_plain_text_conversation_unchanged() -> None:
    """With no tool rows there is nothing to reattach."""
    stored = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": "hello"},
    ]

    assert rebuild_provider_messages(stored) == stored


def test_rebuild_output_survives_compaction_without_orphaning() -> None:
    """Rebuild then compact -- the pairing must hold on the wire too.

    The two run in sequence in the orchestrator, so a valid rebuild that a
    later compaction cut into an orphan would still 400. A long thread forces
    compaction to actually drop turns.
    """
    stored: list[JsonObject] = []
    for turn in range(60):
        stored.append({"role": "user", "content": f"attempt {turn}: " + "x" * 400})
        stored.append({"role": "assistant", "content": "z" * 300})
        stored.append(
            {"role": "tool", "content": "y" * 400, "tool_call_id": f"call{turn}"}
        )

    rebuilt = rebuild_provider_messages(stored)
    _assert_valid_tool_pairing(rebuilt)

    with_system = [{"role": "system", "content": "system prompt"}, *rebuilt]
    compacted = compact_messages(with_system, threshold_percent=70, max_chars=20_000)

    assert len(compacted) < len(with_system), "this input must actually compact"
    _assert_valid_tool_pairing(compacted)


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
