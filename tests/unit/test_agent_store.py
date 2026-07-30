from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.agent.models import RunStatus
from headless_re_mcp.agent.store import AgentStore, canonical_args_sha256


def test_agent_store_seq_approval_and_restart(tmp_path: Path) -> None:
    path = tmp_path / "agent.db"
    store = AgentStore(path)
    thread = store.create_thread(session_id="analysis-session")
    run = store.create_run(thread.id, provider_profile="default", model="fake", deadline_seconds=30)
    store.transition(run.id, RunStatus.STREAMING)
    first = store.append_event(run.id, "message.delta", {"delta": "a"})
    second = store.append_event(run.id, "message.delta", {"delta": "b"})
    assert second.seq == first.seq + 1

    arguments = {"session_id": "s", "value": 7}
    proposed = store.propose_tool_call(run.id, "call-1", "dynamic.resume", arguments, ["state_change"])
    assert proposed["args_sha256"] == canonical_args_sha256(arguments)
    with pytest.raises(ValueError, match="hash mismatch"):
        store.decide_tool_call(run.id, "call-1", "0" * 64, approved=True)
    store.decide_tool_call(run.id, "call-1", proposed["args_sha256"], approved=True)
    assert store.consume_approval(run.id, "call-1", proposed["args_sha256"])
    assert not store.consume_approval(run.id, "call-1", proposed["args_sha256"])

    reopened = AgentStore(path)
    interrupted = reopened.get_run(run.id)
    assert interrupted is not None and interrupted.status is RunStatus.INTERRUPTED
    events = reopened.list_events(run.id)
    assert [event.seq for event in events] == sorted({event.seq for event in events})


def test_tool_call_identity_is_run_scoped_and_arguments_are_redacted(tmp_path: Path) -> None:
    store = AgentStore(tmp_path / "agent.db")
    first_thread = store.create_thread()
    second_thread = store.create_thread()
    first = store.create_run(
        first_thread.id,
        provider_profile="default",
        model="fake",
        deadline_seconds=30,
    )
    second = store.create_run(
        second_thread.id,
        provider_profile="default",
        model="fake",
        deadline_seconds=30,
    )
    for run in (first, second):
        store.transition(run.id, RunStatus.STREAMING)
        store.transition(run.id, RunStatus.AWAITING_APPROVAL)

    first_args = {"nested": {"api_key": "first-secret"}, "value": 1}
    second_args = {"nested": {"api_key": "second-secret"}, "value": 2}
    first_call = store.propose_tool_call(
        first.id,
        "provider-reused-id",
        "dynamic.resume",
        first_args,
        ["state_change"],
    )
    second_call = store.propose_tool_call(
        second.id,
        "provider-reused-id",
        "dynamic.resume",
        second_args,
        ["state_change"],
    )

    store.decide_tool_call(
        first.id,
        "provider-reused-id",
        str(first_call["args_sha256"]),
        approved=True,
    )
    assert store.get_tool_call(first.id, "provider-reused-id")["approved"] is True
    assert store.get_tool_call(second.id, "provider-reused-id")["approved"] is None
    assert store.get_tool_call(first.id, "provider-reused-id")["arguments"] == {
        "nested": {"api_key": "***REDACTED***"},
        "value": 1,
    }
    assert store.get_tool_call(second.id, "provider-reused-id")["arguments"] == {
        "nested": {"api_key": "***REDACTED***"},
        "value": 2,
    }
    assert store.consume_approval(
        first.id,
        "provider-reused-id",
        str(first_call["args_sha256"]),
    )
    assert not store.consume_approval(
        second.id,
        "provider-reused-id",
        str(second_call["args_sha256"]),
    )
