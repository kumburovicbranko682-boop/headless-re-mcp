"""Standalone coverage for the orchestrator's pure helpers.

``test_agent_orchestrator.py`` drives the async run loop end to end, which
leaves the small self-contained helpers unverified in isolation. This file
unit-tests them directly: the token estimator, the cumulative output meter, the
system-prompt assembly when a persona already carries the rules, the iterative
depth guard, and the provider-tool listing's skip branches (a spec with no
handler, and a tool hidden by the active work-direction profile).
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.agent.config import ProviderConfigStore, ProviderProfile
from headless_re_mcp.agent.orchestrator import (
    _DESKTOP_RULE,
    _STEALTH_RULE,
    _SYSTEM_PROMPT,
    AgentOrchestrator,
    _arguments_too_deep,
    _LlmOutputMeter,
    estimate_output_tokens,
    thread_system_prompt,
)
from headless_re_mcp.agent.store import AgentStore
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
)

JsonObject = dict[str, Any]


# ---------------------------------------------------------------------------
# estimate_output_tokens


def test_estimate_output_tokens_is_zero_for_empty_text() -> None:
    assert estimate_output_tokens("") == 0


def test_estimate_output_tokens_counts_cjk_as_one_each() -> None:
    assert estimate_output_tokens("日本語") == 3


def test_estimate_output_tokens_discounts_latin_to_a_quarter() -> None:
    assert estimate_output_tokens("a" * 8) == 2


def test_estimate_output_tokens_mixes_latin_and_cjk() -> None:
    # two latin -> round(2/4) = 0 (well, int(0.5+0.5)=1), plus one CJK.
    assert estimate_output_tokens("ab日") == 2


def test_estimate_output_tokens_never_reports_zero_for_nonempty_latin() -> None:
    assert estimate_output_tokens("a") == 1


# ---------------------------------------------------------------------------
# _LlmOutputMeter


class _FakeStore:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, JsonObject]] = []

    def append_event(self, run_id: str, kind: str, data: JsonObject) -> None:
        self.events.append((run_id, kind, data))


def _progress_tokens(store: _FakeStore) -> list[int]:
    return [int(data["tokens"]) for _run, kind, data in store.events if kind == "llm.progress"]


def test_meter_ignores_empty_text() -> None:
    store = _FakeStore()
    meter = _LlmOutputMeter(store, "run")  # type: ignore[arg-type]
    meter.add("")
    assert meter.tokens == 0
    assert store.events == []


def test_meter_counts_latin_and_cjk_and_emits_a_first_progress_event() -> None:
    store = _FakeStore()
    meter = _LlmOutputMeter(store, "run")  # type: ignore[arg-type]
    meter.add("abcd")  # first non-empty add forces a progress flush
    assert meter.tokens >= 1
    assert _progress_tokens(store) == [meter.tokens]

    meter.add("字")  # exercises the non-latin branch of the counter
    assert meter.other == 1


def test_meter_prefers_provider_tokens_when_set() -> None:
    store = _FakeStore()
    meter = _LlmOutputMeter(store, "run")  # type: ignore[arg-type]
    meter.set_provider_tokens(0)  # non-positive is ignored
    assert meter.tokens == 0
    assert store.events == []

    meter.set_provider_tokens(123)
    assert meter.tokens == 123
    assert _progress_tokens(store)[-1] == 123


def test_meter_flush_is_a_noop_when_the_count_has_not_moved() -> None:
    store = _FakeStore()
    meter = _LlmOutputMeter(store, "run")  # type: ignore[arg-type]
    meter.set_provider_tokens(50)
    before = len(store.events)
    meter.flush()  # same token count -> no new event
    assert len(store.events) == before


def test_meter_forced_flush_emits_even_within_the_progress_interval() -> None:
    store = _FakeStore()
    meter = _LlmOutputMeter(store, "run")  # type: ignore[arg-type]
    meter.latin = 40  # tokens now 10 without going through add()
    meter.flush(force=True)
    assert _progress_tokens(store) == [meter.tokens]


# ---------------------------------------------------------------------------
# thread_system_prompt


def test_system_prompt_appends_both_rules_to_a_bare_persona() -> None:
    body = thread_system_prompt(None)
    assert body.count(_DESKTOP_RULE) == 1
    assert body.count(_STEALTH_RULE) == 1


def test_system_prompt_does_not_duplicate_rules_a_persona_already_carries() -> None:
    persona = f"{_SYSTEM_PROMPT}\n{_DESKTOP_RULE}\n{_STEALTH_RULE}"
    body = thread_system_prompt("sess-1", persona)
    assert body.count(_DESKTOP_RULE) == 1, "the desktop rule must not be appended twice"
    assert body.count(_STEALTH_RULE) == 1, "the stealth rule must not be appended twice"
    assert "session_id=sess-1" in body


# ---------------------------------------------------------------------------
# _arguments_too_deep


def test_arguments_too_deep_accepts_a_shallow_value() -> None:
    assert _arguments_too_deep({"a": 1, "b": [1, 2, 3]}) is False


def test_arguments_too_deep_flags_a_deep_dict() -> None:
    assert _arguments_too_deep({"a": {"b": {"c": 1}}}, limit=1) is True


def test_arguments_too_deep_flags_a_deep_list() -> None:
    assert _arguments_too_deep([1, [2, [3]]], limit=1) is True


def test_arguments_too_deep_allows_a_value_at_exactly_the_limit() -> None:
    assert _arguments_too_deep({"a": {"b": 1}}, limit=2) is False


# ---------------------------------------------------------------------------
# _provider_tools skip branches


def _spec(
    name: str,
    *,
    handler: Any | None,
    schema: dict[str, Any] | None,
) -> CommandSpec:
    return CommandSpec(
        name,
        name.replace(".", "_"),
        frozenset({CommandTransport.AGENT}),
        frozenset({ToolEffect.READ_ONLY}),
        handler=handler,
        input_schema=schema,
    )


def _orchestrator(tmp_path: Any, catalog: CommandCatalog, profile: str) -> AgentOrchestrator:
    configs = ProviderConfigStore(tmp_path / "providers.json")
    configs.save(ProviderProfile("default", "https://example.invalid", "m", api_key="k"))
    # _provider_tools never builds a provider, so the default factory (never
    # invoked here) is fine; only the profile and catalog matter.
    return AgentOrchestrator(
        AgentStore(tmp_path / "agent.db"),
        catalog,
        configs,
        tool_profile_provider=lambda: profile,
    )


def test_provider_tools_skips_specs_without_a_handler_or_schema(tmp_path: Any) -> None:
    catalog = CommandCatalog(
        [
            _spec("session.get", handler=lambda: {"ok": True}, schema={"type": "object"}),
            _spec("no.handler", handler=None, schema={"type": "object"}),
            _spec("no.schema", handler=lambda: {"ok": True}, schema=None),
        ]
    )
    tools = _orchestrator(tmp_path, catalog, "full")._provider_tools()
    names = {tool["function"]["name"] for tool in tools}
    assert names == {"session.get"}, "specs missing a handler or a schema are not offered"


def test_provider_tools_hides_tools_excluded_by_the_active_profile(tmp_path: Any) -> None:
    catalog = CommandCatalog(
        [
            _spec("session.get", handler=lambda: {"ok": True}, schema={"type": "object"}),
            _spec("apk.list", handler=lambda: {"ok": True}, schema={"type": "object"}),
        ]
    )
    # The "pe" work direction hides apk.* (and web.*), so only the core tool
    # reaches the provider even though both have handlers and schemas.
    tools = _orchestrator(tmp_path, catalog, "pe")._provider_tools()
    names = {tool["function"]["name"] for tool in tools}
    assert names == {"session.get"}
