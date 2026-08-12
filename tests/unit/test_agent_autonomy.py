from __future__ import annotations

from dataclasses import replace

import pytest

from headless_re_mcp.agent.autonomy import AutonomyPolicy
from headless_re_mcp.config import Settings
from headless_re_mcp.tools.catalog import (
    CommandSpec,
    CommandTransport,
    ToolEffect,
)


def _spec(name: str, *effects: ToolEffect) -> CommandSpec:
    return CommandSpec(
        name,
        name.replace(".", "_"),
        frozenset({CommandTransport.AGENT}),
        frozenset(effects),
    )


READ = _spec("static.functions", ToolEffect.READ_ONLY)
STATE = _spec("dynamic.launch", ToolEffect.STATE_CHANGE)
WRITE = _spec("report.generate", ToolEffect.FILE_WRITE)
BOTH = _spec("unpack.start", ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE)


def test_the_default_policy_grants_exactly_what_fail_closed_granted() -> None:
    """An empty policy must not widen anything.

    The safe default is structural here: with nothing configured the allowlist
    matches the old hardcoded rule, so an operator cannot open writes by
    forgetting to deny them.
    """
    policy = AutonomyPolicy()

    assert policy.unattended is False
    assert policy.decide(READ).approved is True
    assert policy.decide(READ).reason == "read_only"
    for spec in (STATE, WRITE, BOTH):
        decision = policy.decide(spec)
        assert decision.approved is False
        assert decision.reason == "requires_human"


def test_effects_can_be_opened_up_one_class_at_a_time() -> None:
    policy = AutonomyPolicy(auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE}))

    assert policy.unattended is True
    assert policy.decide(STATE).approved is True
    assert policy.decide(STATE).reason == "allowlisted_effects:state_change"
    # A tool that also writes files is not covered by a state_change grant.
    assert policy.decide(WRITE).approved is False
    assert policy.decide(BOTH).approved is False


def test_a_named_tool_can_be_granted_without_its_whole_effect_class() -> None:
    policy = AutonomyPolicy(auto_approve_tools=frozenset({"unpack.start"}))

    assert policy.decide(BOTH).approved is True
    assert policy.decide(BOTH).reason == "allowlisted_tool"
    # Nothing else in those effect classes came along with it.
    assert policy.decide(STATE).approved is False
    assert policy.decide(WRITE).approved is False


def test_a_denial_outranks_every_grant_including_read_only() -> None:
    """Naming a tool as never-auto has to be an unconditional guarantee."""
    policy = AutonomyPolicy(
        auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE}),
        auto_approve_tools=frozenset({"unpack.start", "static.functions"}),
        never_auto_approve=frozenset({"unpack.start", "static.functions"}),
    )

    for spec in (BOTH, READ):
        decision = policy.decide(spec)
        assert decision.approved is False
        assert decision.reason == "never_auto_approve"


def test_policy_is_read_from_settings(tmp_path) -> None:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path,
        agent_auto_approve_effects=("state_change",),
        agent_auto_approve_tools=("report.generate",),
        agent_never_auto_approve=("patches.apply",),
    )

    policy = AutonomyPolicy.from_settings(settings)

    assert policy.auto_approve_effects == frozenset({ToolEffect.STATE_CHANGE})
    assert policy.auto_approve_tools == frozenset({"report.generate"})
    assert policy.never_auto_approve == frozenset({"patches.apply"})
    assert policy.decide(STATE).approved is True
    assert policy.decide(WRITE).approved is True
    assert policy.decide(_spec("patches.apply", ToolEffect.STATE_CHANGE)).approved is False


def test_an_unknown_effect_name_is_rejected_rather_than_ignored(tmp_path) -> None:
    """A typo must not silently grant nothing while looking configured."""
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path,
        agent_auto_approve_effects=("state_chagne",),
    )

    with pytest.raises(ValueError, match="unknown tool effect"):
        AutonomyPolicy.from_settings(settings)


def test_settings_parse_effects_from_a_comma_separated_env_var(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HEADLESS_RE_AGENT_AUTO_APPROVE_EFFECTS", "state_change, file_write")
    monkeypatch.setenv("HEADLESS_RE_AGENT_AUTO_APPROVE_TOOLS", "unpack.start,unpack.start")
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path))

    settings = Settings.load(tmp_path / "missing-config.json")

    assert settings.agent_auto_approve_effects == ("state_change", "file_write")
    # A repeated entry is one rule, not two.
    assert settings.agent_auto_approve_tools == ("unpack.start",)
    policy = AutonomyPolicy.from_settings(settings)
    assert policy.decide(BOTH).approved is True


def test_the_real_catalog_stays_fail_closed_by_default() -> None:
    """Against the shipped tool set, an empty policy auto-runs no writes at all."""
    from headless_re_mcp.tools.catalog import COMMAND_CATALOG

    policy = AutonomyPolicy()
    agent_specs = list(COMMAND_CATALOG.for_transport(CommandTransport.AGENT))
    assert agent_specs, "catalog should expose tools to the agent transport"

    writes = [spec for spec in agent_specs if spec.write]
    assert writes, "catalog should contain write tools"
    assert [spec.name for spec in writes if policy.decide(spec).approved] == []
    # And the read-only ones still run unattended, as they always did.
    reads = [spec for spec in agent_specs if not spec.write]
    assert all(policy.decide(spec).approved for spec in reads)


def test_opening_state_change_covers_the_expected_shipped_tools() -> None:
    from headless_re_mcp.tools.catalog import COMMAND_CATALOG

    policy = AutonomyPolicy(auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE}))
    granted = {
        spec.name
        for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
        if spec.write and policy.decide(spec).approved
    }

    assert "dynamic.launch" in granted
    # File writers are a separate class and must not ride along.
    file_writers = {
        spec.name
        for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
        if ToolEffect.FILE_WRITE in spec.effects
    }
    assert not (granted & file_writers)


def test_replace_keeps_the_spec_contract_intact() -> None:
    """decide() reads only name and effects, so a bound spec behaves the same."""
    bound = replace(STATE, description="bound", input_schema={"type": "object"})
    policy = AutonomyPolicy(auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE}))
    assert policy.decide(bound).approved is True