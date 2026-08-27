from __future__ import annotations

from dataclasses import replace

import pytest

from headless_re_mcp.agent.autonomy import ApprovalMode, AutonomyPolicy, parse_approval_mode
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


def test_grant_and_revoke_are_additive() -> None:
    policy = AutonomyPolicy().grant(tools=("dynamic.open",), effects=("state_change",))
    assert policy.decide(STATE).approved is True
    assert policy.decide(_spec("dynamic.open", ToolEffect.STATE_CHANGE)).approved is True
    revoked = policy.revoke_tools(("dynamic.open",))
    assert revoked.decide(_spec("dynamic.open", ToolEffect.STATE_CHANGE)).approved is True
    assert "dynamic.open" not in revoked.auto_approve_tools


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


def test_settings_load_without_autonomy_keys_uses_packed_analysis_preset(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("HEADLESS_RE_AGENT_AUTO_APPROVE_EFFECTS", raising=False)
    monkeypatch.delenv("HEADLESS_RE_AGENT_AUTO_APPROVE_TOOLS", raising=False)
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path))
    settings = Settings.load(tmp_path / "missing-config.json")
    policy = AutonomyPolicy.from_settings(settings)

    assert "state_change" in settings.agent_auto_approve_effects
    assert "dynamic.stealth.set" in settings.agent_auto_approve_tools
    assert policy.decide(STATE).approved is True
    assert policy.decide(
        _spec("dynamic.stealth.set", ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE)
    ).approved is True
    assert policy.decide(BOTH).approved is True
    assert policy.decide(
        _spec("patches.apply", ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE)
    ).approved is False


def test_explicit_empty_autonomy_keys_stay_fail_closed(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("HEADLESS_RE_AGENT_AUTO_APPROVE_EFFECTS", raising=False)
    monkeypatch.delenv("HEADLESS_RE_AGENT_AUTO_APPROVE_TOOLS", raising=False)
    monkeypatch.setenv("HEADLESS_RE_ARTIFACT_ROOT", str(tmp_path))
    config = tmp_path / "config.json"
    config.write_text(
        '{"agent_auto_approve_effects": [], "agent_auto_approve_tools": []}',
        encoding="utf-8",
    )
    settings = Settings.load(config)
    policy = AutonomyPolicy.from_settings(settings)
    assert settings.agent_auto_approve_effects == ()
    assert settings.agent_auto_approve_tools == ()
    assert policy.decide(STATE).approved is False
    assert policy.decide(BOTH).approved is False


def test_approval_mode_collapses_the_allowlist_to_two_switches() -> None:
    empty = AutonomyPolicy()
    assert empty.mode is ApprovalMode.REQUEST
    assert empty.describe()["mode"] == "request"
    assert parse_approval_mode("ask") is ApprovalMode.REQUEST
    assert parse_approval_mode("full") is ApprovalMode.FULL_ACCESS

    partial = AutonomyPolicy(auto_approve_effects=frozenset({ToolEffect.STATE_CHANGE}))
    assert partial.mode is ApprovalMode.REQUEST

    opened = empty.with_mode("full_access")
    assert opened.mode is ApprovalMode.FULL_ACCESS
    assert opened.decide(STATE).approved is True
    assert opened.decide(WRITE).approved is True
    assert opened.decide(BOTH).approved is True
    assert opened.auto_approve_tools == frozenset()

    asked = opened.with_mode("request")
    assert asked.mode is ApprovalMode.REQUEST
    assert asked.unattended is False
    assert asked.decide(STATE).approved is False
    assert asked.never_auto_approve == opened.never_auto_approve

    with pytest.raises(ValueError, match="unknown approval mode"):
        empty.with_mode("approve_for_me")


def test_full_access_still_honors_never_auto_approve() -> None:
    policy = AutonomyPolicy(never_auto_approve=frozenset({"unpack.start"})).with_mode(
        ApprovalMode.FULL_ACCESS
    )
    assert policy.decide(STATE).approved is True
    assert policy.decide(BOTH).approved is False
    assert policy.decide(BOTH).reason == "never_auto_approve"


def test_the_packed_analysis_denylist_stays_pinned_to_the_real_catalog() -> None:
    """The packed-analysis preset auto-approves file writes except a denylist.

    That denylist is string literals; nothing otherwise ties them to real tools.
    A rename turns an entry into a dead string and quietly lets a sensitive file
    write (a patch, an APK re-sign, an artifact GC) auto-run unattended, and any
    new file-write tool rides the preset by default unless it is added here. So
    the denylist and the computed preset are pinned against the shipped catalog.
    """
    from headless_re_mcp.agent.autonomy import (
        _EXCLUDED_AUTO_FILE_WRITES,
        PACKED_ANALYSIS_AUTO_APPROVE_TOOLS,
    )
    from headless_re_mcp.tools.catalog import COMMAND_CATALOG

    agent_specs = {
        spec.name: spec for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
    }

    # Every denylisted name is a real file-write tool, or the exclusion is dead.
    for name in _EXCLUDED_AUTO_FILE_WRITES:
        spec = agent_specs.get(name)
        assert spec is not None, f"denylisted tool no longer exists: {name}"
        assert ToolEffect.FILE_WRITE in spec.effects, (
            f"{name} is denylisted as a file write but is no longer one"
        )

    # The computed preset never includes a denylisted tool.
    assert not (set(PACKED_ANALYSIS_AUTO_APPROVE_TOOLS) & _EXCLUDED_AUTO_FILE_WRITES)

    # The preset is exactly the agent file-write tools minus the denylist, so a
    # newly added file writer is caught here rather than silently auto-approved.
    file_writes = {
        name for name, spec in agent_specs.items() if ToolEffect.FILE_WRITE in spec.effects
    }
    assert set(PACKED_ANALYSIS_AUTO_APPROVE_TOOLS) == file_writes - _EXCLUDED_AUTO_FILE_WRITES


def test_the_packed_analysis_preset_keeps_sensitive_writes_behind_approval() -> None:
    """Applied to the real specs: no denylisted write auto-runs, stealth does."""
    from headless_re_mcp.agent.autonomy import (
        PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS,
        PACKED_ANALYSIS_AUTO_APPROVE_TOOLS,
    )
    from headless_re_mcp.tools.catalog import COMMAND_CATALOG

    # Built exactly as Settings.load() wires the preset with no operator keys.
    policy = AutonomyPolicy(
        auto_approve_effects=frozenset(
            ToolEffect(value) for value in PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS
        ),
        auto_approve_tools=frozenset(PACKED_ANALYSIS_AUTO_APPROVE_TOOLS),
    )
    agent_specs = {
        spec.name: spec for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
    }

    for name in (
        "patches.apply",
        "patches.restore",
        "static.bytes.patch",
        "apk.sign",
        "apk.repack",
        "artifacts.gc",
        "web.screenshot",
    ):
        assert policy.decide(agent_specs[name]).approved is False, (
            f"{name} must stay behind human approval under the packed preset"
        )

    # A representative packed-analysis write still runs unattended.
    assert policy.decide(agent_specs["dynamic.stealth.set"]).approved is True


def test_non_pe_state_change_tools_riding_the_packed_preset_are_pinned() -> None:
    """Pin the non-PE state changes that auto-run under the packed-PE preset.

    The preset grants the state_change class by effect, so every non-PE mutation
    -- the Android device.* line, the frida.* device path, proxy start/stop and
    replay, the web.* browser drive and the global workspace.mode.set -- rides
    the unattended default even though none of it is packed-PE analysis. An
    effect grant, unlike the file-write denylist above, records nothing about
    which tools it sweeps in, so a newly added non-PE state-change tool would
    silently join this set with no review. Pinning it against the shipped
    catalog turns that into a failing test that forces a conscious decision:
    either the new tool genuinely belongs in the unattended preset and is added
    here, or it does not and should be excluded before it ships. The file-write
    carve-outs on these same lines (device.pull/screenshot, proxy.export_har,
    web.har.export/screenshot) must stay gated and so must not appear.
    """
    from headless_re_mcp.agent.autonomy import (
        PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS,
        PACKED_ANALYSIS_AUTO_APPROVE_TOOLS,
    )
    from headless_re_mcp.tools.catalog import COMMAND_CATALOG

    policy = AutonomyPolicy(
        auto_approve_effects=frozenset(
            ToolEffect(value) for value in PACKED_ANALYSIS_AUTO_APPROVE_EFFECTS
        ),
        auto_approve_tools=frozenset(PACKED_ANALYSIS_AUTO_APPROVE_TOOLS),
    )
    non_pe_prefixes = ("device.", "frida.", "proxy.", "web.", "workspace.")
    riding = {
        spec.name
        for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
        if spec.write
        and spec.name.startswith(non_pe_prefixes)
        and policy.decide(spec).approved
    }

    assert riding == {
        "device.connect",
        "device.force_stop",
        "device.forward",
        "device.install",
        "device.launch",
        "device.push",
        "device.uninstall",
        "frida.attach",
        "frida.device.connect",
        "frida.hook.template",
        "frida.server.ensure",
        "frida.spawn",
        "proxy.ca.install_android",
        "proxy.replay",
        "proxy.start",
        "proxy.stop",
        "web.click",
        "web.close",
        "web.navigate",
        "web.open",
        "web.type",
        "workspace.mode.set",
    }

    # The file-write carve-outs on these same lines never auto-run under the
    # preset; if one starts to, this and the file-write pin above both fail.
    gated_file_writes = {
        spec.name
        for spec in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
        if spec.name.startswith(non_pe_prefixes)
        and ToolEffect.FILE_WRITE in spec.effects
        and not policy.decide(spec).approved
    }
    assert gated_file_writes == {
        "device.pull",
        "device.screenshot",
        "proxy.export_har",
        "web.har.export",
        "web.screenshot",
    }