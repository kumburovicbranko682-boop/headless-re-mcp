from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.server import create_server
from headless_re_mcp.tools.assembly import bind_all_tools
from headless_re_mcp.tools.catalog import (
    COMMAND_CATALOG,
    CommandCatalog,
    CommandTransport,
    ToolEffect,
)


def test_all_mcp_tools_share_explicit_agent_catalog() -> None:
    analysis = AnalysisService()
    # This test asserts the full surface, independent of any machine-local
    # workspace profile that would otherwise trim it.
    object.__setattr__(analysis.settings, "workspace_profile", "full")
    server = create_server(analysis)
    mcp_names = set(server._tool_manager._tools)
    catalog_names = {item.name for item in COMMAND_CATALOG.for_transport(CommandTransport.MCP)}
    agent_names = {item.name for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)}
    assert len(mcp_names) == 265
    assert mcp_names == catalog_names == agent_names
    assert COMMAND_CATALOG.uncategorized_names() == ()
    assert all(item.effects for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT))
    assert all(
        item.agent_auto_execute == (item.effects == frozenset({ToolEffect.READ_ONLY}))
        for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
    )
    assert all(item.input_schema is not None for item in COMMAND_CATALOG.for_transport(CommandTransport.MCP))
    assert COMMAND_CATALOG.require("static.open").resource_policy.timeout_seconds == 1800.0
    assert COMMAND_CATALOG.require("session.list").resource_policy.timeout_seconds == 60.0


def test_protocol_independent_tool_domains_bind_complete_fresh_catalog() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
    finally:
        analysis.close_all()

    specs = catalog.for_transport(CommandTransport.MCP)
    assert len(bindings) == len(specs) == 265
    assert {binding.name for binding in bindings} == {spec.name for spec in specs}
    assert all(spec.handler is not None for spec in specs)
    assert all(spec.input_schema is not None for spec in specs)
    assert all(spec.description for spec in specs)
    for binding in bindings:
        service_methods = [
            name
            for name in binding.handler.__code__.co_names
            if hasattr(AnalysisService, name)
        ]
        assert service_methods == [catalog.require(binding.name).service_method]

    tools_root = Path(__file__).parents[2] / "src" / "headless_re_mcp" / "tools"
    transport_imports = [
        path
        for path in tools_root.glob("*.py")
        if "headless_re_mcp.mcp" in path.read_text(encoding="utf-8")
        or "mcp.server" in path.read_text(encoding="utf-8")
        or "fastapi" in path.read_text(encoding="utf-8")
    ]
    assert transport_imports == []


def test_mutating_catalog_tools_are_writes_not_auto_execute() -> None:
    """Breakpoint put/disable and page-rights changes must not auto-run."""
    for name in (
        "workflow.breakpoint.put",
        "workflow.breakpoint.disable",
        "memory.protection",
        "frida.hook.template",
    ):
        spec = COMMAND_CATALOG.require(name)
        assert spec.write is True
        assert spec.agent_auto_execute is False
        assert spec.effects == frozenset({ToolEffect.STATE_CHANGE})


def test_query_catalog_tools_are_read_only() -> None:
    """Text search and patch listing are queries, not writes."""
    for name in ("static.search.text", "patches.list", "dynamic.stealth.status"):
        spec = COMMAND_CATALOG.require(name)
        assert spec.write is False
        assert spec.agent_auto_execute is True
        assert spec.effects == frozenset({ToolEffect.READ_ONLY})


def test_stealth_set_is_a_file_write() -> None:
    spec = COMMAND_CATALOG.require("dynamic.stealth.set")
    assert spec.write is True
    assert spec.agent_auto_execute is False
    assert spec.effects == frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE})


def test_agent_effect_shapes_are_a_closed_three_way_taxonomy() -> None:
    """Every agent tool is exactly one of three effect shapes; the set is closed.

    The autonomy model reads a tool's effects three ways, each guarded by its own
    pin: ``{read_only}`` is decide()'s unconditional baseline, auto-approved even
    under a fully fail-closed policy (see AutonomyPolicy.decide, ``== {READ_ONLY}``);
    ``{state_change}`` is the class the packed preset grants wholesale (pinned in
    test_agent_autonomy); ``{file_write, state_change}`` is gated by the file-write
    denylist under that preset (pinned there too). Those pins each police one shape.
    Nothing asserts the taxonomy is *closed*, so a fourth shape -- an empty set
    (silently denied forever), a bare ``{file_write}`` with no state_change, a tool
    that mixes read_only with a mutation, or a novel triple -- would slip between
    the three shape-specific pins and reach the policy unreviewed. Pin the closure:
    a new shape lands here for a human before it reaches decide().
    """
    canonical = {
        frozenset({ToolEffect.READ_ONLY}),
        frozenset({ToolEffect.STATE_CHANGE}),
        frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE}),
    }
    agent_specs = list(COMMAND_CATALOG.for_transport(CommandTransport.AGENT))

    off_taxonomy = {
        spec.name: sorted(effect.value for effect in spec.effects)
        for spec in agent_specs
        if spec.effects not in canonical
    }
    assert off_taxonomy == {}, f"agent tools off the closed effect taxonomy: {off_taxonomy}"

    # Non-vacuous: all three shapes are actually present, so an emptied or
    # collapsed catalog cannot let the closure assertion pass by having nothing
    # to check.
    observed = {spec.effects for spec in agent_specs}
    assert observed == canonical

    # File writes never travel alone: each carries state_change, so a preset that
    # opens only the state_change class (the packed default) still cannot sweep a
    # file write in on a bare {file_write} shape.
    assert all(
        ToolEffect.STATE_CHANGE in spec.effects
        for spec in agent_specs
        if ToolEffect.FILE_WRITE in spec.effects
    )
