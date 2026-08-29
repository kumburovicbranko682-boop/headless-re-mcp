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


def test_capture_read_tools_stay_read_only_even_though_they_register_a_spill() -> None:
    """A read that spills an oversized result to a registered artifact is READ_ONLY.

    ``proxy.flow.get`` and ``web.network.get`` read a flow that was *already*
    captured (during ``proxy.start`` / ``web.navigate``) and, when a body is too
    large to inline or is not valid UTF-8, spill it to a ``.bin`` file that the
    service registers as a retention-tracked artifact (``proxy_flow_request_body``,
    ``web_response_body``, ...). Registering an artifact is easy to mistake for a
    write -- the Ghidra exports genuinely were one -- but here the artifact is only
    the overflow form of a read, exactly like ``static.decompile`` writing an
    oversized decompilation to ``static/<sid>/oversized`` and still being a query.
    The distinction matters: READ_ONLY tools are what the agent auto-executes and
    what a read-only deployment still allows, so misclassifying these as FILE_WRITE
    would make every captured-flow inspection demand a confirmation and vanish when
    writes are disabled. Anchored against a static spiller so the convention they
    follow is pinned alongside them.
    """
    for name in ("proxy.flow.get", "web.network.get", "static.decompile"):
        spec = COMMAND_CATALOG.require(name)
        assert spec.effects == frozenset({ToolEffect.READ_ONLY}), name
        assert spec.write is False, name
        assert spec.confirm_required is False, name
        assert spec.agent_auto_execute is True, name

    # The counter-case that fixes the boundary: turning captures into a *new*
    # exported file (a HAR, an unpacked bundle) is the tool's purpose, not an
    # overflow of a read, so those are FILE_WRITE and confirmation-gated.
    for name in ("proxy.export_har", "web.har.export", "js.unpack_bundle"):
        spec = COMMAND_CATALOG.require(name)
        assert spec.effects == frozenset({ToolEffect.STATE_CHANGE, ToolEffect.FILE_WRITE}), name
        assert spec.write is True, name
        assert spec.confirm_required is True, name
        assert spec.agent_auto_execute is False, name
