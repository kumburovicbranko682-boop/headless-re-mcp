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


def test_apk_open_is_a_state_change_like_every_other_backend_open() -> None:
    """apk.open records a backend + timeline, so it must be a guarded write.

    apk.open calls _record_backend / _timeline_append (persisting to the session
    store) and guards CLOSING/CLOSED/FAILED with InvalidStateTransition -- the
    same session mutation r2.open / dynamic.open / web.open do, all filed as
    state_change. Filed read-only it skipped guard_write, so it ran and mutated
    the store even in a read-only deployment and auto-executed under the
    request-approval autonomy mode. Its read-only siblings that only parse the
    APK (apk.classes, apk.manifest, ...) stay read-only.
    """
    apk_open = COMMAND_CATALOG.require("apk.open")
    assert apk_open.effects == frozenset({ToolEffect.STATE_CHANGE})
    assert apk_open.write is True
    assert apk_open.agent_auto_execute is False
    # r2.open is the direct analogue: another backend open on an existing
    # session that records a backend. Their effects must match.
    assert apk_open.effects == COMMAND_CATALOG.require("r2.open").effects
    # The pure-reader APK tools are unaffected and remain read-only.
    for reader in ("apk.classes", "apk.manifest", "apk.strings", "apk.xrefs"):
        spec = COMMAND_CATALOG.require(reader)
        assert spec.effects == frozenset({ToolEffect.READ_ONLY})
        assert spec.write is False
