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
    assert len(mcp_names) == 263
    assert mcp_names == catalog_names == agent_names
    assert COMMAND_CATALOG.uncategorized_names() == ()
    assert all(item.effects for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT))
    assert all(
        item.agent_auto_execute == (item.effects == frozenset({ToolEffect.READ_ONLY}))
        for item in COMMAND_CATALOG.for_transport(CommandTransport.AGENT)
    )
    assert all(item.input_schema is not None for item in COMMAND_CATALOG.for_transport(CommandTransport.MCP))


def test_protocol_independent_tool_domains_bind_complete_fresh_catalog() -> None:
    analysis = AnalysisService()
    catalog = CommandCatalog()
    try:
        bindings = bind_all_tools(analysis, catalog)
    finally:
        analysis.close_all()

    specs = catalog.for_transport(CommandTransport.MCP)
    assert len(bindings) == len(specs) == 263
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
