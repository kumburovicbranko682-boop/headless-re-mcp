from __future__ import annotations

import anyio
from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.commands import COMMAND_CATALOG
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.error_boundary import install_global_exception_hooks
from headless_re_mcp.mcp.adapter import install_cursor_underscore_aliases
from headless_re_mcp.mcp.registry import (
    register_core_session_tools,
    register_detect_tools,
    register_dotnet_tools,
    register_static_core_tools,
    register_static_extended_tools,
    register_workflow_tools,
)
from headless_re_mcp.mcp.routes import register_remaining_tools
from headless_re_mcp.telemetry import configure_telemetry_logging


def create_server(service: AnalysisService | None = None) -> FastMCP[None]:
    analysis = service or AnalysisService()
    # The setting existed and was written by setup, but nothing read it, so a
    # deployment asking to be read-only still got the full write surface.
    COMMAND_CATALOG.write_allowed = bool(analysis.settings.local_full_access)
    server: FastMCP[None] = FastMCP(
        "Headless RE-MCP",
        instructions=(
            "Create a session for an authorized local PE, then open its static IDA "
            "backend, dynamic x64dbg backend, or both. Dynamic tools expose only "
            "bounded debugger operations; arbitrary x64dbg commands are unavailable. "
            "Every tool returns an ok/data/error/meta envelope. Close sessions when finished."
        ),
    )
    register_core_session_tools(server, analysis)
    register_static_core_tools(server, analysis)
    register_detect_tools(server, analysis)
    register_static_extended_tools(server, analysis)
    register_workflow_tools(server, analysis)
    register_dotnet_tools(server, analysis)
    register_remaining_tools(server, analysis)
    _apply_workspace_profile(server, analysis)
    install_cursor_underscore_aliases(server)
    return server


def _apply_workspace_profile(server: FastMCP[None], analysis: AnalysisService) -> None:
    """Hide tools outside the configured work direction.

    The full catalog is always registered first so it stays the single
    authority; this only trims what a client sees. ``full`` (the default) hides
    nothing, so the complete surface is unchanged unless a profile is chosen.
    """
    from headless_re_mcp.core.workspace import excluded_prefixes

    profile = str(getattr(analysis.settings, "workspace_profile", "full"))
    prefixes = excluded_prefixes(profile)
    if not prefixes:
        return
    tools = server._tool_manager._tools
    for name in [n for n in tools if n.startswith(prefixes)]:
        del tools[name]


def run_stdio(service: AnalysisService | None = None) -> None:
    install_global_exception_hooks("mcp-stdio")
    configure_telemetry_logging()
    analysis = service or AnalysisService()
    try:
        anyio.run(_run_stdio, create_server(analysis))
    finally:
        analysis.close_all()


async def _run_stdio(server: FastMCP[None]) -> None:
    from headless_re_mcp.mcp.stdio_errors import stdio_server_with_parse_replies

    async with stdio_server_with_parse_replies() as (read_stream, write_stream):
        await server._mcp_server.run(
            read_stream,
            write_stream,
            server._mcp_server.create_initialization_options(),
        )
