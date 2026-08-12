from __future__ import annotations

from mcp.server.fastmcp import FastMCP

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


def create_server(service: AnalysisService | None = None) -> FastMCP[None]:
    analysis = service or AnalysisService()
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
    install_cursor_underscore_aliases(server)
    return server


def run_stdio(service: AnalysisService | None = None) -> None:
    install_global_exception_hooks("mcp-stdio")
    analysis = service or AnalysisService()
    try:
        create_server(analysis).run(transport="stdio")
    finally:
        analysis.close_all()
