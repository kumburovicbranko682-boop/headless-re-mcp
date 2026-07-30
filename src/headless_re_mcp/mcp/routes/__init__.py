from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.routes.dynamic import register_dynamic_tools
from headless_re_mcp.mcp.routes.dynamic_analysis import register_dynamic_analysis_tools
from headless_re_mcp.mcp.routes.frida import register_frida_tools
from headless_re_mcp.mcp.routes.ghidra import register_ghidra_tools
from headless_re_mcp.mcp.routes.meta import register_meta_tools
from headless_re_mcp.mcp.routes.r2 import register_r2_tools
from headless_re_mcp.mcp.routes.trace import register_trace_tools
from headless_re_mcp.mcp.routes.ui import register_ui_tools
from headless_re_mcp.mcp.routes.unpack import register_unpack_tools
from headless_re_mcp.mcp.routes.windbg import register_windbg_tools


def register_remaining_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_dynamic_tools(server, analysis)
    register_dynamic_analysis_tools(server, analysis)
    register_frida_tools(server, analysis)
    register_ghidra_tools(server, analysis)
    register_meta_tools(server, analysis)
    register_r2_tools(server, analysis)
    register_trace_tools(server, analysis)
    register_ui_tools(server, analysis)
    register_unpack_tools(server, analysis)
    register_windbg_tools(server, analysis)


__all__ = ["register_remaining_tools"]
