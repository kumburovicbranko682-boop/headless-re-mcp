from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.routes.apk import register_apk_tools
from headless_re_mcp.mcp.routes.device import register_device_tools
from headless_re_mcp.mcp.routes.dex import register_dex_tools
from headless_re_mcp.mcp.routes.dynamic import register_dynamic_tools
from headless_re_mcp.mcp.routes.dynamic_analysis import register_dynamic_analysis_tools
from headless_re_mcp.mcp.routes.elf import register_elf_tools
from headless_re_mcp.mcp.routes.frida import register_frida_tools
from headless_re_mcp.mcp.routes.ghidra import register_ghidra_tools
from headless_re_mcp.mcp.routes.js_wasm import register_js_wasm_tools
from headless_re_mcp.mcp.routes.meta import register_meta_tools
from headless_re_mcp.mcp.routes.proxy import register_proxy_tools
from headless_re_mcp.mcp.routes.r2 import register_r2_tools
from headless_re_mcp.mcp.routes.trace import register_trace_tools
from headless_re_mcp.mcp.routes.ui import register_ui_tools
from headless_re_mcp.mcp.routes.unpack import register_unpack_tools
from headless_re_mcp.mcp.routes.web import register_web_tools
from headless_re_mcp.mcp.routes.windbg import register_windbg_tools
from headless_re_mcp.mcp.routes.workspace import register_workspace_tools


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
    register_apk_tools(server, analysis)
    register_dex_tools(server, analysis)
    register_elf_tools(server, analysis)
    register_device_tools(server, analysis)
    register_js_wasm_tools(server, analysis)
    register_web_tools(server, analysis)
    register_proxy_tools(server, analysis)
    register_workspace_tools(server, analysis)


__all__ = ["register_remaining_tools"]
