from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.adapter import register_bound_tools
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def register_js_wasm_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_js_wasm_tools(analysis))
