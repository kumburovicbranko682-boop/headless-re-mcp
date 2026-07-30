"""MCP adapter for the ghidra_tools tool domain."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.adapter import register_bound_tools
from headless_re_mcp.tools.ghidra import build_ghidra_tools


def register_ghidra_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_ghidra_tools(analysis))
