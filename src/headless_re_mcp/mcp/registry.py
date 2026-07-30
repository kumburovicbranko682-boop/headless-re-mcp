"""MCP adapters for protocol-independent core tool domains."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.adapter import register_bound_tools
from headless_re_mcp.tools.core import (
    build_core_session_tools,
    build_detect_tools,
    build_dotnet_tools,
    build_static_core_tools,
    build_static_extended_tools,
    build_workflow_tools,
)


def register_core_session_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_core_session_tools(analysis))

def register_static_core_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_static_core_tools(analysis))

def register_detect_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_detect_tools(analysis))

def register_static_extended_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_static_extended_tools(analysis))

def register_workflow_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_workflow_tools(analysis))

def register_dotnet_tools(server: FastMCP[None], analysis: AnalysisService) -> None:
    register_bound_tools(server, build_dotnet_tools(analysis))
