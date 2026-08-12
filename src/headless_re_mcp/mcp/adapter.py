"""MCP transport adapter helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools import Tool

from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandCatalog, CommandTransport
from headless_re_mcp.error_boundary import guard_tool_handler
from headless_re_mcp.tools.binding import BoundTool


def register_tool(
    server: FastMCP[None],
    handler: Callable[..., dict[str, Any]],
    *,
    name: str,
    catalog: CommandCatalog = COMMAND_CATALOG,
) -> None:
    """Register one typed handler and retain its generated schema in the catalog."""
    spec = catalog.require(name)
    safe_handler = guard_tool_handler(handler, tool_name=name)
    description = handler.__doc__ or spec.description or name
    server.add_tool(
        safe_handler,
        name=name,
        description=description,
        structured_output=True,
    )
    tool = Tool.from_function(
        safe_handler,
        name=name,
        description=description,
        structured_output=True,
    )
    catalog.bind_mcp(
        name,
        safe_handler,
        input_schema=dict(tool.parameters),
        description=tool.description,
    )


def register_bound_tools(
    server: FastMCP[None],
    tools: Iterable[BoundTool],
    *,
    catalog: CommandCatalog = COMMAND_CATALOG,
) -> None:
    """Register typed handlers while checking shared catalog metadata when present."""
    for tool in tools:
        spec = catalog.get(tool.name)
        if spec is not None and CommandTransport.MCP not in spec.transports:
            raise ValueError(f"command is not exposed over MCP: {tool.name}")
        register_tool(server, tool.handler, name=tool.name, catalog=catalog)


def install_cursor_underscore_aliases(server: FastMCP[None]) -> None:
    """Resolve Cursor's underscore calls without duplicating ListTools entries."""
    manager = server._tool_manager
    dotted_by_underscore = {
        name.replace(".", "_"): name for name in list(manager._tools) if "." in name
    }
    if not dotted_by_underscore:
        return
    original_get = manager.get_tool

    def get_tool(name: str) -> Any:
        tool = original_get(name)
        if tool is None:
            dotted = dotted_by_underscore.get(name)
            if dotted is not None:
                tool = original_get(dotted)
        return tool

    manager.get_tool = get_tool  # type: ignore[method-assign]
