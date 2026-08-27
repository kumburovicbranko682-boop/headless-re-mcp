"""Coverage for register_bound_tools' non-MCP fail-closed guard.

The happy registration path is covered by the server assembly tests. This pins
the guard that refuses to register a bound tool whose catalog spec does not list
the MCP transport, rather than silently exposing an agent-only command.
"""

from __future__ import annotations

from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from headless_re_mcp.mcp.adapter import register_bound_tools
from headless_re_mcp.tools.binding import BoundTool
from headless_re_mcp.tools.catalog import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ToolEffect,
)


def _handler(**kwargs: Any) -> dict[str, Any]:
    return {"ok": True}


def test_register_bound_tools_refuses_a_command_not_exposed_over_mcp() -> None:
    catalog = CommandCatalog()
    catalog.register(
        CommandSpec(
            name="agentonly.tool",
            service_method="agentonly_tool",
            transports=frozenset({CommandTransport.AGENT}),
            effects=frozenset({ToolEffect.READ_ONLY}),
        )
    )
    bound = BoundTool(name="agentonly.tool", handler=_handler)
    server: FastMCP[None] = FastMCP("test")

    with pytest.raises(ValueError, match="not exposed over MCP"):
        register_bound_tools(server, [bound], catalog=catalog)
