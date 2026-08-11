"""MCP transport adapter helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from functools import wraps
from typing import Any

import anyio.to_thread
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools import Tool

from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandCatalog, CommandTransport
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.telemetry import instrument
from headless_re_mcp.tools.binding import BoundTool

JsonObject = dict[str, Any]


def enforce_write_policy(
    handler: Callable[..., dict[str, Any]],
    *,
    name: str,
    catalog: CommandCatalog,
) -> Callable[..., dict[str, Any]]:
    """Refuse state-changing tools while the deployment is read-only.

    Every tool already declares its effects, but nothing consulted them, so
    `local_full_access` looked like an access control and enforced nothing. The
    refusal is an ordinary error envelope: a caller that cannot write should
    learn why, not see the tool disappear.
    """

    @wraps(handler)
    def guarded(*args: Any, **kwargs: Any) -> dict[str, Any]:
        if not catalog.write_allowed:
            refusal: Result[JsonObject] = Result(
                ok=False,
                error=RpcError(
                    code="write_disabled",
                    message=f"{name} changes state and this deployment is read-only",
                    details={"tool": name, "setting": "local_full_access"},
                ),
            )
            dumped = refusal.model_dump(mode="json")
            assert isinstance(dumped, dict)
            return dumped
        return handler(*args, **kwargs)

    return guarded


def offload(handler: Callable[..., dict[str, Any]]) -> Callable[..., Any]:
    """Run a blocking handler off the event loop.

    FastMCP calls a synchronous tool directly inside the event loop, and these
    handlers block for as long as the debugger takes: a single launch or
    decompile would otherwise stall every other request on the connection,
    including the ones asking what went wrong. ``functools.wraps`` keeps the
    typed signature so schema generation is unaffected.
    """

    @wraps(handler)
    async def offloaded(*args: Any, **kwargs: Any) -> dict[str, Any]:
        def call() -> dict[str, Any]:
            return handler(*args, **kwargs)

        return await anyio.to_thread.run_sync(call)

    return offloaded


def register_tool(
    server: FastMCP[None],
    handler: Callable[..., dict[str, Any]],
    *,
    name: str,
    catalog: CommandCatalog = COMMAND_CATALOG,
) -> None:
    """Register one typed handler and retain its generated schema in the catalog."""
    spec = catalog.require(name)
    description = handler.__doc__ or spec.description or name
    # One wrapper serves both transports: the server calls it directly and the
    # catalog binding is what the agent transport invokes.
    guarded = enforce_write_policy(handler, name=name, catalog=catalog) if spec.write else handler
    observed = instrument(guarded, name=name)
    # The server gets the offloaded form so the event loop stays free, while the
    # catalog keeps the direct one: the agent transport calls it synchronously.
    server.add_tool(
        offload(observed),
        name=name,
        description=description,
        structured_output=True,
    )
    tool = Tool.from_function(
        observed,
        name=name,
        description=description,
        structured_output=True,
    )
    catalog.bind_mcp(
        name,
        observed,
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
