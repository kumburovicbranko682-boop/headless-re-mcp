"""MCP transport adapter helpers."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from functools import wraps
from typing import Any

import anyio
import anyio.to_thread
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.tools import Tool

from headless_re_mcp.agent.context import bounded_tool_result
from headless_re_mcp.core.commands import COMMAND_CATALOG, CommandCatalog, CommandTransport
from headless_re_mcp.error_boundary import guard_tool_handler
from headless_re_mcp.telemetry import instrument
from headless_re_mcp.tools.binding import BoundTool

# Debugger calls run for tens of seconds, so they get their own limiter: sharing
# anyio's default pool would let a handful of stuck tools starve everything else
# that offloads work, including the framework's own. Reaching this bound queues
# further tool calls, which is honest backpressure rather than silent starvation.
_TOOL_THREADS = 16
_tool_limiter: anyio.CapacityLimiter | None = None


def _limiter() -> anyio.CapacityLimiter:
    # Built on first use because a capacity limiter binds to the running loop.
    global _tool_limiter
    if _tool_limiter is None:
        _tool_limiter = anyio.CapacityLimiter(_TOOL_THREADS)
    return _tool_limiter


def apply_result_budget(
    handler: Callable[..., dict[str, Any]],
    *,
    max_bytes: int,
) -> Callable[..., dict[str, Any]]:
    """Cut a tool reply that outran the catalog byte budget.

    The agent transport already does this. MCP was sending the raw envelope,
    so a 400 KB jadx class went into the Cursor context while the same call
    on the agent path was replaced with a 16 KB truncated summary.
    """

    @wraps(handler)
    def wrapped(*args: Any, **kwargs: Any) -> dict[str, Any]:
        value = handler(*args, **kwargs)
        result, _truncated = bounded_tool_result(value, max_bytes=max_bytes)
        return result

    return wrapped


def offload(
    handler: Callable[..., dict[str, Any]],
    *,
    timeout: float = 60.0,
) -> Callable[..., Any]:
    """Run a blocking handler off the event loop.

    FastMCP calls a synchronous tool directly inside the event loop, and these
    handlers block for as long as the debugger takes: a single launch or
    decompile would otherwise stall every other request on the connection,
    including the ones asking what went wrong. ``functools.wraps`` keeps the
    typed signature so schema generation is unaffected.

    The catalog timeout is the outer deadline. ``abandon_on_cancel`` lets a
    disconnect return immediately; ``fail_after`` does the same when the
    catalog bound fires, so the limiter slot is reusable instead of waiting
    out a backend that has already missed it. Default is 60s, the same as
    ``ResourcePolicy.timeout_seconds``.
    """
    bound = max(0.1, float(timeout))

    @wraps(handler)
    async def offloaded(*args: Any, **kwargs: Any) -> dict[str, Any]:
        def call() -> dict[str, Any]:
            return handler(*args, **kwargs)

        try:
            with anyio.fail_after(bound):
                return await anyio.to_thread.run_sync(
                    call,
                    abandon_on_cancel=True,
                    limiter=_limiter(),
                )
        except TimeoutError:
            return {
                "ok": False,
                "data": None,
                "error": {
                    "code": "tool_timeout",
                    "message": f"tool exceeded {bound:g}s",
                    "details": {},
                    "retryable": True,
                },
                "meta": {},
            }

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
    # catalog binding is what the agent transport invokes. The boundary sits
    # inside the instrumentation so a defect is recorded as the envelope's
    # internal_error rather than as a raw exception type.
    observed = instrument(guard_tool_handler(handler, tool_name=name), name=name)
    budgeted = apply_result_budget(
        observed, max_bytes=spec.resource_policy.max_result_bytes
    )
    tool = Tool.from_function(
        observed,
        name=name,
        description=description,
        structured_output=True,
    )
    # bind_mcp applies the write policy, so take the handler back from the spec
    # rather than registering the unguarded one with the server.
    bound = catalog.bind_mcp(
        name,
        budgeted,
        input_schema=dict(tool.parameters),
        description=tool.description,
    )
    assert bound.handler is not None
    # The server gets the offloaded form so the event loop stays free, while the
    # catalog keeps the direct one: the agent transport calls it synchronously.
    server.add_tool(
        offload(bound.handler, timeout=bound.resource_policy.timeout_seconds),
        name=name,
        description=description,
        structured_output=True,
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
