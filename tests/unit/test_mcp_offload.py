"""A slow tool must not stall the connection it arrived on.

FastMCP invokes a synchronous tool directly inside the event loop, and these
handlers block for as long as the debugger takes. Without offloading, one launch
or decompile freezes every other request, including the ones asking what is
wrong, so this pins the behaviour rather than trusting the wrapper to stay.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from headless_re_mcp.core.commands import CommandCatalog, CommandSpec, CommandTransport
from headless_re_mcp.mcp.adapter import offload, register_tool
from headless_re_mcp.tools.catalog import ToolEffect


def test_offload_preserves_the_signature_schema_generation_needs() -> None:
    def handler(session_id: str, limit: int = 5) -> dict[str, Any]:
        """Docstring stays."""
        return {"ok": True, "session_id": session_id, "limit": limit}

    offloaded = offload(handler)

    assert asyncio.iscoroutinefunction(offloaded)
    assert offloaded.__doc__ == "Docstring stays."
    # Schema generation reads the signature, so losing it here would silently
    # turn every tool into one that accepts anything.
    assert inspect.signature(offloaded) == inspect.signature(handler)
    assert list(inspect.signature(offloaded).parameters) == ["session_id", "limit"]


@pytest.mark.anyio
async def test_a_blocking_tool_leaves_the_event_loop_free() -> None:
    release = asyncio.Event()
    loop = asyncio.get_running_loop()

    def blocking() -> dict[str, Any]:
        # A real handler blocks on the debugger; sleeping in the calling thread
        # is the same problem in miniature.
        time.sleep(0.3)
        loop.call_soon_threadsafe(release.set)
        return {"ok": True}

    task = asyncio.create_task(offload(blocking)())
    # If the handler ran inline this would never get a turn before the sleep ends.
    ticks = 0
    while not release.is_set():
        await asyncio.sleep(0.01)
        ticks += 1

    assert await task == {"ok": True}
    assert ticks > 1, "the event loop never regained control while the tool ran"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_registration_offloads_the_server_copy_but_not_the_catalog_one() -> None:
    catalog = CommandCatalog(
        [
            CommandSpec(
                name="probe.echo",
                service_method="probe_echo",
                transports=frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
                effects=frozenset({ToolEffect.READ_ONLY}),
            )
        ]
    )
    server: FastMCP[None] = FastMCP(name="probe")

    def handler(value: str) -> dict[str, Any]:
        """Echo."""
        return {"ok": True, "value": value}

    register_tool(server, handler, name="probe.echo", catalog=catalog)

    spec = catalog.get("probe.echo")
    assert spec is not None and spec.handler is not None
    # The agent transport calls the catalog handler directly, so it has to stay
    # synchronous even though the server copy is awaited.
    assert not asyncio.iscoroutinefunction(spec.handler)
    assert spec.handler(value="x") == {"ok": True, "value": "x"}
    assert asyncio.iscoroutinefunction(server._tool_manager.get_tool("probe.echo").fn)
