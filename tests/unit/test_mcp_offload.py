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

import headless_re_mcp.mcp.adapter as adapter
from headless_re_mcp.core.commands import (
    CommandCatalog,
    CommandSpec,
    CommandTransport,
    ResourcePolicy,
)
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


@pytest.mark.anyio
async def test_a_cancelled_call_does_not_hold_the_caller_for_the_whole_tool() -> None:
    started = asyncio.Event()
    loop = asyncio.get_running_loop()

    def blocking() -> dict[str, Any]:
        loop.call_soon_threadsafe(started.set)
        time.sleep(1.0)
        return {"ok": True}

    task = asyncio.create_task(offload(blocking)())
    await started.wait()
    task.cancel()

    began = time.monotonic()
    with pytest.raises(asyncio.CancelledError):
        await task
    # A client that disconnects mid-launch must not keep the server waiting out
    # the debugger's timeout before it can answer anything else.
    assert time.monotonic() - began < 0.5


def test_tool_threads_do_not_share_the_default_pool() -> None:
    limiter = adapter._limiter()

    # Sharing anyio's default pool would let a handful of stuck debugger calls
    # starve every other offloaded task, including the framework's own.
    assert limiter is not None
    assert limiter.total_tokens == adapter._TOOL_THREADS
    assert adapter._limiter() is limiter


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


@pytest.mark.anyio
async def test_catalog_timeout_returns_and_frees_the_limiter_slot() -> None:
    """Offload used to ignore ResourcePolicy.timeout_seconds.

    Measured: a handler that slept past the catalog bound kept its limiter
    slot until the debugger's own timeout. Sixteen of those and every later
    tool queued behind work that had already missed its deadline.
    """
    catalog = CommandCatalog(
        [
            CommandSpec(
                name="probe.slow",
                service_method="probe_slow",
                transports=frozenset({CommandTransport.MCP, CommandTransport.AGENT}),
                effects=frozenset({ToolEffect.READ_ONLY}),
                resource_policy=ResourcePolicy(timeout_seconds=0.2),
            )
        ]
    )
    server: FastMCP[None] = FastMCP(name="probe")

    def hanging() -> dict[str, Any]:
        time.sleep(5.0)
        return {"ok": True}

    register_tool(server, hanging, name="probe.slow", catalog=catalog)
    fn = server._tool_manager.get_tool("probe.slow").fn
    limiter = adapter._limiter()
    before = limiter.borrowed_tokens

    began = time.monotonic()
    result = await fn()
    elapsed = time.monotonic() - began

    assert elapsed < 1.5
    assert result["ok"] is False
    assert result["error"]["code"] == "tool_timeout"
    assert limiter.borrowed_tokens == before

    def quick() -> dict[str, Any]:
        return {"ok": True, "n": 1}

    assert await offload(quick, timeout=1.0)() == {"ok": True, "n": 1}
