"""Coverage for the MCP server's profile trim and stdio wiring.

``test_mcp_server.py`` builds the full surface with the default "full" profile,
where ``_apply_workspace_profile`` is a no-op. These pin the trim branch for a
non-full profile and the ``run_stdio`` wiring (hooks, telemetry, and the
guaranteed service shutdown), both with light fakes so no real stdio is opened.
"""

from __future__ import annotations

import contextlib
import types
from collections.abc import AsyncIterator
from typing import Any, cast

import anyio
import pytest
from mcp.server.fastmcp import FastMCP

import headless_re_mcp.mcp.server as server_module
import headless_re_mcp.mcp.stdio_errors as stdio_errors
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.mcp.server import _apply_workspace_profile, run_stdio


class _ToolManager:
    def __init__(self, tools: dict[str, object]) -> None:
        self._tools = tools


class _Server:
    def __init__(self, tools: dict[str, object]) -> None:
        self._tool_manager = _ToolManager(tools)


def _analysis(profile: str) -> AnalysisService:
    settings = types.SimpleNamespace(workspace_profile=profile)
    return cast(AnalysisService, types.SimpleNamespace(settings=settings))


def test_a_non_full_profile_trims_the_excluded_prefixes() -> None:
    tools: dict[str, object] = {
        "session.list": object(),
        "static.strings": object(),
        "apk.list": object(),  # hidden by the web profile
        "device.info": object(),  # hidden by the web profile
        "web.open": object(),  # kept by the web profile
    }
    server = cast(FastMCP[None], _Server(tools))

    _apply_workspace_profile(server, _analysis("web"))

    # apk.*/device.* are trimmed; core and web tools stay.
    assert set(tools) == {"session.list", "static.strings", "web.open"}


def test_the_full_profile_trims_nothing() -> None:
    tools: dict[str, object] = {"session.list": object(), "apk.list": object()}
    server = cast(FastMCP[None], _Server(tools))

    _apply_workspace_profile(server, _analysis("full"))

    assert set(tools) == {"session.list", "apk.list"}


def test_run_stdio_configures_and_always_closes_the_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    sentinel_server = object()

    class _Service:
        def close_all(self) -> None:
            calls.append("close_all")

    monkeypatch.setattr(
        server_module, "install_global_exception_hooks", lambda name: calls.append(f"hooks:{name}")
    )
    monkeypatch.setattr(
        server_module, "configure_telemetry_logging", lambda: calls.append("telemetry")
    )
    monkeypatch.setattr(server_module, "create_server", lambda analysis: sentinel_server)

    ran_with: list[tuple[Any, Any]] = []
    monkeypatch.setattr(anyio, "run", lambda fn, arg: ran_with.append((fn, arg)))

    service = cast(AnalysisService, _Service())
    run_stdio(service)

    assert calls == ["hooks:mcp-stdio", "telemetry", "close_all"]
    assert ran_with == [(server_module._run_stdio, sentinel_server)]


def test_run_stdio_closes_the_service_even_when_the_loop_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[str] = []

    class _Service:
        def close_all(self) -> None:
            closed.append("close_all")

    monkeypatch.setattr(server_module, "install_global_exception_hooks", lambda name: None)
    monkeypatch.setattr(server_module, "configure_telemetry_logging", lambda: None)
    monkeypatch.setattr(server_module, "create_server", lambda analysis: object())

    def _boom(fn: Any, arg: Any) -> None:
        raise RuntimeError("event loop refused to start")

    monkeypatch.setattr(anyio, "run", _boom)

    service = cast(AnalysisService, _Service())
    with pytest.raises(RuntimeError, match="event loop refused"):
        run_stdio(service)

    assert closed == ["close_all"], "the service must be closed on the failure path too"


@pytest.mark.asyncio
async def test_run_stdio_inner_runs_the_mcp_server_over_the_parse_reply_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextlib.asynccontextmanager
    async def fake_streams() -> AsyncIterator[tuple[str, str]]:
        yield ("read-stream", "write-stream")

    monkeypatch.setattr(stdio_errors, "stdio_server_with_parse_replies", fake_streams)

    ran: dict[str, Any] = {}

    class _McpServer:
        def create_initialization_options(self) -> dict[str, bool]:
            return {"init": True}

        async def run(self, read: Any, write: Any, opts: Any) -> None:
            ran["args"] = (read, write, opts)

    class _Server:
        _mcp_server = _McpServer()

    await server_module._run_stdio(cast(FastMCP[None], _Server()))

    assert ran["args"] == ("read-stream", "write-stream", {"init": True})
