"""Workspace profiles trim the MCP surface without touching the full catalog."""

from __future__ import annotations

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.workspace import PROFILES, excluded_prefixes, is_tool_visible
from headless_re_mcp.mcp.server import create_server


def _service_with_profile(tmp_path, profile: str) -> AnalysisService:
    settings = Settings.load()
    object.__setattr__(settings, "artifact_root", tmp_path)
    object.__setattr__(settings, "workspace_profile", profile)
    return AnalysisService(settings=settings)


@pytest.mark.asyncio
async def test_full_profile_exposes_every_tool(tmp_path) -> None:
    analysis = _service_with_profile(tmp_path, "full")
    try:
        server = create_server(analysis)
        tools = await server.list_tools()
    finally:
        analysis.close_all()
    names = {tool.name for tool in tools}
    assert len(names) == 263
    assert "apk.open" in names
    assert "web.open" in names


@pytest.mark.asyncio
async def test_android_profile_hides_web_domain(tmp_path) -> None:
    analysis = _service_with_profile(tmp_path, "android")
    try:
        server = create_server(analysis)
        names = {tool.name for tool in await server.list_tools()}
    finally:
        analysis.close_all()
    assert "apk.open" in names
    assert "device.list" in names
    assert not any(n.startswith(("web.", "js.", "wasm.", "proxy.")) for n in names)
    # Core debugger tools remain available in every profile.
    assert "session.create" in names
    assert "frida.devices" in names


@pytest.mark.asyncio
async def test_web_profile_hides_android_domain(tmp_path) -> None:
    analysis = _service_with_profile(tmp_path, "web")
    try:
        server = create_server(analysis)
        names = {tool.name for tool in await server.list_tools()}
    finally:
        analysis.close_all()
    assert "web.open" in names
    assert not any(n.startswith(("apk.", "device.")) for n in names)


@pytest.mark.asyncio
async def test_pe_profile_hides_both_android_and_web(tmp_path) -> None:
    analysis = _service_with_profile(tmp_path, "pe")
    try:
        server = create_server(analysis)
        names = {tool.name for tool in await server.list_tools()}
    finally:
        analysis.close_all()
    assert not any(
        n.startswith(("apk.", "device.", "web.", "js.", "wasm.", "proxy.")) for n in names
    )
    assert "static.open" in names
    assert "workspace.mode.get" in names


def test_workspace_mode_get_and_set_roundtrip(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.config.default_config_path", lambda: tmp_path / "config.json"
    )
    analysis = _service_with_profile(tmp_path, "full")
    try:
        got = analysis.workspace_mode_get()
        assert got.ok and got.data is not None
        assert got.data["profile"] == "full"
        assert {item["id"] for item in got.data["available"]} == set(PROFILES)

        bad = analysis.workspace_mode_set("nonsense")
        assert not bad.ok

        ok = analysis.workspace_mode_set("android")
        assert ok.ok and ok.data is not None
        assert ok.data["profile"] == "android"
        assert analysis.settings.workspace_profile == "android"
    finally:
        analysis.close_all()


def test_profile_helpers_are_consistent() -> None:
    assert excluded_prefixes("full") == ()
    assert is_tool_visible("apk.open", "web") is False
    assert is_tool_visible("web.open", "android") is False
    assert is_tool_visible("session.create", "pe") is True


def test_agent_tool_surface_follows_workspace_profile(tmp_path) -> None:
    from headless_re_mcp.agent.config import ProviderConfigStore
    from headless_re_mcp.agent.orchestrator import AgentOrchestrator
    from headless_re_mcp.agent.store import AgentStore
    from headless_re_mcp.tools.assembly import bind_all_tools
    from headless_re_mcp.tools.catalog import CommandCatalog

    profile = {"value": "full"}
    catalog = CommandCatalog()
    analysis = AnalysisService()
    try:
        bind_all_tools(analysis, catalog)
        orchestrator = AgentOrchestrator(
            AgentStore(tmp_path / "agent.db"),
            catalog,
            ProviderConfigStore(tmp_path / "providers.json"),
            tool_profile_provider=lambda: profile["value"],
        )

        full_names = {tool["function"]["name"] for tool in orchestrator._provider_tools()}
        assert "apk.open" in full_names and "web.open" in full_names

        profile["value"] = "android"
        android_names = {tool["function"]["name"] for tool in orchestrator._provider_tools()}
        assert "apk.open" in android_names
        assert not any(
            n.startswith(("web.", "js.", "wasm.", "proxy.")) for n in android_names
        )
        assert "session.create" in android_names

        profile["value"] = "web"
        web_names = {tool["function"]["name"] for tool in orchestrator._provider_tools()}
        assert "web.open" in web_names
        assert not any(n.startswith(("apk.", "device.")) for n in web_names)
    finally:
        analysis.close_all()
