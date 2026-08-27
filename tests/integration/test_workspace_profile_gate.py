"""Workspace-profile gate: the startup work direction trims the MCP surface.

A profile (``full`` / ``pe`` / ``android`` / ``web``) hides the tool families
that do not belong to the chosen workflow, by dotted-name prefix, when the
server builds its tool surface. This gate pins that contract end to end
through real ``headless_re_mcp serve`` processes:

* each profile advertises exactly the full catalog minus its hidden prefixes
  -- the expected prefix sets are written out here rather than imported, so a
  product-side change to the trimming is a visible test failure, not a
  silently moved goalpost;
* the interception proxy is shared by the android and web directions and only
  the pe direction hides it (a documented earlier regression);
* core families (session/static/knowledge/...) survive every profile, and
  ``full`` is a superset of everything;
* ``workspace.mode.set`` persists: the running process answers ``mode.get``
  with the new profile immediately, the *current* connection keeps its tool
  list (a client's surface is fixed for a session), and the next server
  process comes up trimmed -- proven by round-tripping through the real
  config.json in an isolated config home.

Pure Python end to end; no analysis backend is consulted. Config isolation
relies on ``XDG_CONFIG_HOME`` / ``APPDATA``, which macOS ignores, so the
persistence test is skipped there.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.tools.catalog import CommandCatalog, CommandTransport

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# The trimming semantics, restated independently of the implementation.
_PROFILE_HIDDEN_PREFIXES: dict[str, tuple[str, ...]] = {
    "full": (),
    "pe": ("apk.", "device.", "web.", "js.", "wasm.", "proxy."),
    "android": ("web.", "js.", "wasm."),
    "web": ("apk.", "device."),
}
_CORE_ANCHORS = ("session.create", "static.functions", "knowledge.record", "artifacts.list")


@asynccontextmanager
async def _mcp_client(
    tmp_root: Path, *, profile: str | None, config_home: Path
) -> AsyncIterator[ClientSession]:
    """A real MCP stdio server with isolated state, config and profile."""
    env = os.environ.copy()
    env.pop("HEADLESS_RE_WORKSPACE_PROFILE", None)
    if profile is not None:
        env["HEADLESS_RE_WORKSPACE_PROFILE"] = profile
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_root / "artifacts")
    # platformdirs resolves the user config under these on Linux / Windows.
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


async def _call(client: ClientSession, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await client.call_tool(tool, arguments)
    payload = getattr(result, "structuredContent", None)
    assert isinstance(payload, dict), f"{tool} left the error envelope: {result.content!r}"
    return payload


async def _advertised(client: ClientSession) -> set[str]:
    listed = await client.list_tools()
    return {tool.name for tool in listed.tools}


def _catalog_names() -> set[str]:
    return {spec.name for spec in CommandCatalog().for_transport(CommandTransport.MCP)}


def _expected_surface(profile: str) -> set[str]:
    hidden = _PROFILE_HIDDEN_PREFIXES[profile]
    return {name for name in _catalog_names() if not name.startswith(hidden)}


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_each_profile_advertises_exactly_its_surface(tmp_path: Path) -> None:
    """Every profile trims precisely its prefixes; full hides nothing."""
    surfaces: dict[str, set[str]] = {}
    for profile in ("full", "pe", "android", "web"):
        async with _mcp_client(
            tmp_path / profile, profile=profile, config_home=tmp_path / profile / "config"
        ) as client:
            advertised = await _advertised(client)
            assert advertised == _expected_surface(profile), profile
            surfaces[profile] = advertised

            summary = await _call(client, "workspace.mode.get", {})
            assert summary["ok"] is True, summary
            assert summary["data"]["profile"] == profile
            hidden = set(summary["data"]["hidden_prefixes"])
            assert hidden == set(_PROFILE_HIDDEN_PREFIXES[profile])

    # full is the superset; core anchors survive every direction.
    assert surfaces["full"] == _catalog_names()
    for profile, advertised in surfaces.items():
        assert advertised <= surfaces["full"]
        for anchor in _CORE_ANCHORS:
            assert anchor in advertised, (profile, anchor)

    # The proxy is shared by android and web and hidden only from pe.
    assert "proxy.start" in surfaces["android"]
    assert "proxy.start" in surfaces["web"]
    assert "proxy.start" not in surfaces["pe"]
    # Direction-defining anchors land exactly where they belong.
    assert "apk.open" in surfaces["android"]
    assert "apk.open" not in surfaces["web"]
    assert "web.open" in surfaces["web"]
    assert "web.open" not in surfaces["android"]
    assert "web.open" not in surfaces["pe"]


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform == "darwin", reason="config home is not env-relocatable on macOS")
async def test_mode_set_persists_for_the_next_connection(tmp_path: Path) -> None:
    """mode.set answers immediately, keeps this session's surface, trims the next."""
    config_home = tmp_path / "config"

    async with _mcp_client(tmp_path / "first", profile=None, config_home=config_home) as client:
        before = await _call(client, "workspace.mode.get", {})
        assert before["data"]["profile"] == "full"
        assert await _advertised(client) == _catalog_names()

        changed = await _call(client, "workspace.mode.set", {"profile": "pe"})
        assert changed["ok"] is True, changed
        assert changed["data"]["profile"] == "pe"
        assert changed["data"]["persisted"] is True
        assert "next connection" in changed["data"]["note"]

        # The running process reflects the choice at once...
        after = await _call(client, "workspace.mode.get", {})
        assert after["data"]["profile"] == "pe"
        # ...but this connection's tool list stays what it connected with.
        assert await _advertised(client) == _catalog_names()

        # A profile outside the schema pattern never reaches the service.
        garbage = await client.call_tool("workspace.mode.set", {"profile": "solaris"})
        assert garbage.isError is True
        assert getattr(garbage, "structuredContent", None) is None

    # The choice landed in the real config file of the isolated config home.
    config_file = config_home / "headless-re-mcp" / "config.json"
    assert config_file.is_file()
    assert json.loads(config_file.read_text(encoding="utf-8"))["workspace_profile"] == "pe"

    # A fresh server in the same config home comes up trimmed, with no env help.
    async with _mcp_client(tmp_path / "second", profile=None, config_home=config_home) as client:
        summary = await _call(client, "workspace.mode.get", {})
        assert summary["data"]["profile"] == "pe"
        assert await _advertised(client) == _expected_surface("pe")
