"""Mach-O opens a session over real MCP and routes to the cross-platform tools.

The radare2 and Ghidra lines exist to analyse native binaries the PE backends
cannot, and a Mach-O is the macOS/iOS case. classify_target used to funnel it
into PE, and session.create then rejected it with "not a PE file", so a Mach-O
could not open a session at all.

This gate drives the real MCP stdio server and pins the contract end to end for
a thin x86-64 Mach-O:

- session.create returns ok with target=macho and architecture x64;
  session.get echoes it.
- static.open (the PE/IDA backend) answers target_mismatch.
- r2.open reaches the radare2 availability check: absent the CLI that is
  capability_unavailable, never target_mismatch.
"""

from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from typing import Any

import pytest

mcp = pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

JsonObject = dict[str, Any]

_CPU_X86_64 = 0x01000007


def _thin_macho_x64(path: Path) -> Path:
    # MH_MAGIC_64 (little-endian) + cputype x86_64 + a zeroed rest of the header.
    path.write_bytes(b"\xcf\xfa\xed\xfe" + struct.pack("<I", _CPU_X86_64) + b"\x00" * 24)
    return path


def _structured(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


def _server_env(tmp_path: Path) -> dict[str, str]:
    env = os.environ.copy()
    config_home = tmp_path / "config"
    config_home.mkdir(exist_ok=True)
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["APPDATA"] = str(config_home)
    env["LOCALAPPDATA"] = str(config_home)
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    return env


@pytest.mark.integration
@pytest.mark.asyncio
async def test_macho_session_opens_and_routes_over_mcp(tmp_path: Path) -> None:
    macho = _thin_macho_x64(tmp_path / "program")

    project_root = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=_server_env(tmp_path),
        cwd=str(project_root),
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()

        created = _structured(
            await client.call_tool("session.create", {"binary": str(macho)})
        )
        assert created["ok"] is True, created
        session = created["data"]["session"]
        assert session["target"] == "macho", session
        assert session["architecture"] == "x64", session
        session_id = str(session["id"])

        fetched = _structured(
            await client.call_tool("session.get", {"session_id": session_id})
        )
        assert fetched["data"]["session"]["target"] == "macho"

        opened = _structured(
            await client.call_tool("static.open", {"session_id": session_id})
        )
        assert opened["ok"] is False, opened
        assert opened["error"]["code"] == "target_mismatch", opened

        r2 = _structured(
            await client.call_tool("r2.open", {"session_id": session_id})
        )
        if r2["ok"] is False:
            assert r2["error"]["code"] != "target_mismatch", r2

        closed = _structured(
            await client.call_tool("session.close", {"session_id": session_id})
        )
        assert closed["ok"] is True, closed
