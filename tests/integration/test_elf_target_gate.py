"""ELF opens a session over real MCP, and routes to the cross-platform tools.

The radare2 and Ghidra lines exist to analyse native binaries the PE backends
cannot, and on Linux that means ELF. But classify_target used to funnel every
non-PE file into PE, and session.create then rejected it with "not a PE file",
so an ELF could not open a session at all -- the r2/ghidra tools had nothing to
run against.

This gate drives the real MCP stdio server and pins the contract end to end:

- session.create on an ELF returns ok with target=elf and, for a machine we
  model, its architecture; session.get echoes the same.
- static.open (the PE/IDA backend) answers target_mismatch -- an ELF is not a
  PE, said honestly rather than crashing inside a backend.
- r2.open reaches the radare2 availability check: absent the CLI that is
  capability_unavailable, but never target_mismatch, which would mean ELF was
  turned away as a target rather than analysed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

mcp = pytest.importorskip("mcp")

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

JsonObject = dict[str, Any]


def _elf_x64(path: Path) -> Path:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2  # ELFCLASS64
    header[5] = 1  # ELFDATA2LSB
    header[6] = 1  # EV_CURRENT
    header[16:18] = (2).to_bytes(2, "little")  # ET_EXEC
    header[18:20] = (0x3E).to_bytes(2, "little")  # EM_X86_64
    path.write_bytes(bytes(header))
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
async def test_elf_session_opens_and_routes_over_mcp(tmp_path: Path) -> None:
    elf = _elf_x64(tmp_path / "program")

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
            await client.call_tool("session.create", {"binary": str(elf)})
        )
        assert created["ok"] is True, created
        session = created["data"]["session"]
        assert session["target"] == "elf", session
        assert session["architecture"] == "x64", session
        session_id = str(session["id"])

        fetched = _structured(
            await client.call_tool("session.get", {"session_id": session_id})
        )
        assert fetched["data"]["session"]["target"] == "elf"

        # PE-only static backend must refuse the ELF, honestly.
        opened = _structured(
            await client.call_tool("static.open", {"session_id": session_id})
        )
        assert opened["ok"] is False, opened
        assert opened["error"]["code"] == "target_mismatch", opened

        # radare2 is reached (never target_mismatch); absent the CLI it is
        # capability_unavailable.
        r2 = _structured(
            await client.call_tool("r2.open", {"session_id": session_id})
        )
        if r2["ok"] is False:
            assert r2["error"]["code"] != "target_mismatch", r2

        closed = _structured(
            await client.call_tool("session.close", {"session_id": session_id})
        )
        assert closed["ok"] is True, closed
