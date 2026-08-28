"""macho.summary over real MCP stdio: a Mach-O is a first-class thing to read.

With PE covered by a whole tool line and ELF by elf.summary/elf.symbols, Mach-O
was the one native format that could not be opened here at all. The header and
load commands are an exact binary format that reads with the stdlib alone. This
gate drives the real stdio server end to end on a hand-assembled Mach-O
(portable, so it runs anywhere) and pins the round trip: macho.summary is
advertised, it returns the cpu, filetype, segments, linked dylibs and platform,
and a file that is not a Mach-O fails with invalid_params rather than an
internal fault. It needs no analysis backend, so it always runs.
"""

from __future__ import annotations

import asyncio
import os
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.integration


def _cmd(cmd_id: int, body: bytes) -> bytes:
    size = 8 + len(body)
    pad = (-size) % 8
    return struct.pack("<II", cmd_id, size + pad) + body + b"\x00" * pad


def _build_dylib64() -> bytes:
    """An arm64 LE dylib with __TEXT segment, libSystem dependency and macOS target."""
    commands = [
        _cmd(
            0x19,
            struct.pack(
                "<16sQQQQiiII", b"__TEXT", 0x100000000, 0x4000, 0, 0x4000, 0x5, 0x5, 2, 0
            ),
        ),
        _cmd(0xD, struct.pack("<IIII", 24, 0, 0, 0) + b"libgate.dylib\x00"),
        _cmd(0xC, struct.pack("<IIII", 24, 0, 0, 0) + b"/usr/lib/libSystem.B.dylib\x00"),
        _cmd(0x32, struct.pack("<IIII", 1, 0x000B0000, 0x000E0000, 0)),  # macOS 11.0
        _cmd(0x2, struct.pack("<IIII", 0, 3, 0, 0)),
    ]
    payload = b"".join(commands)
    header = b"\xcf\xfa\xed\xfe" + struct.pack(
        "<iiIIIII", 0x0100000C, 0, 6, len(commands), len(payload), 0, 0
    )
    return header + payload


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return {str(key): item for key, item in content.items()}


async def _call(client: ClientSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return _structured(await asyncio.wait_for(client.call_tool(tool, args), timeout=60))


@pytest.mark.asyncio
async def test_mcp_stdio_macho_summary(tmp_path: Path) -> None:
    binary = tmp_path / "libgate.dylib"
    binary.write_bytes(_build_dylib64())
    junk = tmp_path / "bad.dylib"
    junk.write_bytes(b"not a mach-o binary at all")

    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=os.environ.copy(),
        cwd=str(_PROJECT_ROOT),
    )

    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        tools = {tool.name for tool in (await client.list_tools()).tools}
        assert "macho.summary" in tools

        full = await _call(client, "macho.summary", {"path": str(binary)})
        assert full["ok"] is True, full
        data = full["data"]
        assert data["format"] == "Mach-O"
        assert data["fat"] is False
        assert data["cpu"] == "AArch64"
        assert data["filetype"] == "dylib"
        assert data["id_dylib"] == "libgate.dylib"
        assert data["dylibs"] == ["/usr/lib/libSystem.B.dylib"]
        assert data["platform"] == {"name": "macOS", "min_os": "11.0.0", "sdk": "14.0.0"}
        assert [segment["name"] for segment in data["segments"]] == ["__TEXT"]

        bad = await _call(client, "macho.summary", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"
