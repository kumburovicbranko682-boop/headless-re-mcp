"""elf.summary over real MCP stdio: a native ELF is a first-class thing to read.

Native code could only be opened here through r2 or Ghidra, external tools that
are not always installed. The ELF header/section/dynamic tables are an exact
binary format that reads with the stdlib alone. This gate drives the real stdio
server end to end on a hand-assembled ELF (portable, so it runs anywhere) and
pins the round trip: elf.summary is advertised, it returns the class, machine,
section list and shared-library dependencies, and a file that is not an ELF fails
with invalid_params rather than an internal fault. It needs no analysis backend,
so it always runs.
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


def _build_elf64() -> bytes:
    """A little-endian 64-bit shared object with .text/.dynstr/.dynamic sections."""
    dynstr = bytearray(b"\x00")

    def add(text: str) -> int:
        offset = len(dynstr)
        dynstr.extend(text.encode("ascii") + b"\x00")
        return offset

    off_libc = add("libc.so.6")
    off_soname = add("libgate.so")
    dynamic = b"".join(
        struct.pack("<qQ", tag, val)
        for tag, val in [(1, off_libc), (14, off_soname), (0, 0)]
    )
    sections: list[tuple[str, int, int, bytes]] = [
        ("", 0, 0, b""),
        (".text", 1, 0x6, b"\x90" * 8),
        (".dynstr", 3, 0x2, bytes(dynstr)),
        (".dynamic", 6, 0x2, dynamic),
        (".symtab", 2, 0x0, b"\x00" * 24),
        (".shstrtab", 3, 0x0, b""),
    ]
    shstr = bytearray(b"\x00")
    name_off: dict[str, int] = {}
    for name, _t, _f, _c in sections:
        if name and name not in name_off:
            name_off[name] = len(shstr)
            shstr.extend(name.encode("ascii") + b"\x00")
    sections[-1] = (".shstrtab", 3, 0x0, bytes(shstr))

    offset = 64
    placed: list[tuple[str, int, int, int, int]] = []
    contents = bytearray()
    for name, stype, flags, content in sections:
        if stype == 0:
            placed.append((name, stype, flags, 0, 0))
            continue
        placed.append((name, stype, flags, offset, len(content)))
        contents.extend(content)
        offset += len(content)
    shoff = offset
    sht = b"".join(
        struct.pack(
            "<IIQQQQIIQQ",
            name_off.get(name, 0) if name else 0,
            stype,
            flags,
            0,
            off,
            size,
            0,
            0,
            1,
            0,
        )
        for name, stype, flags, off, size in placed
    )
    shstrndx = next(i for i, entry in enumerate(placed) if entry[0] == ".shstrtab")
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0x1000, 0, shoff, 0, 64, 0, 0, 64, len(placed), shstrndx
    )
    return ident + ehdr + bytes(contents) + sht


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return {str(key): item for key, item in content.items()}


async def _call(client: ClientSession, tool: str, args: dict[str, Any]) -> dict[str, Any]:
    return _structured(await asyncio.wait_for(client.call_tool(tool, args), timeout=60))


@pytest.mark.asyncio
async def test_mcp_stdio_elf_summary(tmp_path: Path) -> None:
    binary = tmp_path / "libgate.so"
    binary.write_bytes(_build_elf64())
    junk = tmp_path / "bad.so"
    junk.write_bytes(b"not an elf binary at all")

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
        assert "elf.summary" in tools

        full = await _call(client, "elf.summary", {"path": str(binary)})
        assert full["ok"] is True, full
        data = full["data"]
        assert data["class"] == "ELF64"
        assert data["machine"] == "x86-64"
        assert data["type"] == "shared object"
        assert data["needed"] == ["libc.so.6"]
        assert data["soname"] == "libgate.so"
        assert ".dynamic" in {section["name"] for section in data["sections"]}

        bad = await _call(client, "elf.summary", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"
