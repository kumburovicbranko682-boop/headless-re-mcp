"""elf.* over real MCP stdio: a native ELF is a first-class thing to read.

Native code could only be opened here through r2 or Ghidra, external tools that
are not always installed. The ELF header/section/program/dynamic/symbol tables
are an exact binary format that reads with the stdlib alone. This gate drives
the real stdio server end to end on a hand-assembled ELF (portable, so it runs
anywhere) and pins the round trip: elf.summary, elf.symbols and elf.segments are
advertised, the summary returns the class, machine, section list and shared-
library dependencies, the symbol page classifies imports and exports, the
segment list carries the program headers with the interp/nx/relro posture, and a
file that is not an ELF fails with invalid_params rather than an internal fault.
It needs no analysis backend, so it always runs.
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
    # .dynsym: the null symbol, one import (undefined) and one export (defined).
    dynsym = b"".join(
        struct.pack("<IBBHQQ", *entry)
        for entry in [
            (0, 0, 0, 0, 0, 0),
            (add("malloc"), 0x12, 0, 0, 0, 0),
            (add("gate_open"), 0x12, 0, 1, 0x1010, 0x20),
        ]
    )
    sections: list[tuple[str, int, int, bytes]] = [
        ("", 0, 0, b""),
        (".text", 1, 0x6, b"\x90" * 8),
        (".dynstr", 3, 0x2, bytes(dynstr)),
        (".dynamic", 6, 0x2, dynamic),
        (".dynsym", 11, 0x2, dynsym),
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
    dynstr_index = next(i for i, entry in enumerate(placed) if entry[0] == ".dynstr")
    sht = b"".join(
        struct.pack(
            "<IIQQQQIIQQ",
            name_off.get(name, 0) if name else 0,
            stype,
            flags,
            0,
            off,
            size,
            dynstr_index if name == ".dynsym" else 0,
            0,
            1,
            24 if name == ".dynsym" else 0,
        )
        for name, stype, flags, off, size in placed
    )
    shstrndx = next(i for i, entry in enumerate(placed) if entry[0] == ".shstrtab")
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<HHIQQQIHHHHHH", 3, 62, 1, 0x1000, 0, shoff, 0, 64, 0, 0, 64, len(placed), shstrndx
    )
    return ident + ehdr + bytes(contents) + sht


def _build_seg_elf() -> bytes:
    """A minimal ELF64 carrying only a program header table (INTERP/LOAD/stack)."""
    entries = [("INTERP", 0x4), ("LOAD", 0x5), ("GNU_STACK", 0x6), ("GNU_RELRO", 0x4)]
    ptype = {"INTERP": 3, "LOAD": 1, "GNU_STACK": 0x6474E551, "GNU_RELRO": 0x6474E552}
    phoff, phentsize = 64, 56
    interp_off = phoff + len(entries) * phentsize
    interp_bytes = b"/lib64/ld-linux-x86-64.so.2\x00"
    phdrs = b""
    for name, flags in entries:
        if name == "INTERP":
            poff, psz = interp_off, len(interp_bytes)
        else:
            poff, psz = phoff, phentsize
        phdrs += struct.pack(
            "<IIQQQQQQ", ptype[name], flags, poff, poff, poff, psz, psz, 0x1000
        )
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0x1000, phoff, 0, 0, 64, phentsize, len(entries), 0, 0, 0
    )
    return ident + ehdr + phdrs + interp_bytes


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
    prog = tmp_path / "prog"
    prog.write_bytes(_build_seg_elf())
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
        assert "elf.symbols" in tools
        assert "elf.segments" in tools

        full = await _call(client, "elf.summary", {"path": str(binary)})
        assert full["ok"] is True, full
        data = full["data"]
        assert data["class"] == "ELF64"
        assert data["machine"] == "x86-64"
        assert data["type"] == "shared object"
        assert data["needed"] == ["libc.so.6"]
        assert data["soname"] == "libgate.so"
        assert ".dynamic" in {section["name"] for section in data["sections"]}

        symbols = await _call(client, "elf.symbols", {"path": str(binary)})
        assert symbols["ok"] is True, symbols
        listing = symbols["data"]
        assert listing["symbols_total"] == 3
        by_name = {s["name"]: s for s in listing["symbols"]}
        assert by_name["malloc"]["imported"] is True
        assert by_name["gate_open"]["exported"] is True
        assert listing["imported_listed"] == 1
        assert listing["exported_listed"] == 1

        paged = await _call(client, "elf.symbols", {"path": str(binary), "offset": 1, "limit": 1})
        assert paged["ok"] is True, paged
        assert [s["name"] for s in paged["data"]["symbols"]] == ["malloc"]
        assert paged["data"]["has_more"] is True

        segments = await _call(client, "elf.segments", {"path": str(prog)})
        assert segments["ok"] is True, segments
        seg_data = segments["data"]
        assert seg_data["interp"] == "/lib64/ld-linux-x86-64.so.2"
        assert seg_data["nx"] is True
        assert seg_data["relro"] is True
        assert seg_data["writable_executable"] is False
        assert [s["type"] for s in seg_data["segments"]] == [
            "INTERP",
            "LOAD",
            "GNU_STACK",
            "GNU_RELRO",
        ]

        bad = await _call(client, "elf.summary", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"

        bad_segments = await _call(client, "elf.segments", {"path": str(junk)})
        assert bad_segments["ok"] is False
        assert bad_segments["error"]["code"] == "invalid_params"

        bad_symbols = await _call(client, "elf.symbols", {"path": str(junk)})
        assert bad_symbols["ok"] is False
        assert bad_symbols["error"]["code"] == "invalid_params"
