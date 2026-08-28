"""macho.summary over real MCP stdio: a Mach-O is a first-class thing to read.

With PE covered by a whole tool line and ELF by elf.summary/elf.symbols, Mach-O
was the one native format that could not be opened here at all. The header and
load commands are an exact binary format that reads with the stdlib alone. This
gate drives the real stdio server end to end on hand-assembled Mach-O images
(portable, so it runs anywhere) and pins the round trip: macho.summary,
macho.symbols, macho.signature and macho.strings are advertised, the summary
returns the cpu, filetype, segments, linked dylibs and platform, the symbol page
classifies imports and exports, the signature decode surfaces the CodeDirectory
identity, team ID, flags and entitlements (and says unsigned when there is no
signature), the string extraction pulls printable literals tagged with the
two-level __TEXT,__cstring section they came from, and a file that is not a
Mach-O fails with invalid_params rather than an internal fault. It needs no
analysis backend, so it always runs.
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
    """An arm64 LE dylib with __TEXT, libSystem, macOS target and a real symtab.

    The LC_SYMTAB points at a two-entry nlist appended after the load commands:
    an undefined external import (_malloc, from library ordinal 1 = libSystem)
    and a defined external export (_gate_open).
    """
    strtab = b"\x00_malloc\x00_gate_open\x00"
    off_malloc = strtab.index(b"_malloc")
    off_export = strtab.index(b"_gate_open")
    nlist = struct.pack("<IBBHQ", off_malloc, 0x01, 0, 1 << 8, 0) + struct.pack(
        "<IBBHQ", off_export, 0x0F, 1, 0, 0x4000
    )

    fixed = [
        _cmd(
            0x19,
            struct.pack(
                "<16sQQQQiiII", b"__TEXT", 0x100000000, 0x4000, 0, 0x4000, 0x5, 0x5, 2, 0
            ),
        ),
        _cmd(0xD, struct.pack("<IIII", 24, 0, 0, 0) + b"libgate.dylib\x00"),
        _cmd(0xC, struct.pack("<IIII", 24, 0, 0, 0) + b"/usr/lib/libSystem.B.dylib\x00"),
        _cmd(0x32, struct.pack("<IIII", 1, 0x000B0000, 0x000E0000, 0)),  # macOS 11.0
    ]
    payload_len = sum(len(c) for c in fixed) + 24  # + LC_SYMTAB
    symoff = 32 + payload_len
    stroff = symoff + len(nlist)
    commands = [*fixed, _cmd(0x2, struct.pack("<IIII", symoff, 2, stroff, len(strtab)))]
    payload = b"".join(commands)
    header = b"\xcf\xfa\xed\xfe" + struct.pack(
        "<iiIIIII", 0x0100000C, 0, 6, len(commands), len(payload), 0, 0
    )
    return header + payload + nlist + strtab


def _build_signed_dylib() -> bytes:
    """An arm64 dylib carrying a real code-signature superblob at end of file.

    The CodeDirectory (version 0x20200, hardened-runtime flag, sha256) names
    the signing identifier and a team ID; an entitlements blob grants
    get-task-allow -- the pieces macho.signature must surface over the wire.
    """
    ident = b"com.example.gate\x00"
    team = b"TEAMID1234\x00"
    cd_len = 52 + len(ident) + len(team)
    cd = (
        struct.pack(
            ">IIIIIIIIIBBBBI",
            0xFADE0C02, cd_len, 0x20200, 0x10000,  # RUNTIME
            cd_len, 52, 0, 0, 0x4000, 32, 2, 0, 12, 0,
        )
        + struct.pack(">II", 0, 52 + len(ident))
        + ident
        + team
    )
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<plist version="1.0"><dict>'
        b"<key>com.apple.security.get-task-allow</key><true/>"
        b"</dict></plist>"
    )
    ent = struct.pack(">II", 0xFADE7171, 8 + len(xml)) + xml
    sig = (
        struct.pack(">III", 0xFADE0CC0, 28 + len(cd) + len(ent), 2)
        + struct.pack(">II", 0, 28)
        + struct.pack(">II", 5, 28 + len(cd))
        + cd
        + ent
    )

    def commands(dataoff: int) -> list[bytes]:
        return [
            _cmd(
                0x19,
                struct.pack(
                    "<16sQQQQiiII", b"__TEXT", 0x100000000, 0x4000, 0, 0x4000, 0x5, 0x5, 1, 0
                ),
            ),
            _cmd(0x1D, struct.pack("<II", dataoff, len(sig))),
        ]

    payload = b"".join(commands(0))
    payload = b"".join(commands(32 + len(payload)))
    header = b"\xcf\xfa\xed\xfe" + struct.pack(
        "<iiIIIII", 0x0100000C, 0, 6, 2, len(payload), 0, 0
    )
    return header + payload + sig


def _build_string_dylib() -> bytes:
    """An arm64 dylib with a __TEXT,__cstring section carrying known constants.

    The single LC_SEGMENT_64 declares one real section_64 whose file offset is
    wired to the appended content, so macho.strings must return those literals
    tagged with the two-level __TEXT,__cstring label.
    """
    content = b"\x00hello_gate\x00yaml_parse_error\x00"
    hdr_size, seg_hdr, sect_size = 32, 72, 80
    seg_cmd_size = seg_hdr + sect_size
    content_off = hdr_size + seg_cmd_size
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__cstring", b"__TEXT", 0x1000, len(content), content_off, 0, 0, 0, 0x2, 0, 0, 0
    )
    seg = struct.pack(
        "<II16sQQQQiiII",
        0x19, seg_cmd_size, b"__TEXT", 0x100000000, 0x10000, 0, content_off + len(content),
        0x7, 0x5, 1, 0,
    )
    payload = seg + section
    header = b"\xcf\xfa\xed\xfe" + struct.pack(
        "<iiIIIII", 0x0100000C, 0, 6, 1, len(payload), 0, 0
    )
    return header + payload + content


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
    signed = tmp_path / "libsigned.dylib"
    signed.write_bytes(_build_signed_dylib())
    stringy = tmp_path / "libstrings.dylib"
    stringy.write_bytes(_build_string_dylib())
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
        assert "macho.symbols" in tools
        assert "macho.signature" in tools
        assert "macho.strings" in tools

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

        symbols = await _call(client, "macho.symbols", {"path": str(binary)})
        assert symbols["ok"] is True, symbols
        listing = symbols["data"]
        assert listing["symbols_total"] == 2
        by_name = {s["name"]: s for s in listing["symbols"]}
        assert by_name["_malloc"]["imported"] is True
        assert by_name["_malloc"]["library"] == "/usr/lib/libSystem.B.dylib"
        assert by_name["_gate_open"]["exported"] is True

        signature = await _call(client, "macho.signature", {"path": str(signed)})
        assert signature["ok"] is True, signature
        sig_data = signature["data"]
        assert sig_data["signed"] is True
        directory = sig_data["code_directory"]
        assert directory["identifier"] == "com.example.gate"
        assert directory["team_id"] == "TEAMID1234"
        assert directory["flags"] == ["RUNTIME"]
        assert directory["hash_type"] == "sha256"
        assert sig_data["hardened_runtime"] is True
        assert sig_data["adhoc"] is False
        assert sig_data["entitlements"]["com.apple.security.get-task-allow"] is True

        unsigned = await _call(client, "macho.signature", {"path": str(binary)})
        assert unsigned["ok"] is True, unsigned
        assert unsigned["data"]["signed"] is False

        strings = await _call(
            client, "macho.strings", {"path": str(stringy), "min_length": 4, "section": "__cstring"}
        )
        assert strings["ok"] is True, strings
        str_data = strings["data"]
        assert str_data["sections_scanned"] == ["__TEXT,__cstring"]
        by_value = {s["value"]: s for s in str_data["strings"]}
        assert "hello_gate" in by_value
        assert "yaml_parse_error" in by_value
        assert by_value["hello_gate"]["segment"] == "__TEXT"
        assert by_value["hello_gate"]["section"] == "__cstring"

        bad = await _call(client, "macho.summary", {"path": str(junk)})
        assert bad["ok"] is False
        assert bad["error"]["code"] == "invalid_params"

        bad_symbols = await _call(client, "macho.symbols", {"path": str(junk)})
        assert bad_symbols["ok"] is False
        assert bad_symbols["error"]["code"] == "invalid_params"

        bad_signature = await _call(client, "macho.signature", {"path": str(junk)})
        assert bad_signature["ok"] is False
        assert bad_signature["error"]["code"] == "invalid_params"

        bad_strings = await _call(client, "macho.strings", {"path": str(junk)})
        assert bad_strings["ok"] is False
        assert bad_strings["error"]["code"] == "invalid_params"
