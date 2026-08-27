"""Pure-Python .NET managed reader, proven over the real MCP server on Linux.

The .NET metadata reader is pure Python -- it parses ECMA-335 without IDA,
de4dot, or any external tool. Yet its only end-to-end integration gate
(``test_dotnet_m6_gate.py``) requires a configured ``HEADLESS_RE_DE4DOT`` build
and a real sample, so on a bare Linux box the entire .NET tool surface is
exercised only by unit tests calling the functions directly -- nothing drives
``dotnet.inspect`` / ``dotnet.enumerate`` / ``dotnet.il`` / ``dotnet.xrefs``
through the actual MCP server, and nothing proves the fail-closed contract at
the tool boundary.

This gate does, using three inputs that need no external tooling:

* a synthetic but genuinely verifiable CLR image (valid PE + COR20 + BSJB
  metadata root) built in the test -- the reader must verify it and read back
  real header facts, and the metadata tools must answer as the pure-Python
  ``dotnet_metadata`` backend (never claiming to be IDA);
* the committed ``fixtures/dotnet/minimal_clr_hint.exe``, which has a CLR
  directory hint but no verifiable metadata -- ``require_verified`` inspect and
  every metadata tool must fail closed with ``clr_unverified``, never crash and
  never reach for an external deobfuscator;
* a plain native PE -- ``dotnet.inspect`` must call it not-.NET.

Pure Python, any platform.
"""

from __future__ import annotations

import os
import struct
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_HINT_FIXTURE = _PROJECT_ROOT / "fixtures" / "dotnet" / "minimal_clr_hint.exe"


def _write_verified_clr_pe(path: Path) -> None:
    """A minimal PE carrying a COR20 header + BSJB metadata root (empty tables)."""
    image = bytearray(0x800)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def _write_native_pe(path: Path) -> None:
    """A minimal 64-bit PE with no CLR directory at all."""
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    path.write_bytes(image)


def _structured(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), result
    return content


class _Mcp:
    """Thin helper bound to a live MCP session."""

    def __init__(self, session: ClientSession) -> None:
        self._session = session

    async def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        return _structured(await self._session.call_tool(name, args))

    async def open(self, binary: Path) -> str:
        created = await self.call("session.create", {"binary": str(binary)})
        assert created["ok"] is True, created
        return str(created["data"]["session"]["id"])


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[_Mcp]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=str(_PROJECT_ROOT),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield _Mcp(session)


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_reader_verifies_and_reads_a_managed_assembly(tmp_path: Path) -> None:
    managed = tmp_path / "managed.exe"
    _write_verified_clr_pe(managed)

    async with _mcp(tmp_path / "artifacts") as mcp:
        session_id = await mcp.open(managed)

        inspected = await mcp.call(
            "dotnet.inspect", {"session_id": session_id, "require_verified": True}
        )
        assert inspected["ok"] is True, inspected
        data = inspected["data"]
        assert data["is_dotnet"] is True
        assert data["verified_clr"] is True
        assert data["kind"] == "pure_managed"
        assert data["runtime_major"] == 2 and data["runtime_minor"] == 5
        assert data["metadata_version"] == "v4.0.30319"
        assert data["entry_point_token"] == 0x06000001
        assert "ILONLY" in data["flags_decoded"]
        assert data["claims_universal_unpack"] is False

        # The metadata tools answer as the pure-Python backend, not IDA.
        types = await mcp.call("dotnet.enumerate", {"session_id": session_id, "kind": "types"})
        assert types["ok"] is True, types
        assert types["data"]["backend"] == "dotnet_metadata"
        assert types["data"]["not_ida_idalib"] is True
        assert types["data"]["claims_universal_unpack"] is False
        assert int(types["data"]["total"]) == 0  # empty tables, but a real read

        xrefs = await mcp.call("dotnet.xrefs", {"session_id": session_id})
        assert xrefs["ok"] is True, xrefs
        assert xrefs["data"]["kind"] == "xrefs"
        assert xrefs["data"]["not_ida_idalib"] is True

        # IL for a token that has no body degrades to a structured answer, never
        # a crash and never a claim to be a universal unpacker.
        il = await mcp.call("dotnet.il", {"session_id": session_id, "method_token": 0x06000001})
        assert isinstance(il["ok"], bool)
        if il["ok"]:
            assert il["data"]["backend"] == "dotnet_metadata"
        else:
            assert il["error"]["code"]


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_hint_only_assembly_fails_closed(tmp_path: Path) -> None:
    assert _HINT_FIXTURE.is_file(), f"committed fixture missing: {_HINT_FIXTURE}"

    async with _mcp(tmp_path / "artifacts") as mcp:
        session_id = await mcp.open(_HINT_FIXTURE)

        # Best-effort inspect recognises the CLR hint but will not verify it.
        soft = await mcp.call("dotnet.inspect", {"session_id": session_id})
        assert soft["ok"] is True, soft
        assert soft["data"]["is_dotnet"] is True
        assert soft["data"]["verified_clr"] is False
        assert soft["data"]["kind"] == "clr_directory_hint"

        # Verified inspect and every metadata tool refuse, with the same code.
        strict = await mcp.call(
            "dotnet.inspect", {"session_id": session_id, "require_verified": True}
        )
        assert strict["ok"] is False
        assert strict["error"]["code"] == "clr_unverified"

        for name, args in (
            ("dotnet.enumerate", {"kind": "methods"}),
            ("dotnet.il", {"method_token": 0x06000001}),
            ("dotnet.xrefs", {}),
        ):
            refused = await mcp.call(name, {"session_id": session_id, **args})
            assert refused["ok"] is False, (name, refused)
            assert refused["error"]["code"] == "clr_unverified", (name, refused)


@pytest.mark.integration
@pytest.mark.headless
@pytest.mark.asyncio
async def test_native_pe_is_reported_not_dotnet(tmp_path: Path) -> None:
    native = tmp_path / "native.exe"
    _write_native_pe(native)

    async with _mcp(tmp_path / "artifacts") as mcp:
        session_id = await mcp.open(native)

        soft = await mcp.call("dotnet.inspect", {"session_id": session_id})
        assert soft["ok"] is True, soft
        assert soft["data"]["is_dotnet"] is False
        assert soft["data"]["kind"] == "not_dotnet"

        strict = await mcp.call(
            "dotnet.inspect", {"session_id": session_id, "require_verified": True}
        )
        assert strict["ok"] is False
        assert strict["error"]["code"] == "not_dotnet"
