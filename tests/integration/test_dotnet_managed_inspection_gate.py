"""The .NET managed line, proven over MCP on a bare box with no external tools.

The pure-Python CLR reader (``dotnet.inspect`` / ``enumerate`` / ``il`` /
``xrefs``) is the part of the .NET surface that needs no de4dot and no real
sample -- it parses ECMA-335 metadata straight out of the image. Yet the
existing M6 gate (``test_dotnet_m6_gate.py``) skips in its entirety unless
``HEADLESS_RE_DE4DOT`` and a .NET binary are configured, and the metadata-enum
unit tests call ``AnalysisService`` directly. So on an ordinary Linux CI box the
managed surface had no end-to-end coverage at all, and none over the transport
an agent drives.

This gate closes that: it synthesizes a minimal but genuine managed PE (a real
COR20 header pointing at a ``BSJB`` metadata root, ECMA-335 II.24, ILONLY) and a
valid native PE with no CLR directory, then drives the real MCP stdio server
against both. It proves two halves:

* A managed image is recognized and readable: ``dotnet.inspect`` reports
  ``is_dotnet`` and ``verified_clr`` true with ``kind="pure_managed"``;
  ``dotnet.enumerate`` answers on every category from the ``dotnet_metadata``
  backend (not IDA); ``dotnet.xrefs`` answers; and asking for the IL of a token
  that is not in the tables is an honest ``not_found``, not a crash. Every reply
  carries ``claims_universal_unpack=False`` -- the surface never claims a
  magic unpacker.

* A native PE is turned away honestly, not misread: ``dotnet.inspect`` returns
  ``is_dotnet=False`` with ``kind="not_dotnet"`` (a clean answer, not an error),
  and every metadata tool refuses it with ``not_dotnet`` rather than pretending
  to parse managed structures that are not there.

The image layout is adapted from ``tests/unit/test_dotnet_metadata_enum.py``.
Pure stdlib, stdio loopback, no de4dot, no sample, any platform.
"""

from __future__ import annotations

import os
import struct
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from headless_re_mcp.core.service import JsonObject

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# A MethodDef token (0x06 table) that is not present in the empty tables, used to
# prove IL lookup fails cleanly rather than crashing.
_ABSENT_METHOD_TOKEN = 0x06000001


def _write_pe(path: Path, *, with_clr: bool) -> Path:
    """Write a valid PE64; with_clr adds a COR20 header and a BSJB metadata root.

    The optional-header, section, and data-directory layout is a minimal
    ECMA-335 / PE image sufficient for the pure-Python reader to parse. When
    with_clr is false the COM descriptor directory is left empty, so the file is
    a well-formed native PE with no managed metadata.
    """
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
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    if with_clr:
        # Data directory 14 is the COM descriptor: point it at the COR20 header.
        struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
        cor_off = 0x300
        struct.pack_into("<I", image, cor_off, 72)
        struct.pack_into("<HH", image, cor_off + 4, 2, 5)
        struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
        struct.pack_into("<I", image, cor_off + 16, 0x1)  # COMIMAGE_FLAGS_ILONLY
        struct.pack_into("<I", image, cor_off + 20, _ABSENT_METHOD_TOKEN)
        meta_off = 0x400
        version = b"v4.0.30319\0"
        version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
        image[meta_off : meta_off + 4] = b"BSJB"
        struct.pack_into("<HH", image, meta_off + 4, 1, 1)
        struct.pack_into("<I", image, meta_off + 8, 0)
        struct.pack_into("<I", image, meta_off + 12, len(version))
        image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
        cursor = meta_off + 16 + len(version_padded)
        struct.pack_into("<HH", image, cursor, 0, 0)  # stream count 0: empty tables
    path.write_bytes(image)
    return path


@asynccontextmanager
async def _mcp(tmp_path: Path) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(tmp_path / "artifacts")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=_PROJECT_ROOT,
    )
    async with (
        stdio_client(params) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


def _envelope(result: object) -> JsonObject:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"no structuredContent: {result!r}"
    return content


async def _open(client: ClientSession, path: Path) -> str:
    envelope = _envelope(await client.call_tool("session.create", {"binary": str(path)}))
    assert envelope["ok"] is True, envelope
    session = envelope["data"]["session"]
    assert session["target"] == "pe", session
    return str(session["id"])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_managed_assembly_is_recognized_and_readable(tmp_path: Path) -> None:
    managed = _write_pe(tmp_path / "managed.exe", with_clr=True)
    async with _mcp(tmp_path) as client:
        session_id = await _open(client, managed)

        inspect = _envelope(await client.call_tool("dotnet.inspect", {"session_id": session_id}))
        assert inspect["ok"] is True, inspect
        report = inspect["data"]
        assert report["is_dotnet"] is True, report
        assert report["verified_clr"] is True, report
        assert report["kind"] == "pure_managed", report
        assert report["claims_universal_unpack"] is False, report

        # The metadata backend answers on every category, and says plainly it is
        # the pure-Python reader, not IDA.
        for kind in ("types", "methods", "fields", "strings"):
            enumerated = _envelope(
                await client.call_tool(
                    "dotnet.enumerate", {"session_id": session_id, "kind": kind, "limit": 16}
                )
            )
            assert enumerated["ok"] is True, (kind, enumerated)
            page = enumerated["data"]
            assert page["backend"] == "dotnet_metadata", (kind, page)
            assert page["not_ida_idalib"] is True, (kind, page)
            assert page["claims_universal_unpack"] is False, (kind, page)
            assert isinstance(page["total"], int) and page["total"] >= 0, (kind, page)

        xrefs = _envelope(
            await client.call_tool("dotnet.xrefs", {"session_id": session_id, "limit": 16})
        )
        assert xrefs["ok"] is True, xrefs
        assert xrefs["data"]["kind"] == "xrefs", xrefs
        assert xrefs["data"]["not_ida_idalib"] is True, xrefs

        # IL for a token that is not in the tables is an honest miss, not a crash
        # or a fabricated method body.
        il = _envelope(
            await client.call_tool(
                "dotnet.il", {"session_id": session_id, "method_token": _ABSENT_METHOD_TOKEN}
            )
        )
        assert il["ok"] is False, il
        assert il["error"]["code"] == "not_found", il


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_native_pe_is_turned_away_honestly(tmp_path: Path) -> None:
    native = _write_pe(tmp_path / "native.exe", with_clr=False)
    async with _mcp(tmp_path) as client:
        session_id = await _open(client, native)

        # Not .NET is a clean answer, not an error: is_dotnet is False and the
        # kind names why.
        inspect = _envelope(await client.call_tool("dotnet.inspect", {"session_id": session_id}))
        assert inspect["ok"] is True, inspect
        report = inspect["data"]
        assert report["is_dotnet"] is False, report
        assert report["kind"] == "not_dotnet", report
        assert report["verified_clr"] is False, report

        # Every metadata tool refuses a non-managed PE with the same code rather
        # than trying to read tables that are not there.
        enumerated = _envelope(
            await client.call_tool(
                "dotnet.enumerate", {"session_id": session_id, "kind": "types", "limit": 16}
            )
        )
        assert enumerated["ok"] is False, enumerated
        assert enumerated["error"]["code"] == "not_dotnet", enumerated

        il = _envelope(
            await client.call_tool(
                "dotnet.il", {"session_id": session_id, "method_token": _ABSENT_METHOD_TOKEN}
            )
        )
        assert il["ok"] is False, il
        assert il["error"]["code"] == "not_dotnet", il

        xrefs = _envelope(
            await client.call_tool("dotnet.xrefs", {"session_id": session_id, "limit": 16})
        )
        assert xrefs["ok"] is False, xrefs
        assert xrefs["error"]["code"] == "not_dotnet", xrefs

        # And require_verified on inspect refuses rather than downgrading.
        strict = _envelope(
            await client.call_tool(
                "dotnet.inspect", {"session_id": session_id, "require_verified": True}
            )
        )
        assert strict["ok"] is False, strict
        assert strict["error"]["code"] == "not_dotnet", strict
