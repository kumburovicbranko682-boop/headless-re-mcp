"""Malformed-.NET no-incident gate over a real MCP stdio server.

The .NET managed surface (``dotnet.inspect``/``enumerate``/``il``) is a pure-Python
ECMA-335 reader with no external dependency, so it runs on any box -- and it
parses attacker-controlled bytes. The contract for such a parser is that every
malformed input becomes a structured verdict naming what is wrong, never an
``internal_error`` incident (the catch-all for a defect in this process), and
never a hang. A metadata table is free to claim two billion rows; the reader
must not believe it.

This pins that end-to-end over stdio, building the fixtures with the stdlib on a
known-valid minimal CLR PE and then corrupting only the CLR layer so the PE
itself still parses and the managed reader is actually reached:

  * A PE whose COM descriptor directory is empty is honestly ``not_dotnet`` and
    enumeration says so.
  * A PE that advertises a CLR directory but whose metadata is absent, not
    ``BSJB``, or truncated inspects as a directory *hint* and enumerates as
    ``clr_unverified`` -- the reader does not pretend the tables are there.
  * A ``#~`` table stream that declares 0x7fffffff rows behind a 48-byte body is
    bounded to the rows the stream can actually hold: enumeration returns a
    small total instead of materialising two billion rows (the documented guard
    against a 60 KB file eating gigabytes and tens of seconds).
  * ``dotnet.il`` rejects a non-MethodDef token and rid 0 as ``invalid_argument``
    and an out-of-range rid as ``not_found``.

A valid empty CLR shell is included as an anchor so the gate is not vacuously
rejecting everything upstream. No input, anywhere, is allowed to answer
``internal_error``. Pure-stdlib fixtures, stdio loopback, no backend, any platform.
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

# Data-directory index of the COM (CLR) descriptor and its offsets, so the tests
# can corrupt the CLR layer by name rather than magic numbers.
_PE_OFFSET = 0x80
_FILE_HEADER = _PE_OFFSET + 4
_OPTIONAL = _FILE_HEADER + 20
_DIR_BASE = _OPTIONAL + 112
_COR20_DIR = _DIR_BASE + 14 * 8
_COR_OFF = 0x300  # file offset of the COR20 header (RVA 0x1100)
_META_OFF = 0x400  # file offset of the metadata root (RVA 0x1200)


def _minimal_clr() -> bytearray:
    """A known-valid minimal managed PE: COR20 + BSJB, no metadata tables."""
    image = bytearray(0x800)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, _PE_OFFSET)
    image[_PE_OFFSET : _PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, _FILE_HEADER, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    struct.pack_into("<HBB", image, _OPTIONAL, 0x20B, 14, 0)
    struct.pack_into("<I", image, _OPTIONAL + 16, 0x1000)
    struct.pack_into("<Q", image, _OPTIONAL + 24, 0x140000000)
    struct.pack_into("<II", image, _OPTIONAL + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, _OPTIONAL + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, _OPTIONAL + 68, 3, 0x8160)
    struct.pack_into("<I", image, _OPTIONAL + 108, 16)
    struct.pack_into("<II", image, _COR20_DIR, 0x1100, 72)
    section = _OPTIONAL + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    struct.pack_into("<I", image, _COR_OFF, 72)
    struct.pack_into("<HH", image, _COR_OFF + 4, 2, 5)
    struct.pack_into("<II", image, _COR_OFF + 8, 0x1200, 0x40)  # metadata RVA, size
    struct.pack_into("<I", image, _COR_OFF + 16, 0x1)
    struct.pack_into("<I", image, _COR_OFF + 20, 0x06000001)
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[_META_OFF : _META_OFF + 4] = b"BSJB"
    struct.pack_into("<HH", image, _META_OFF + 4, 1, 1)
    struct.pack_into("<I", image, _META_OFF + 8, 0)
    struct.pack_into("<I", image, _META_OFF + 12, len(version))
    image[_META_OFF + 16 : _META_OFF + 16 + len(version_padded)] = version_padded
    cursor = _META_OFF + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)  # flags, stream_count = 0
    return image


def _name_pad(name: str) -> bytes:
    raw = name.encode() + b"\0"
    return raw + b"\0" * ((4 - (len(raw) % 4)) % 4)


def _make_metadata(streams: list[tuple[str, bytes]]) -> bytes:
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    head = bytearray(b"BSJB")
    head += struct.pack("<HH", 1, 1)
    head += struct.pack("<I", 0)
    head += struct.pack("<I", len(version))
    head += version_padded
    head += struct.pack("<HH", 0, len(streams))
    header_size = sum(8 + len(_name_pad(name)) for name, _ in streams)
    data_start = len(head) + header_size
    headers = bytearray()
    datas = bytearray()
    cursor = data_start
    for name, data in streams:
        headers += struct.pack("<II", cursor, len(data))
        headers += _name_pad(name)
        datas += data
        cursor += len(data)
    return bytes(head + headers + datas)


def _tables_stream(valid_bit: int, row_count: int, body: bytes) -> bytes:
    stream = bytearray()
    stream += struct.pack("<I", 0)  # reserved
    stream += struct.pack("<BB", 2, 0)  # major/minor version
    stream += struct.pack("<BB", 0, 0)  # heap sizes, reserved
    stream += struct.pack("<Q", 1 << valid_bit)  # valid table bitmask
    stream += struct.pack("<Q", 0)  # sorted bitmask
    stream += struct.pack("<I", row_count)  # the (possibly absurd) row count
    stream += body
    return bytes(stream)


def _native(path: Path) -> Path:
    image = _minimal_clr()
    struct.pack_into("<II", image, _COR20_DIR, 0, 0)  # no COM descriptor at all
    path.write_bytes(image)
    return path


def _cor_meta_empty(path: Path) -> Path:
    image = _minimal_clr()
    struct.pack_into("<II", image, _COR_OFF + 8, 0, 0)  # metadata RVA/size zeroed
    path.write_bytes(image)
    return path


def _not_bsjb(path: Path) -> Path:
    image = _minimal_clr()
    image[_META_OFF : _META_OFF + 4] = b"XXXX"
    path.write_bytes(image)
    return path


def _bsjb_truncated(path: Path) -> Path:
    image = _minimal_clr()
    struct.pack_into("<II", image, _COR_OFF + 8, 0x1200, 8)  # metadata size < 16
    path.write_bytes(image)
    return path


def _valid_empty(path: Path) -> Path:
    path.write_bytes(_minimal_clr())
    return path


def _huge_typedef_rows(path: Path) -> Path:
    image = _minimal_clr()
    meta = _make_metadata(
        [
            ("#~", _tables_stream(0x02, 0x7FFFFFFF, body=b"\0" * 48)),
            ("#Strings", b"\0name\0"),
        ]
    )
    assert len(meta) <= 0x1F0, len(meta)
    image[_META_OFF : _META_OFF + len(meta)] = meta
    struct.pack_into("<II", image, _COR_OFF + 8, 0x1200, len(meta))
    path.write_bytes(image)
    return path


def _envelope(result: object) -> dict[str, Any]:
    content = getattr(result, "structuredContent", None)
    assert isinstance(content, dict), f"expected a structured envelope, got {content!r}"
    return content


def _code(envelope: dict[str, Any]) -> str | None:
    error = envelope.get("error")
    return error.get("code") if isinstance(error, dict) else None


@asynccontextmanager
async def _mcp(artifact_root: Path) -> AsyncIterator[ClientSession]:
    env = os.environ.copy()
    env["HEADLESS_RE_ARTIFACT_ROOT"] = str(artifact_root)
    project_root = Path(__file__).resolve().parents[2]
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "headless_re_mcp", "serve"],
        env=env,
        cwd=project_root,
    )
    async with (
        stdio_client(parameters) as (read_stream, write_stream),
        ClientSession(read_stream, write_stream) as client,
    ):
        await client.initialize()
        yield client


async def _session(client: ClientSession, binary: str) -> str:
    created = _envelope(await client.call_tool("session.create", {"binary": binary}))
    assert created.get("ok") is True, created
    return str(created["data"]["session"]["id"])


@pytest.mark.integration
@pytest.mark.asyncio
async def test_malformed_clr_never_incidents_and_names_the_verdict(
    tmp_path: Path,
) -> None:
    fixtures = {
        "valid_empty": _valid_empty(tmp_path / "valid_empty.exe"),
        "native": _native(tmp_path / "native.exe"),
        "cor_meta_empty": _cor_meta_empty(tmp_path / "cor_meta_empty.exe"),
        "not_bsjb": _not_bsjb(tmp_path / "not_bsjb.exe"),
        "bsjb_truncated": _bsjb_truncated(tmp_path / "bsjb_truncated.exe"),
    }
    # (inspect is_dotnet, inspect kind, enumerate ok, enumerate code)
    expected = {
        "valid_empty": (True, "pure_managed", True, None),
        "native": (False, "not_dotnet", False, "not_dotnet"),
        "cor_meta_empty": (True, "clr_directory_hint", False, "clr_unverified"),
        "not_bsjb": (True, "clr_directory_hint", False, "clr_unverified"),
        "bsjb_truncated": (True, "clr_directory_hint", False, "clr_unverified"),
    }
    async with _mcp(tmp_path / "artifacts") as client:
        for name, path in fixtures.items():
            want_is_dotnet, want_kind, want_enum_ok, want_enum_code = expected[name]
            sid = await _session(client, str(path))

            inspect = _envelope(await client.call_tool("dotnet.inspect", {"session_id": sid}))
            assert _code(inspect) != "internal_error", (name, inspect)
            assert inspect.get("ok") is True, (name, inspect)
            assert inspect["data"]["is_dotnet"] is want_is_dotnet, (name, inspect)
            assert inspect["data"]["kind"] == want_kind, (name, inspect)

            enum = _envelope(
                await client.call_tool(
                    "dotnet.enumerate", {"session_id": sid, "kind": "types", "limit": 20}
                )
            )
            assert _code(enum) != "internal_error", (name, enum)
            assert enum.get("ok") is want_enum_ok, (name, enum)
            assert _code(enum) == want_enum_code, (name, enum)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_a_table_claiming_two_billion_rows_is_bounded_not_an_incident(
    tmp_path: Path,
) -> None:
    fixture = _huge_typedef_rows(tmp_path / "huge_rows.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        sid = await _session(client, str(fixture))
        # A 48-byte table body cannot hold two billion 16-byte rows. The reader
        # must return the rows the stream can actually hold (48 // 16 == 3),
        # promptly, rather than believing the header and materialising 2^31 rows.
        enum = _envelope(
            await client.call_tool(
                "dotnet.enumerate", {"session_id": sid, "kind": "types", "limit": 20}
            )
        )
        assert _code(enum) != "internal_error", enum
        assert enum.get("ok") is True, enum
        assert enum["data"]["total"] == 3, enum


@pytest.mark.integration
@pytest.mark.asyncio
async def test_dotnet_il_rejects_bad_tokens_structurally(tmp_path: Path) -> None:
    fixture = _valid_empty(tmp_path / "valid_empty.exe")
    async with _mcp(tmp_path / "artifacts") as client:
        sid = await _session(client, str(fixture))

        cases = [
            (0x02000001, "invalid_argument"),  # a TypeDef token, not a MethodDef
            (0x06000000, "invalid_argument"),  # MethodDef rid 0 is not a row
            (0x06009999, "not_found"),  # MethodDef rid past the (empty) table
        ]
        for token, expected_code in cases:
            envelope = _envelope(
                await client.call_tool(
                    "dotnet.il", {"session_id": sid, "method_token": token}
                )
            )
            assert _code(envelope) != "internal_error", (hex(token), envelope)
            assert envelope.get("ok") is False, (hex(token), envelope)
            assert _code(envelope) == expected_code, (hex(token), envelope)
