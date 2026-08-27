"""M6.4 metadata enumeration unit tests."""

from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.metadata_enum import CAPABILITY, _disassemble_il, enumerate_metadata


def _write_minimal_clr(path: Path) -> None:
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


def test_enumerate_empty_tables_is_ok(tmp_path: Path) -> None:
    binary = tmp_path / "empty_tables.exe"
    _write_minimal_clr(binary)
    page = enumerate_metadata(binary, "types", limit=10)
    assert page.capability == CAPABILITY
    assert page.total == 0
    assert page.backend == "dotnet_metadata"
    assert page.claims_universal_unpack is False


def test_il_branch_and_constant_operands_are_signed() -> None:
    """A backward branch is a negative offset, not a four-billion one.

    ldc.i4 and both branch widths carry signed operands in ECMA-335. Only the
    short branches were decoded signed, so a long ``br`` to a target ten bytes
    back printed as 4294967286 and a ``ldc.i4 -1`` as 4294967295 -- the value an
    agent reads to follow a loop was its two's-complement bit pattern instead.
    """
    il = (
        bytes([0x38])
        + (-10).to_bytes(4, "little", signed=True)  # br -10 (long, backward)
        + bytes([0x20])
        + (-1).to_bytes(4, "little", signed=True)  # ldc.i4 -1
        + bytes([0x2B])
        + (-2).to_bytes(1, "little", signed=True)  # br.s -2 (short, was already signed)
        + bytes([0x28])
        + (0x0A000001).to_bytes(4, "little")  # call token stays unsigned
    )

    instructions, partial = _disassemble_il(il, max_insns=16)

    decoded = [(insn["mnemonic"], insn["operand"]) for insn in instructions]
    assert decoded == [
        ("br", -10),
        ("ldc.i4", -1),
        ("br.s", -2),
        ("call", 0x0A000001),
    ]
    assert partial is False


def test_service_enumerate_and_xrefs_surface(tmp_path: Path) -> None:
    binary = tmp_path / "empty_tables.exe"
    _write_minimal_clr(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    enumerated = service.dotnet_enumerate(session_id, "strings", limit=5)
    assert enumerated.ok
    assert enumerated.data is not None
    assert enumerated.data["not_ida_idalib"] is True
    xrefs = service.dotnet_xrefs(session_id, limit=5)
    assert xrefs.ok
    assert xrefs.data is not None
    assert xrefs.data["kind"] == "xrefs"


def _padded_stream_name(name: bytes) -> bytes:
    raw = name + b"\0"
    return raw + b"\0" * ((4 - len(raw) % 4) % 4)


# index 0 is the empty string; the TypeDef rows below point at these offsets.
_STRINGS_HEAP = b"\0Alpha\0Beta\0Ns\0"
_ALPHA, _BETA, _NS = 1, 7, 12


def _typedef_row(name_index: int, namespace_index: int, extends_size: int) -> bytes:
    """One TypeDef row: Flags, Name, Namespace, Extends, FieldList, MethodList."""
    fixed = struct.pack("<IHH", 0, name_index, namespace_index)
    extends = b"\0" * extends_size
    lists = struct.pack("<HH", 1, 1)
    return fixed + extends + lists


def _write_clr_with_typedef_table(
    path: Path, *, declared_rows: int, row_data: bytes
) -> None:
    """A hermetic verified CLR whose #~ TypeDef table declares ``declared_rows``.

    Mirrors ``_write_minimal_clr`` but carries a real ``#~`` tables stream (only
    the TypeDef bit set) plus a ``#Strings`` heap, so ``enumerate_metadata`` runs
    its full table walk without an external assembly fixture. ``declared_rows`` is
    the attacker-controlled count in the stream header; ``row_data`` is the bytes
    actually present after it.
    """
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - len(version) % 4) % 4)
    root_prefix = (
        b"BSJB"
        + struct.pack("<HH", 1, 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", len(version))
        + version_padded
        + struct.pack("<HH", 0, 2)  # metadata flags, stream count = 2
    )
    strings_heap = _STRINGS_HEAP + b"\0" * ((4 - len(_STRINGS_HEAP) % 4) % 4)

    tilde = (
        struct.pack("<I", 0)  # reserved
        + struct.pack("<BB", 2, 0)  # schema major, minor
        + struct.pack("<BB", 0, 1)  # heap sizes (all 2-byte indices), reserved
        + struct.pack("<Q", 1 << 0x02)  # valid: TypeDef only
        + struct.pack("<Q", 0)  # sorted
        + struct.pack("<I", declared_rows)  # TypeDef row count
        + row_data
    )
    # #Strings header (20 bytes) + #~ header (12 bytes) follow the root prefix.
    data_start = len(root_prefix) + 20 + 12
    strings_off = data_start
    tilde_off = strings_off + len(strings_heap)
    stream_headers = (
        struct.pack("<II", strings_off, len(strings_heap))
        + _padded_stream_name(b"#Strings")
        + struct.pack("<II", tilde_off, len(tilde))
        + _padded_stream_name(b"#~")
    )
    metadata = root_prefix + stream_headers + strings_heap + tilde

    image = bytearray(0x1000)
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
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(metadata))
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    if meta_off + len(metadata) > 0x600:
        raise AssertionError("synthetic metadata overran the .text raw range")
    image[meta_off : meta_off + len(metadata)] = metadata
    path.write_bytes(image)


def test_enumerate_reads_an_honest_typedef_table(tmp_path: Path) -> None:
    """The synthetic #~ walk resolves names when the count is truthful."""
    binary = tmp_path / "honest.dll"
    rows = _typedef_row(_ALPHA, _NS, 2) + _typedef_row(_BETA, _NS, 2)
    _write_clr_with_typedef_table(binary, declared_rows=2, row_data=rows)

    page = enumerate_metadata(binary, kind="types", offset=0, limit=20)

    assert page.total == 2
    assert [item["name"] for item in page.items] == ["Alpha", "Beta"]
    assert {item["namespace"] for item in page.items} == {"Ns"}


@pytest.mark.parametrize("declared", [0x7FFFFFFF, 0xFFFFFFFF])
def test_typedef_table_cannot_declare_more_rows_than_its_stream_holds(
    declared: int, tmp_path: Path
) -> None:
    """A declared row count over the stream's capacity must not be materialised.

    ``enumerate_metadata`` builds the whole table into a list before paging it, so
    the declared count decides the work a request for twenty items does. A table
    claiming 0x7fffffff rows would otherwise run for tens of seconds and take over
    a gigabyte of heap; the walker instead bounds the count to the bytes the #~
    stream can actually hold. This pins that end to end without the managed-binary
    fixture that keeps the sibling test skipped in CI.
    """
    binary = tmp_path / f"hostile_{declared:x}.dll"
    # A large declared TypeDef count widens the coded Extends index to 4 bytes,
    # so each row is 16 bytes; three rows' worth is all that is really present.
    _write_clr_with_typedef_table(
        binary, declared_rows=declared, row_data=b"\0" * (16 * 3)
    )

    started = time.perf_counter()
    page = enumerate_metadata(binary, kind="types", offset=0, limit=20)
    elapsed = time.perf_counter() - started

    assert elapsed < 5.0, f"{declared:#x} rows took {elapsed:.1f}s"
    assert page.total <= 3, f"reported {page.total} rows from a handful of bytes"
    assert len(page.items) <= 20
    assert page.truncated is False
