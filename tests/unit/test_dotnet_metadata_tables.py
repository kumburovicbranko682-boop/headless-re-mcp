"""Dotnet metadata parsing against a real (non-empty) #~ table stream.

Every prior fixture wrote ``valid = 0`` -- a BSJB root with no tables -- so the
ECMA-335 table walkers (`_table_row_size`, `_table_start`, the row iterators,
and clr_inspect's Module/Assembly name extraction) were never exercised
against actual rows. This fixture emits a byte-accurate metadata stream with
Module, TypeDef, Field, MethodDef (tiny IL body) and Assembly tables plus a
#Strings heap, so the walkers are tested end to end from a file on disk.
"""

from __future__ import annotations

import struct
import time
import tracemalloc
from pathlib import Path

import pytest

from headless_re_mcp.dotnet.clr_inspect import inspect_dotnet
from headless_re_mcp.dotnet.metadata_enum import (
    disassemble_method_il,
    enumerate_metadata,
    list_memberref_xrefs,
)

_METHOD_BODY_RVA = 0x1180
_METHOD_BODY_FILE = 0x380


def _build_strings_heap() -> tuple[bytes, dict[str, int]]:
    heap = bytearray(b"\0")
    indexes: dict[str, int] = {}
    for name in ("MyModule.exe", "Program", "MyApp", "Main", "counter", "ToString", "MyAssembly"):
        indexes[name] = len(heap)
        heap.extend(name.encode("ascii") + b"\0")
    return bytes(heap), indexes


def _build_tables_stream(idx: dict[str, int], *, typedef_declared: int = 1) -> bytes:
    tables = bytearray()
    # reserved(4), major, minor, heap_sizes (all 2-byte heap indexes), reserved
    tables += struct.pack("<IBBBB", 0, 2, 0, 0x00, 1)
    valid = (
        (1 << 0x00) | (1 << 0x02) | (1 << 0x04) | (1 << 0x06) | (1 << 0x0A) | (1 << 0x20)
    )
    tables += struct.pack("<QQ", valid, 0)
    # Row counts in ascending table order; TypeDef's declared count is overridable
    # so a crafted file can claim far more rows than the stream actually holds.
    tables += struct.pack("<IIIIII", 1, typedef_declared, 1, 1, 1, 1)
    # Module: Generation, Name, Mvid, EncId, EncBaseId
    tables += struct.pack("<HHHHH", 0, idx["MyModule.exe"], 1, 0, 0)
    # TypeDef: Flags, Name, Namespace, Extends, FieldList, MethodList
    tables += struct.pack("<IHHHHH", 0x00100001, idx["Program"], idx["MyApp"], 0, 1, 1)
    # Field: Flags, Name, Signature
    tables += struct.pack("<HHH", 0x0016, idx["counter"], 0)
    # MethodDef: RVA, ImplFlags, Flags, Name, Signature, ParamList
    tables += struct.pack("<IHHHHH", _METHOD_BODY_RVA, 0, 0x0096, idx["Main"], 0, 1)
    # MemberRef: Class (MemberRefParent -> TypeDef rid 1 == (1<<3)|0), Name, Signature
    tables += struct.pack("<HHH", (1 << 3) | 0, idx["ToString"], 0)
    # Assembly: HashAlgId, Major, Minor, Build, Revision, Flags, PublicKey, Name, Culture
    tables += struct.pack("<IHHHHIHHH", 0x8004, 1, 2, 3, 4, 0, 0, idx["MyAssembly"], 0)
    return bytes(tables)


def _build_metadata_root(*, typedef_declared: int = 1) -> bytes:
    strings_heap, idx = _build_strings_heap()
    tables = _build_tables_stream(idx, typedef_declared=typedef_declared)
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - len(version) % 4) % 4)
    root = bytearray()
    root += b"BSJB"
    root += struct.pack("<HHI", 1, 1, 0)
    root += struct.pack("<I", len(version))
    root += version_padded
    root += struct.pack("<HH", 0, 2)  # flags, stream count
    header_area = (8 + 4) + (8 + 12)  # "#~\0" pads to 4; "#Strings\0" pads to 12
    tables_off = len(root) + header_area
    strings_off = tables_off + len(tables)
    root += struct.pack("<II", tables_off, len(tables)) + b"#~\0\0"
    root += struct.pack("<II", strings_off, len(strings_heap)) + b"#Strings\0\0\0\0"
    root += tables
    root += strings_heap
    return bytes(root)


def _write_clr_with_tables(path: Path, *, typedef_declared: int = 1) -> None:
    """PE64 with COR20 + BSJB metadata carrying real table rows in .text."""
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
    # RVA 0x1000..0x1800 maps to file 0x200..0xA00
    struct.pack_into("<IIII", image, section + 8, 0x800, 0x1000, 0x800, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    metadata = _build_metadata_root(typedef_declared=typedef_declared)
    # COR20 at file 0x300 / RVA 0x1100
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(metadata))
    struct.pack_into("<I", image, cor_off + 16, 0x1)  # ILONLY
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    # Tiny-format method body for MethodDef rid 1: ldc.i4.0; ret
    image[_METHOD_BODY_FILE : _METHOD_BODY_FILE + 3] = bytes([(2 << 2) | 0x2, 0x16, 0x2A])
    # BSJB metadata root at file 0x400 / RVA 0x1200
    image[0x400 : 0x400 + len(metadata)] = metadata
    path.write_bytes(image)


def test_enumerate_types_methods_fields_from_real_tables(tmp_path: Path) -> None:
    binary = tmp_path / "tables.exe"
    _write_clr_with_tables(binary)

    types = enumerate_metadata(binary, "types", limit=10)
    assert types.total == 1
    assert types.items[0]["token"] == 0x02000001
    assert types.items[0]["name"] == "Program"
    assert types.items[0]["namespace"] == "MyApp"

    methods = enumerate_metadata(binary, "methods", limit=10)
    assert methods.total == 1
    assert methods.items[0]["token"] == 0x06000001
    assert methods.items[0]["name"] == "Main"
    assert methods.items[0]["rva"] == _METHOD_BODY_RVA

    fields = enumerate_metadata(binary, "fields", limit=10)
    assert fields.total == 1
    assert fields.items[0]["token"] == 0x04000001
    assert fields.items[0]["name"] == "counter"


def test_strings_heap_enumeration_lists_interned_names(tmp_path: Path) -> None:
    binary = tmp_path / "tables.exe"
    _write_clr_with_tables(binary)
    page = enumerate_metadata(binary, "strings", limit=50)
    values = {item["value"] for item in page.items}
    assert {"MyModule.exe", "Program", "MyApp", "Main", "counter", "MyAssembly"} <= values


def test_disassemble_tiny_method_body(tmp_path: Path) -> None:
    binary = tmp_path / "tables.exe"
    _write_clr_with_tables(binary)
    result = disassemble_method_il(binary, 0x06000001)
    assert result["header"]["format"] == "tiny"
    assert result["header"]["code_size"] == 2
    assert [insn["mnemonic"] for insn in result["instructions"]] == ["ldc.i4.0", "ret"]
    assert result["partial"] is False


def test_memberref_xrefs_from_real_tables(tmp_path: Path) -> None:
    binary = tmp_path / "tables.exe"
    _write_clr_with_tables(binary)
    page = list_memberref_xrefs(binary, limit=10)
    assert page.kind == "xrefs"
    assert page.total == 1
    row = page.items[0]
    assert row["token"] == 0x0A000001
    assert row["name"] == "ToString"
    # Class is a MemberRefParent coded index at TypeDef rid 1 (tag 0).
    assert row["class_coded_index"] == (1 << 3) | 0


def test_inspect_reports_module_and_assembly_names(tmp_path: Path) -> None:
    binary = tmp_path / "tables.exe"
    _write_clr_with_tables(binary)
    report = inspect_dotnet(binary, require_verified=True)
    assert report.verified_clr is True
    assert report.module_name == "MyModule.exe"
    assert report.assembly_name == "MyAssembly"
    stats = report.metadata_stats
    assert stats is not None
    assert stats.type_count == 1
    assert stats.method_count == 1
    assert stats.field_count == 1


@pytest.mark.parametrize("declared", [0x7FFFFFFF, 0xFFFFFFFF])
def test_declared_typedef_rows_cannot_exceed_the_stream(declared: int, tmp_path: Path) -> None:
    """A crafted row count must not drive unbounded materialisation.

    The sibling test_metadata_hostile_tables.py mutates a real managed DLL to
    prove `_rows_the_stream_can_hold` caps this, but it skips wherever that DLL
    is absent (this environment included), so the DoS guard had no active test
    here. The synthetic assembly reproduces it: a TypeDef table declaring two
    billion rows still enumerates in bounded time and heap from a tiny file.
    """
    binary = tmp_path / "hostile.exe"
    _write_clr_with_tables(binary, typedef_declared=declared)

    tracemalloc.start()
    started = time.perf_counter()
    page = enumerate_metadata(binary, "types", limit=20)
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert elapsed < 5.0, f"{declared:#x} rows took {elapsed:.1f}s"
    assert peak < 64 * 1024 * 1024, f"{declared:#x} rows took {peak / 1024 / 1024:.0f} MB"
    assert page.total < 100_000, f"reported {page.total} rows from a tiny file"
    assert len(page.items) <= 20
