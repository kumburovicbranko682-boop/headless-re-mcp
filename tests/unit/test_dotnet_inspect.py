"""M6.1 CLR inspect unit tests."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.clr_inspect import (
    DotnetInspectError,
    DotnetKind,
    _parse_metadata_root,
    inspect_dotnet,
)


def _write_native_pe(path: Path) -> None:
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


def _write_verified_clr_pe(path: Path) -> None:
    """Minimal PE with COR20 + BSJB in .text (no full metadata tables)."""
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
    # COM descriptor -> RVA 0x1100 (file 0x300)
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)

    # COR20 at file 0x300 / RVA 0x1100
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)  # cb
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)  # runtime 2.5
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)  # metadata
    struct.pack_into("<I", image, cor_off + 16, 0x1)  # ILONLY
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)  # entry token

    # BSJB at file 0x400 / RVA 0x1200
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)  # flags + 0 streams
    path.write_bytes(image)


def _metadata_with_assembly_table() -> bytes:
    """BSJB metadata whose #~ stream holds Module, TypeRef, TypeDef, Assembly."""
    strings_heap = b"\0Payload.dll\0Payload\0"
    module_name_idx = 1  # "Payload.dll"
    assembly_name_idx = 13  # "Payload"

    rows = bytearray()
    # Module: Generation + Name + Mvid + EncId + EncBaseId
    rows += struct.pack("<HHHHH", 0, module_name_idx, 0, 0, 0)
    # TypeRef: ResolutionScope + Name + Namespace
    rows += struct.pack("<HHH", 0, 0, 0)
    # TypeDef: Flags + Name + Namespace + Extends + FieldList + MethodList
    rows += struct.pack("<IHHHHH", 0, 0, 0, 0, 1, 1)
    # Assembly: HashAlgId + Version(4x2) + Flags + PublicKey + Name + Culture
    rows += struct.pack("<IHHHHIHHH", 0x8004, 1, 2, 3, 4, 0, 0, assembly_name_idx, 0)

    valid = (1 << 0x00) | (1 << 0x01) | (1 << 0x02) | (1 << 0x20)
    tables_stream = bytearray()
    tables_stream += struct.pack("<IBBBB", 0, 2, 0, 0, 1)  # reserved, ver 2.0, HeapSizes, reserved
    tables_stream += struct.pack("<QQ", valid, 0)  # Valid, Sorted
    tables_stream += struct.pack("<IIII", 1, 1, 1, 1)  # one row per present table
    tables_stream += rows

    version = b"v4.0.30319\0\0"  # 4-byte aligned
    root = bytearray()
    root += b"BSJB"
    root += struct.pack("<HHI", 1, 1, 0)
    root += struct.pack("<I", len(version))
    root += version
    root += struct.pack("<HH", 0, 2)  # flags, stream count
    headers_at = len(root)
    root += b"\0" * (8 + 4)  # "#~" header: offset + size + name padded to 4
    root += b"\0" * (8 + 12)  # "#Strings" header: offset + size + name padded to 12
    tables_off = len(root)
    root += tables_stream
    strings_off = len(root)
    root += strings_heap
    struct.pack_into("<II", root, headers_at, tables_off, len(tables_stream))
    root[headers_at + 8 : headers_at + 11] = b"#~\0"
    struct.pack_into("<II", root, headers_at + 12, strings_off, len(strings_heap))
    root[headers_at + 20 : headers_at + 29] = b"#Strings\0"
    return bytes(root)


def test_assembly_name_survives_tables_between_module_and_assembly() -> None:
    """assembly_name must come out even with TypeRef/TypeDef in between.

    Real assemblies always carry tables between Module (0x00) and Assembly
    (0x20). The old walk bailed at the first table it did not know how to
    skip, so module_name worked while assembly_name was null for every real
    input -- exactly the shape this metadata reproduces.
    """
    version, streams, module_name, assembly_name, stats = _parse_metadata_root(
        _metadata_with_assembly_table()
    )
    assert version == "v4.0.30319"
    assert streams == ["#~", "#Strings"]
    assert module_name == "Payload.dll"
    assert assembly_name == "Payload"
    assert stats is not None
    assert stats.type_count == 1


def test_inspect_native_pe(tmp_path: Path) -> None:
    path = tmp_path / "native.exe"
    _write_native_pe(path)
    report = inspect_dotnet(path)
    assert report.is_dotnet is False
    assert report.kind is DotnetKind.NOT_DOTNET
    try:
        inspect_dotnet(path, require_verified=True)
        raise AssertionError("expected DotnetInspectError")
    except DotnetInspectError as exc:
        assert exc.code == "not_dotnet"


def test_inspect_does_not_use_an_unbounded_second_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "native.exe"
    _write_native_pe(path)

    def unbounded_read_forbidden(_path: Path) -> bytes:
        raise AssertionError("dotnet inspection must not call read_bytes()")

    monkeypatch.setattr(Path, "read_bytes", unbounded_read_forbidden)
    assert inspect_dotnet(path).kind is DotnetKind.NOT_DOTNET


def test_inspect_clr_hint_fixture() -> None:
    path = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_clr_hint.exe"
    report = inspect_dotnet(path)
    assert report.is_dotnet is True
    assert report.kind is DotnetKind.CLR_HINT
    assert report.verified_clr is False
    try:
        inspect_dotnet(path, require_verified=True)
        raise AssertionError("expected DotnetInspectError")
    except DotnetInspectError as exc:
        assert exc.code == "clr_unverified"


def test_inspect_verified_cor20_bsjb(tmp_path: Path) -> None:
    path = tmp_path / "managed.exe"
    _write_verified_clr_pe(path)
    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.kind is DotnetKind.PURE_MANAGED
    assert report.runtime_major == 2
    assert report.runtime_minor == 5
    assert report.metadata_version == "v4.0.30319"
    assert report.entry_point_token == 0x06000001
    assert "ILONLY" in report.flags_decoded


def test_service_dotnet_inspect(tmp_path: Path) -> None:
    path = tmp_path / "managed.exe"
    _write_verified_clr_pe(path)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    session_id = service.create_session(str(path)).data["session"]["id"]
    result = service.dotnet_inspect(session_id, require_verified=True)
    assert result.ok and result.data is not None
    assert result.data["verified_clr"] is True
    assert result.data["claims_universal_unpack"] is False
