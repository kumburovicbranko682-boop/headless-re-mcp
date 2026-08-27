"""M6.1 CLR inspect unit tests."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError, DotnetKind, inspect_dotnet


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


def _tables_stream_with_named_assembly(assembly_name_index: int) -> bytes:
    """A ``#~`` blob: Module + several tables + Assembly, 2-byte heap indexes.

    Assembly (0x20) trails TypeRef/TypeDef/MethodDef/MemberRef/CustomAttribute,
    so reaching its Name means every one of those rows must be sized correctly.
    """

    def u16(n: int) -> bytes:
        return int(n).to_bytes(2, "little")

    def u32(n: int) -> bytes:
        return int(n).to_bytes(4, "little")

    present = (0x00, 0x01, 0x02, 0x06, 0x0A, 0x0C, 0x20)
    valid = 0
    for bit in present:
        valid |= 1 << bit
    blob = bytearray()
    blob += u32(0) + bytes([2, 0]) + bytes([0]) + bytes([1])  # reserved/ver/heapsizes=0/reserved
    blob += valid.to_bytes(8, "little") + (0).to_bytes(8, "little")  # Valid + Sorted
    for _bit in sorted(present):
        blob += u32(1)  # one row per present table
    blob += u16(0) + u16(1) + u16(0) + u16(0) + u16(0)  # Module: Gen, Name=1, 3×Mvid
    blob += u16(0) + u16(0) + u16(0)  # TypeRef: ResolutionScope, Name, Namespace
    blob += u32(0) + u16(0) + u16(0) + u16(0) + u16(1) + u16(1)  # TypeDef
    blob += u32(0) + u16(0) + u16(0) + u16(0) + u16(0) + u16(1)  # MethodDef
    blob += u16(0) + u16(0) + u16(0)  # MemberRef
    blob += u16(0) + u16(0) + u16(0)  # CustomAttribute
    blob += (  # Assembly: HashAlg, 4×version, Flags, PublicKey, Name, Culture
        u32(0) + u16(1) + u16(0) + u16(0) + u16(0) + u32(0) + u16(0)
        + u16(assembly_name_index) + u16(0)
    )
    return bytes(blob)


def _write_clr_with_named_assembly(path: Path) -> None:
    """Verified PE whose metadata carries a real Assembly row with a name."""
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

    heap = b"\x00MyModule.dll\x00MyAssembly\x00"
    tables = _tables_stream_with_named_assembly(heap.find(b"MyAssembly"))
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)

    def stream_name(name: str) -> bytes:
        raw = name.encode("ascii") + b"\0"
        return raw + b"\0" * ((4 - (len(raw) % 4)) % 4)

    tilde_name = stream_name("#~")
    strings_name = stream_name("#Strings")
    root_len = 16 + len(version_padded)
    header_len = root_len + 4 + (8 + len(tilde_name)) + (8 + len(strings_name))
    tilde_off = header_len
    strings_off = tilde_off + len(tables)

    md = bytearray()
    md += b"BSJB" + struct.pack("<HH", 1, 1) + struct.pack("<I", 0)
    md += struct.pack("<I", len(version)) + version_padded
    md += struct.pack("<HH", 0, 2)  # flags + stream count
    md += struct.pack("<II", tilde_off, len(tables)) + tilde_name
    md += struct.pack("<II", strings_off, len(heap)) + strings_name
    md += tables + heap
    assert len(md) <= 0x200

    meta_off = 0x400
    image[meta_off : meta_off + len(md)] = md
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(md))
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    path.write_bytes(image)


def test_inspect_reports_assembly_name_behind_intervening_tables(tmp_path: Path) -> None:
    """assembly_name must survive the walk past TypeRef/TypeDef/etc.

    The old table walk broke out of its loop at the first table it could not
    size -- always TypeRef or TypeDef -- so it never reached the Assembly table
    and assembly_name came back null for essentially every real assembly, even
    though the field is advertised in the report.
    """
    path = tmp_path / "named.exe"
    _write_clr_with_named_assembly(path)
    report = inspect_dotnet(path, require_verified=True)
    assert report.verified_clr is True
    assert report.module_name == "MyModule.dll"
    assert report.assembly_name == "MyAssembly"
    assert report.metadata_stats is not None
    assert report.metadata_stats.type_count == 1


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
