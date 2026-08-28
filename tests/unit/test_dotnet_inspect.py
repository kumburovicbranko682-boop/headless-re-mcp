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


def _build_metadata_root_with_names(module_name: bytes, assembly_name: bytes) -> bytes:
    """A BSJB blob with Module (0x00), TypeDef (0x02) and Assembly (0x20) rows.

    The Assembly row deliberately sits past the TypeDef table so a walker that
    stops at the first intervening table never reaches it.
    """
    strings = b"\0" + module_name + b"\0" + assembly_name + b"\0"
    module_name_idx = 1
    assembly_name_idx = 1 + len(module_name) + 1

    tables = bytearray()
    tables += b"\0\0\0\0"  # reserved
    tables += bytes([2, 0, 0, 0])  # major, minor, heap_sizes=0, reserved
    valid = (1 << 0x00) | (1 << 0x02) | (1 << 0x20)
    tables += valid.to_bytes(8, "little")
    tables += (0).to_bytes(8, "little")  # sorted
    tables += (1).to_bytes(4, "little")  # Module rows
    tables += (2).to_bytes(4, "little")  # TypeDef rows
    tables += (1).to_bytes(4, "little")  # Assembly rows
    # Module row: Generation(2) Name(2) Mvid(2) EncId(2) EncBaseId(2)
    tables += (0).to_bytes(2, "little") + module_name_idx.to_bytes(2, "little") + b"\0" * 6
    # Two TypeDef rows of 14 bytes each (contents irrelevant to this test)
    tables += b"\0" * (2 * 14)
    # Assembly row: HashAlgId(4) Ver(2*4) Flags(4) PublicKey(2) Name(2) Culture(2)
    tables += (0x8004).to_bytes(4, "little")  # HashAlgId (SHA1)
    tables += (1).to_bytes(2, "little") + b"\0" * 6  # Major=1, Minor/Build/Rev=0
    tables += (0).to_bytes(4, "little")  # Flags
    tables += (0).to_bytes(2, "little")  # PublicKey blob index
    tables += assembly_name_idx.to_bytes(2, "little")  # Name string index
    tables += (0).to_bytes(2, "little")  # Culture string index

    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - len(version) % 4) % 4)

    def _padded_name(name: bytes) -> bytes:
        raw = name + b"\0"
        return raw + b"\0" * ((4 - len(raw) % 4) % 4)

    tilde_name = _padded_name(b"#~")
    strings_name = _padded_name(b"#Strings")
    prefix_len = 16 + len(version_padded) + 4
    header_len = (8 + len(tilde_name)) + (8 + len(strings_name))
    data_start = prefix_len + header_len
    tilde_off = data_start
    strings_off = data_start + len(tables)

    root = bytearray()
    root += b"BSJB"
    root += (1).to_bytes(2, "little") + (1).to_bytes(2, "little")
    root += (0).to_bytes(4, "little")  # reserved
    root += len(version).to_bytes(4, "little")
    root += version_padded
    root += (0).to_bytes(2, "little")  # flags
    root += (2).to_bytes(2, "little")  # stream count
    root += tilde_off.to_bytes(4, "little") + len(tables).to_bytes(4, "little") + tilde_name
    root += strings_off.to_bytes(4, "little") + len(strings).to_bytes(4, "little") + strings_name
    return bytes(root) + bytes(tables) + strings


def _write_clr_pe_with_named_assembly(path: Path) -> None:
    """Verified CLR PE whose metadata carries Module and Assembly names."""
    meta = _build_metadata_root_with_names(b"MyModule.dll", b"MyAssembly")
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
    struct.pack_into("<I", image, cor_off, 72)  # cb
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)  # runtime 2.5
    struct.pack_into("<II", image, cor_off + 8, 0x1200, len(meta))  # metadata rva/size
    struct.pack_into("<I", image, cor_off + 16, 0x1)  # ILONLY
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)  # entry token

    meta_off = 0x400
    image[meta_off : meta_off + len(meta)] = meta
    path.write_bytes(image)


def test_inspect_resolves_assembly_name_past_intervening_tables(tmp_path: Path) -> None:
    # The Assembly table (0x20) follows TypeDef (0x02) in the row data; the
    # earlier hand-rolled walk stopped at TypeDef and reported no assembly name.
    path = tmp_path / "named.exe"
    _write_clr_pe_with_named_assembly(path)
    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.module_name == "MyModule.dll"
    assert report.assembly_name == "MyAssembly"
    assert report.metadata_stats is not None
    assert report.metadata_stats.type_count == 2


def test_read_identity_names_walks_to_the_assembly_row() -> None:
    from headless_re_mcp.dotnet import metadata_enum
    from headless_re_mcp.dotnet.clr_inspect import _parse_metadata_root

    meta = _build_metadata_root_with_names(b"Some.Module", b"Some.Assembly")
    _version, streams, module_name, assembly_name, stats = _parse_metadata_root(meta)
    assert "#~" in streams and "#Strings" in streams
    assert module_name == "Some.Module"
    assert assembly_name == "Some.Assembly"
    assert stats is not None and stats.type_count == 2

    names = metadata_enum.read_identity_names(meta, _stream_map_of(meta))
    assert names == ("Some.Module", "Some.Assembly")


def _stream_map_of(meta: bytes) -> dict[str, tuple[int, int]]:
    version_len = int.from_bytes(meta[12:16], "little")
    cursor = 16 + ((version_len + 3) & ~3)
    stream_count = int.from_bytes(meta[cursor + 2 : cursor + 4], "little")
    cursor += 4
    stream_map: dict[str, tuple[int, int]] = {}
    for _ in range(stream_count):
        offset = int.from_bytes(meta[cursor : cursor + 4], "little")
        size = int.from_bytes(meta[cursor + 4 : cursor + 8], "little")
        cursor += 8
        name_end = meta.find(b"\0", cursor)
        name = meta[cursor:name_end].decode("ascii")
        cursor += ((name_end - cursor + 1) + 3) & ~3
        stream_map[name] = (offset, size)
    return stream_map


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
