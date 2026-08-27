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
    # This synthetic image carries no TargetFrameworkAttribute; the fact is
    # None rather than invented -- pre-4.0 and hand-built assemblies are real.
    assert report.target_framework is None


def test_inspect_reads_assembly_name_past_intervening_tables() -> None:
    """Assembly (0x20) sits behind TypeDef/Field/MethodDef in every real image.

    The name walker used to bail at the first table it could not size -- the
    TypeDef right after Module -- so ``assembly_name`` came back None for any
    genuine assembly. It must now step over the intervening tables and read the
    real name from the committed multi-table fixture.
    """
    fixture = (
        Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    )
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    report = inspect_dotnet(fixture, require_verified=True)
    assert report.module_name == "MyModule.dll"
    assert report.assembly_name == "MyAssembly"
    # The Assembly table's four-part version and the Module table's MVID are the
    # managed identity facts triage keys off; both must come back from the real
    # tables, not None. The MVID is the fixed value the builder stamps in.
    assert report.assembly_version == "1.0.0.0"
    assert report.mvid == "8b8a2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
    assert report.metadata_stats is not None
    assert report.metadata_stats.type_count == 2
    assert report.metadata_stats.method_count == 2
    # The AssemblyRef table is the managed DT_NEEDED: which assemblies this one
    # links against, with the version each was compiled for. The fixture
    # references the runtime library the way every real compiler output does.
    assert report.assembly_refs == ({"name": "mscorlib", "version": "4.0.0.0"},)
    # And the report dict carries it for clients.
    assert report.to_dict()["assembly_refs"] == [{"name": "mscorlib", "version": "4.0.0.0"}]
    # The ModuleRef table is the native complement: the unmanaged DLLs the
    # assembly P/Invokes into. The fixture binds one the way a P/Invoke build
    # does. That this and assembly_refs (which sit on opposite sides of the
    # ModuleRef row) both read correctly proves the new row is sized right.
    assert report.module_refs == ("kernel32.dll",)
    assert report.to_dict()["module_refs"] == ["kernel32.dll"]
    # The TargetFrameworkAttribute the builder stamps on the assembly: reading
    # it walks TypeRef -> MemberRef -> CustomAttribute and decodes the value
    # blob's SerString from #Blob -- the platform the build targets, the
    # managed analogue of Mach-O's LC_BUILD_VERSION.
    assert report.target_framework == ".NETFramework,Version=v4.8"
    assert report.to_dict()["target_framework"] == ".NETFramework,Version=v4.8"


def _rowcount_offset(raw: bytes, table_bit: int) -> int:
    """File offset of a table's row count inside the fixture's #~ header.

    Located from the file's own structures (CLI directory -> metadata root ->
    #~ stream -> valid mask) rather than hardcoded, the same way the hostile
    TypeDef mutation does, so it survives fixture regeneration.
    """
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    cli_rva = struct.unpack_from("<I", raw, directories + 14 * 8)[0]
    # The fixture is a single-section PE: RVA 0x2000 maps to file 0x200.
    cli = cli_rva - 0x2000 + 0x200
    meta = struct.unpack_from("<I", raw, cli + 8)[0] - 0x2000 + 0x200
    version_length = struct.unpack_from("<I", raw, meta + 12)[0]
    cursor = meta + 16 + version_length
    streams = struct.unpack_from("<H", raw, cursor + 2)[0]
    cursor += 4
    tilde = -1
    for _ in range(streams):
        offset = struct.unpack_from("<I", raw, cursor)[0]
        name_start = cursor + 8
        end = raw.index(b"\0", name_start)
        cursor = name_start + ((end - name_start) // 4 + 1) * 4
        if raw[name_start:end] == b"#~":
            tilde = meta + offset
    assert tilde >= 0, "no #~ stream in the fixture"
    valid = struct.unpack_from("<Q", raw, tilde + 8)[0]
    assert valid & (1 << table_bit), f"fixture has no table 0x{table_bit:02x}"
    ordinal = bin(valid & ((1 << table_bit) - 1)).count("1")
    return tilde + 24 + ordinal * 4


def test_a_lying_assemblyref_count_stays_bounded(tmp_path: Path) -> None:
    # The row count is attacker-controlled input; a claim of two billion refs
    # must neither allocate for the claim nor crash the walk. What parses
    # before the liar (Module and Assembly, both earlier tables) still comes
    # back; the refs themselves cap at the honest-world bound.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    offset = _rowcount_offset(bytes(raw), 0x23)
    struct.pack_into("<I", raw, offset, 0x7FFFFFFF)
    path = tmp_path / "liar_refs.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.module_name == "MyModule.dll"
    assert report.assembly_name == "MyAssembly"
    assert len(report.assembly_refs) <= 64


def test_a_lying_moduleref_count_stays_bounded(tmp_path: Path) -> None:
    # ModuleRef's row count is attacker-controlled too; the native-dependency
    # walk caps at the honest bound rather than allocating for a giant claim,
    # exactly as the AssemblyRef walk does.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    struct.pack_into("<I", raw, _rowcount_offset(bytes(raw), 0x1A), 0x7FFFFFFF)
    path = tmp_path / "liar_modrefs.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert len(report.module_refs) <= 64


def test_a_lying_customattribute_count_stays_bounded(tmp_path: Path) -> None:
    # The CustomAttribute row count is attacker-controlled like every other:
    # a two-billion claim must not stall or crash the TargetFramework walk.
    # The one honest row still reads (it comes first and the walk stops on the
    # match), and everything the liar sits in front of still parses.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    struct.pack_into("<I", raw, _rowcount_offset(bytes(raw), 0x0C), 0x7FFFFFFF)
    path = tmp_path / "liar_customattrs.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.target_framework == ".NETFramework,Version=v4.8"


def test_a_corrupt_framework_blob_reads_as_none(tmp_path: Path) -> None:
    # A value blob whose SerString claims more bytes than the heap holds is
    # hostile input, not a framework fact: the walk must answer None (and keep
    # every other fact) rather than read out of bounds or crash.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    # The byte before the framework string in #Blob is its SerString packed
    # length; inflating it makes the string overrun the blob's end.
    string_at = raw.index(b".NETFramework,Version=")
    raw[string_at - 1] = 0x7F
    path = tmp_path / "corrupt_tfa.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.assembly_name == "MyAssembly"
    assert report.target_framework is None


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
