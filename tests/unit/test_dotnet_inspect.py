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
    # And no #~ tables at all: the entry token exists but nothing can back a
    # name for it, so the resolved fact stays None rather than fabricated.
    assert report.entry_point_name is None


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
    assert report.metadata_stats.method_count == 4
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
    # The ImplMap decoded: the *native* symbol each P/Invoke resolves and its
    # DLL. The fixture's managed wrapper is NativeBeep but the import is Beep
    # (an EntryPoint= rename), so this passing proves the reader reports the
    # ImportName the runtime binds, not the method name.
    assert report.pinvoke_imports == ({"name": "Beep", "module": "kernel32.dll"},)
    assert report.to_dict()["pinvoke_imports"] == [{"name": "Beep", "module": "kernel32.dll"}]
    # The TargetFrameworkAttribute the builder stamps on the assembly: reading
    # it walks TypeRef -> MemberRef -> CustomAttribute and decodes the value
    # blob's SerString from #Blob -- the platform the build targets, the
    # managed analogue of Mach-O's LC_BUILD_VERSION.
    assert report.target_framework == ".NETFramework,Version=v4.8"
    assert report.to_dict()["target_framework"] == ".NETFramework,Version=v4.8"
    # The strong-name identity: the Assembly row's PublicKey is the 16-byte
    # ECMA key, whose token -- the low 8 bytes of its SHA-1, reversed -- is the
    # published constant b77a5c561934e089. Matching it proves the reader read
    # the right blob and derived the token the way the CLR does.
    assert report.public_key_token == "b77a5c561934e089"
    assert report.to_dict()["public_key_token"] == "b77a5c561934e089"
    # The entry point resolved to a name: token 0x06000003 is MethodDef row 3
    # (Run), owned by the TypeDef whose MethodList span covers it (Sample) --
    # the same Sample::Run monodis marks with .entrypoint in the gate.
    assert report.entry_point_name == "Sample::Run"
    assert report.to_dict()["entry_point_name"] == "Sample::Run"
    # The module initializer: MethodDef row 1 is the static .cctor owned by
    # <Module> (TypeDef row 1) -- the code the runtime executes at module
    # load, before Run. The monodis gate cross-checks the same method as its
    # "global method .cctor".
    assert report.module_initializer_token == 0x06000001
    assert report.to_dict()["module_initializer_token"] == 0x06000001


def test_inspect_without_a_public_key_reports_no_token(tmp_path: Path) -> None:
    # A private, non-strong-named build carries no PublicKey blob; the token is
    # None rather than a hash of nothing. The synthetic verified image has an
    # Assembly row with a zero PublicKey index, exactly that case.
    path = tmp_path / "unsigned.exe"
    _write_verified_clr_pe(path)
    report = inspect_dotnet(path)
    assert report.public_key_token is None
    assert report.to_dict()["public_key_token"] is None


def _cor20_offset(raw: bytes) -> int:
    """File offset of the fixture's COR20 header, located from its own PE.

    The CLI directory names the COR20's RVA; the fixture is a single-section
    PE mapping RVA 0x2000 to file 0x200, the same arithmetic
    ``_rowcount_offset`` uses, so mutation tests survive fixture regeneration.
    """
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    cli_rva = struct.unpack_from("<I", raw, directories + 14 * 8)[0]
    return cli_rva - 0x2000 + 0x200


def test_a_file_token_entry_point_resolves_no_local_name(tmp_path: Path) -> None:
    # A multi-module assembly can point its entry at another module through a
    # File token (0x26). There is no local MethodDef to name, so the resolved
    # fact stays None while the raw token is still reported for triage.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    struct.pack_into("<I", raw, _cor20_offset(bytes(raw)) + 20, 0x26000001)
    path = tmp_path / "file_entry.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.entry_point_token == 0x26000001
    assert report.entry_point_name is None


def test_an_out_of_range_entry_row_resolves_no_name(tmp_path: Path) -> None:
    # A MethodDef token whose row the table does not have (row 99 of 2) names
    # nothing; the walk must not read past the table or borrow a neighbour's
    # name, and everything else still parses.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    struct.pack_into("<I", raw, _cor20_offset(bytes(raw)) + 20, 0x06000063)
    path = tmp_path / "liar_entry.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.entry_point_token == 0x06000063
    assert report.entry_point_name is None
    assert report.assembly_name == "MyAssembly"


def test_a_zero_entry_token_is_a_library_not_a_name(tmp_path: Path) -> None:
    # Libraries carry EntryPointToken 0. Row 0 of any table is not a thing in
    # ECMA-335 (indices are 1-based); no name may be fabricated from it.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    struct.pack_into("<I", raw, _cor20_offset(bytes(raw)) + 20, 0)
    path = tmp_path / "library.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.entry_point_token == 0
    assert report.entry_point_name is None


def _data_dir_offset(raw: bytes, index: int) -> int:
    """File offset of PE data directory entry ``index`` (each 8 bytes)."""
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    return directories + index * 8


def test_inspect_reads_the_committed_fixture_pdb_reference() -> None:
    # The CodeView RSDS record the fixture bakes into its debug directory: the
    # per-build GUID and age (the symbol-server key, the managed build-id
    # analogue) and the PDB path. objdump cross-checks these same values.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    report = inspect_dotnet(fixture)
    assert report.pdb == {
        "guid": "a1b2c3d4-e5f6-4788-99aa-bbccddeeff00",
        "age": 1,
        "path": r"C:\build\headless\MyAssembly.pdb",
        "signature": "A1B2C3D4E5F6478899AABBCCDDEEFF001",
    }
    assert report.to_dict()["pdb"] == report.pdb


def test_no_debug_directory_reports_no_pdb(tmp_path: Path) -> None:
    # Zeroing data directory 6 is a release build stripped of its debug
    # directory: no PDB reference, reported as None rather than guessed.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    struct.pack_into("<II", raw, _data_dir_offset(bytes(raw), 6), 0, 0)
    path = tmp_path / "no_debug.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.pdb is None
    # And the rest of the assembly still parses -- the debug read is isolated.
    assert report.assembly_name == "MyAssembly"


def test_a_non_codeview_debug_entry_reports_no_pdb(tmp_path: Path) -> None:
    # A debug directory whose only entry is some other type (e.g. POGO, 13)
    # carries no CodeView record, so there is no PDB reference to report.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    dir_rva = struct.unpack_from("<I", raw, _data_dir_offset(bytes(raw), 6))[0]
    entry_off = dir_rva - 0x2000 + 0x200
    struct.pack_into("<I", raw, entry_off + 12, 13)  # Type: POGO, not CodeView
    path = tmp_path / "pogo.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.pdb is None


def test_a_truncated_rsds_blob_reports_no_pdb(tmp_path: Path) -> None:
    # A CodeView entry whose data is too short for even an empty-path RSDS
    # (sig + GUID + age + one NUL) yields None, not a partial or crashing read.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    dir_rva = struct.unpack_from("<I", raw, _data_dir_offset(bytes(raw), 6))[0]
    entry_off = dir_rva - 0x2000 + 0x200
    struct.pack_into("<I", raw, entry_off + 16, 10)  # SizeOfData: below the RSDS minimum
    path = tmp_path / "short_rsds.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.pdb is None


def test_synthetic_verified_image_has_no_pdb(tmp_path: Path) -> None:
    # The synthetic verified CLR PE carries no debug directory at all; the PDB
    # fact is absent (None), the same as any image built without one.
    path = tmp_path / "synthetic.exe"
    _write_verified_clr_pe(path)
    assert inspect_dotnet(path).pdb is None


def test_a_renamed_module_cctor_is_no_initializer(tmp_path: Path) -> None:
    # The initializer's identity is the ".cctor" name (II.10.5.3); a static
    # method on <Module> called anything else is ordinary module-scope code.
    # Renaming the fixture's string in #Strings must clear the fact -- and
    # prove the reader matched the name, not just any row in the span.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    assert raw.count(b"\x00.cctor\x00") == 1, "fixture layout changed"
    raw[raw.index(b"\x00.cctor\x00") + 1] = ord("X")  # ".cctor" -> "Xcctor"
    path = tmp_path / "renamed_cctor.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.module_initializer_token is None
    # The rest of the assembly still parses -- the initializer read is isolated.
    assert report.entry_point_name == "Sample::Run"


def test_a_non_static_cctor_is_no_initializer(tmp_path: Path) -> None:
    # ECMA requires a class constructor to be static; a row that carries the
    # name without the flag is malformed, not a module initializer. The
    # MethodDef row 1 prefix (RVA is irrelevant here) is ImplFlags 0 +
    # Flags 0x1811; clearing the Static bit must clear the fact.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    marker = struct.pack("<HH", 0, 0x1811)
    assert raw.count(marker) == 1, "fixture layout changed"
    struct.pack_into("<H", raw, raw.index(marker) + 2, 0x1801)  # drop Static
    path = tmp_path / "instance_cctor.exe"
    path.write_bytes(bytes(raw))

    assert inspect_dotnet(path).module_initializer_token is None


def test_a_cctor_owned_by_a_type_is_no_initializer(tmp_path: Path) -> None:
    # Only <Module>'s (TypeDef row 1's) .cctor runs at module load; a type's
    # own static constructor runs at first use of that type. Moving Sample's
    # MethodList from 2 to 1 hands every method -- the .cctor included -- to
    # Sample, so the identical row must stop reading as a module initializer.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    sample_flags = struct.pack("<I", 0x00100001)  # TypeDef row 2 (Sample) Flags
    assert raw.count(sample_flags) == 1, "fixture layout changed"
    # Row layout: Flags(4) Name(2) Namespace(2) Extends(2) FieldList(2)
    # MethodList(2) -- the MethodList sits 12 bytes into the row.
    struct.pack_into("<H", raw, raw.index(sample_flags) + 12, 1)
    path = tmp_path / "type_cctor.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.module_initializer_token is None
    # Ownership moved, so the entry point's declaring type is unchanged and
    # the metadata as a whole still parses.
    assert report.entry_point_name == "Sample::Run"


def test_synthetic_verified_image_has_no_module_initializer(tmp_path: Path) -> None:
    # No #~ tables at all means no MethodDef rows to name an initializer:
    # None, the same honest absence as the entry-point name.
    path = tmp_path / "synthetic_no_cctor.exe"
    _write_verified_clr_pe(path)
    assert inspect_dotnet(path).module_initializer_token is None


# The fixture's one ImplMap row: MappingFlags 0x0100 (winapi), MemberForwarded
# (4 << 1) | 1 = 9 (MethodDef row 4). The pair prefixes the row uniquely, so
# mutation tests can locate its fields without hardcoding a file offset.
_IMPLMAP_ROW_PREFIX = struct.pack("<HH", 0x0100, 9)


def test_a_field_forwarded_implmap_row_is_skipped(tmp_path: Path) -> None:
    # MemberForwarded tag 0 is Field, which P/Invoke does not use (ECMA notes
    # it exists only for historical reasons); a row forwarding a field is not
    # a native import. Flipping the fixture row's tag must clear the list --
    # and prove the reader checked the tag rather than taking every row.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    assert raw.count(_IMPLMAP_ROW_PREFIX) == 1, "fixture layout changed"
    struct.pack_into("<H", raw, raw.index(_IMPLMAP_ROW_PREFIX) + 2, 4 << 1)  # tag -> Field
    path = tmp_path / "field_pinvoke.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.pinvoke_imports == ()
    # The tables behind ImplMap still parse -- the skip is per-row.
    assert report.assembly_name == "MyAssembly"


def test_an_out_of_range_import_scope_reads_as_no_module(tmp_path: Path) -> None:
    # ImportScope indexes ModuleRef; a row pointing past the table names no
    # DLL. The import itself is still real (the name is what the runtime
    # resolves), so it is kept with module None rather than dropped or guessed.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    assert raw.count(_IMPLMAP_ROW_PREFIX) == 1, "fixture layout changed"
    # Row layout: MappingFlags(2) MemberForwarded(2) ImportName(2)
    # ImportScope(2) -- the scope sits 6 bytes into the row.
    struct.pack_into("<H", raw, raw.index(_IMPLMAP_ROW_PREFIX) + 6, 99)
    path = tmp_path / "dangling_scope.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.pinvoke_imports == ({"name": "Beep", "module": None},)


def test_a_lying_implmap_count_stays_bounded(tmp_path: Path) -> None:
    # The ImplMap row count is attacker-controlled like every other; a claim
    # of two billion P/Invokes must neither allocate for the claim nor crash
    # the walk, and everything in front of the liar still parses.
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
    if not fixture.is_file():
        pytest.skip("minimal .NET fixture missing (skip != pass)")
    raw = bytearray(fixture.read_bytes())
    struct.pack_into("<I", raw, _rowcount_offset(bytes(raw), 0x1C), 0x7FFFFFFF)
    path = tmp_path / "liar_pinvokes.exe"
    path.write_bytes(bytes(raw))

    report = inspect_dotnet(path)
    assert report.verified_clr is True
    assert report.module_refs == ("kernel32.dll",)
    assert len(report.pinvoke_imports) <= 1024


def test_synthetic_verified_image_has_no_pinvoke_imports(tmp_path: Path) -> None:
    # No #~ tables at all means no ImplMap rows: an empty list, the same
    # honest absence as module_refs.
    path = tmp_path / "synthetic_no_pinvoke.exe"
    _write_verified_clr_pe(path)
    assert inspect_dotnet(path).pinvoke_imports == ()


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
    created = service.create_session(str(path))
    assert created.data is not None
    session_id = created.data["session"]["id"]
    result = service.dotnet_inspect(session_id, require_verified=True)
    assert result.ok and result.data is not None
    assert result.data["verified_clr"] is True
    assert result.data["claims_universal_unpack"] is False
