"""describe_pe_clr: tool-free .NET identity facts for a PE (no dotnet.inspect).

A managed assembly is a PE, so it classifies as a PE target and used to carry
only its architecture. describe_pe_clr adds the first fork of a Windows-binary
triage -- is this native or managed, and if managed, which runtime and metadata
version -- by reading just the PE/CLR headers, no external tool and no second
hash of the file. These cover the committed .NET fixture, a synthetic native PE
(which must stay empty so the PE baseline is unchanged), a non-PE input, and the
facts flowing through session creation.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.core.models import Architecture, TargetKind
from headless_re_mcp.core.session import SessionRegistry, describe_pe_clr

_DOTNET_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
)


def _native_pe() -> bytes:
    """A minimal PE32 with 16 all-zero data directories: valid, but not managed."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (0x40).to_bytes(4, "little")  # e_lfanew
    coff = b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0xE0, 0)
    optional = bytearray(0xE0)
    optional[0:2] = (0x10B).to_bytes(2, "little")  # PE32
    optional[92:96] = (16).to_bytes(4, "little")  # NumberOfRvaAndSizes; all dirs zero
    return bytes(dos) + coff + bytes(optional)


def _cli_header_offset(raw: bytes) -> int:
    """File offset of the COR20 (CLI) header, mapping its RVA through sections."""
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", raw, optional)[0]
    directories = optional + (112 if magic == 0x20B else 96)
    cli_rva = struct.unpack_from("<I", raw, directories + 14 * 8)[0]
    coff = e_lfanew + 4
    sections = struct.unpack_from("<H", raw, coff + 2)[0]
    table = coff + 20 + struct.unpack_from("<H", raw, coff + 16)[0]
    for index in range(sections):
        base = table + index * 40
        virtual_address = struct.unpack_from("<I", raw, base + 12)[0]
        raw_size, raw_pointer = struct.unpack_from("<II", raw, base + 16)
        if virtual_address <= cli_rva < virtual_address + max(raw_size, 1):
            return raw_pointer + (cli_rva - virtual_address)
    raise AssertionError("could not locate the CLI header in the fixture")


def _fixture_with_corflags(tmp_path: Path, flags: int) -> Path:
    """The committed assembly with its COR20 Flags field rewritten to ``flags``."""
    raw = bytearray(_DOTNET_FIXTURE.read_bytes())
    raw[_cli_header_offset(raw) + 16 : _cli_header_offset(raw) + 20] = struct.pack("<I", flags)
    path = tmp_path / f"corflags_{flags:08x}.exe"
    path.write_bytes(raw)
    return path


def test_reads_the_committed_dotnet_fixture() -> None:
    if not _DOTNET_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
    info = describe_pe_clr(_DOTNET_FIXTURE)["dotnet"]
    assert info["is_dotnet"] is True
    assert info["runtime_version"] == "2.5"
    assert info["metadata_version"] == "v4.0.30319"
    # Row 3: the fixture's MethodDef table is .cctor (the module initializer,
    # row 1), Add (row 2), Run (row 3, the entry point).
    assert info["entry_point_token"] == 0x06000003
    assert info["il_only"] is True
    # The fixture's COR20 Flags is ILONLY only (pedump: "ilonly, 32/64,
    # no-trackdebug, notsigned"); the pedump gate cross-checks this.
    assert info["requires_32bit"] is False
    assert info["prefers_32bit"] is False
    assert info["strong_name_signed"] is False


def test_corflags_bits_are_decoded_from_the_cor20_header(tmp_path: Path) -> None:
    if not _DOTNET_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
    # Each corflags bit must be read independently: rewrite only the Flags field
    # of a real assembly and confirm the one fact it controls flips, nothing else.
    ilonly = 0x00000001
    cases = {
        0x00000002: "requires_32bit",  # COMIMAGE_FLAGS_32BITREQUIRED
        0x00020000: "prefers_32bit",  # COMIMAGE_FLAGS_32BITPREFERRED
        0x00000008: "strong_name_signed",  # COMIMAGE_FLAGS_STRONGNAMESIGNED
    }
    for bit, fact in cases.items():
        info = describe_pe_clr(_fixture_with_corflags(tmp_path, ilonly | bit))["dotnet"]
        assert info[fact] is True, fact
        assert info["il_only"] is True
        for other in cases.values():
            if other != fact:
                assert info[other] is False, f"{fact} leaked into {other}"
    # Flags cleared entirely: every posture bit, il_only included, reads False.
    cleared = describe_pe_clr(_fixture_with_corflags(tmp_path, 0))["dotnet"]
    assert cleared["il_only"] is False
    assert cleared["requires_32bit"] is False
    assert cleared["prefers_32bit"] is False
    assert cleared["strong_name_signed"] is False


def test_native_pe_has_no_dotnet_block(tmp_path: Path) -> None:
    path = tmp_path / "native.exe"
    path.write_bytes(_native_pe())
    # No COM descriptor directory: describe_pe_clr must return nothing so the PE
    # baseline session carries no spurious metadata.
    assert describe_pe_clr(path) == {}


def test_non_pe_returns_empty(tmp_path: Path) -> None:
    path = tmp_path / "notpe.bin"
    path.write_bytes(b"this is not a PE file at all")
    assert describe_pe_clr(path) == {}


def test_session_over_the_dotnet_fixture_carries_the_facts() -> None:
    if not _DOTNET_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
    session = SessionRegistry().create(str(_DOTNET_FIXTURE))
    assert session.target is TargetKind.PE
    assert session.metadata["dotnet"]["is_dotnet"] is True
    assert session.metadata["dotnet"]["metadata_version"] == "v4.0.30319"


def test_session_over_a_native_pe_has_empty_metadata(tmp_path: Path) -> None:
    path = tmp_path / "native.exe"
    path.write_bytes(_native_pe())
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.PE
    assert session.architecture is Architecture.X86
    assert session.metadata == {}
