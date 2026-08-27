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


def test_reads_the_committed_dotnet_fixture() -> None:
    if not _DOTNET_FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_DOTNET_FIXTURE}")
    info = describe_pe_clr(_DOTNET_FIXTURE)["dotnet"]
    assert info["is_dotnet"] is True
    assert info["runtime_version"] == "2.5"
    assert info["metadata_version"] == "v4.0.30319"
    assert info["entry_point_token"] == 0x06000002
    assert info["il_only"] is True


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
