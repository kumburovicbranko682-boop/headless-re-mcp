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
from headless_re_mcp.core.session import (
    SessionRegistry,
    _pe_authenticode,
    _pe_overlay,
    describe_pe_clr,
)

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


def _sign_native_pe(
    *,
    cert_type: int = 0x0002,
    revision: int = 0x0200,
    within: bool = True,
    payload: bytes = b"cert",
) -> bytes:
    """A native PE whose security directory points at an appended WIN_CERTIFICATE.

    The directory's first field is a file offset (not an RVA), so the blob is
    glued to the tail and the entry made to point at it -- exactly how a signed
    PE carries its Authenticode PKCS#7. ``within=False`` makes the declared size
    run past the file, the truncated-signature shape.
    """
    base = bytearray(_native_pe())
    blob = struct.pack("<IHH", 8 + len(payload), revision, cert_type) + payload
    cert_offset = len(base)
    declared = len(blob) + (4096 if not within else 0)
    # Optional header starts at 0x40 + 24; PE32 data directories begin at +96,
    # so the security entry (index 4) is at optional[96 + 4*8 : +8].
    security_entry = 0x40 + 24 + 96 + _PE_SECURITY_DIR * 8
    struct.pack_into("<II", base, security_entry, cert_offset, declared)
    return bytes(base) + blob


_PE_SECURITY_DIR = 4


def test_authenticode_absent_reads_unsigned(tmp_path: Path) -> None:
    # A native PE with an all-zero security directory: a real verdict, not
    # absent metadata -- the common unsigned case.
    path = tmp_path / "unsigned.exe"
    path.write_bytes(_native_pe())
    assert _pe_authenticode(path) == {"signed": False}


def test_authenticode_present_reports_the_certificate_range(tmp_path: Path) -> None:
    path = tmp_path / "signed.exe"
    raw = _sign_native_pe(payload=b"PKCS7-BODY")
    path.write_bytes(raw)
    info = _pe_authenticode(path)
    assert info is not None
    assert info["signed"] is True
    # The blob is at the file tail: offset is where the native PE ended, size
    # its whole WIN_CERTIFICATE length, and it fits the file.
    assert info["offset"] == len(_native_pe())
    assert info["size"] == len(raw) - len(_native_pe())
    assert info["within_file"] is True
    assert info["type"] == "pkcs_signed_data"
    assert info["authenticode"] is True
    assert info["revision"] == "2.0"


def test_a_non_authenticode_certificate_type_is_named_not_claimed(tmp_path: Path) -> None:
    # wCertificateType 0x0001 (x509) is a certificate, but not the Authenticode
    # PKCS#7 shape -- signed stays True, authenticode goes False.
    path = tmp_path / "x509.exe"
    path.write_bytes(_sign_native_pe(cert_type=0x0001))
    info = _pe_authenticode(path)
    assert info is not None
    assert info["signed"] is True
    assert info["type"] == "x509"
    assert info["authenticode"] is False


def test_a_signature_running_past_eof_is_flagged(tmp_path: Path) -> None:
    # A directory whose declared size overruns the file: still reported as
    # signed (the claim is there) but within_file False, and the header fields
    # are not read from a range that is not fully present.
    path = tmp_path / "truncated.exe"
    path.write_bytes(_sign_native_pe(within=False))
    info = _pe_authenticode(path)
    assert info is not None
    assert info["signed"] is True
    assert info["within_file"] is False
    assert "type" not in info


def test_authenticode_is_none_for_a_non_pe(tmp_path: Path) -> None:
    path = tmp_path / "notpe.bin"
    path.write_bytes(b"not a PE")
    assert _pe_authenticode(path) is None


class TestPeOverlay:
    """_pe_overlay finds appended data and splits off the signature's share.

    A PE ends at its furthest raw section end; bytes past that were glued on.
    The Authenticode certificate is legitimately appended, so the overlay is
    reported split: certificate_size is the signature's part, extra_size the
    unexplained remainder a dropper would occupy. extra_size 0 (with a cert) is
    a normal signed image; extra_size above 0 is the triage flag.
    """

    def test_a_bare_pe_has_no_overlay(self, tmp_path: Path) -> None:
        path = tmp_path / "bare.exe"
        path.write_bytes(_native_pe())
        assert _pe_overlay(path) is None

    def test_appended_junk_reads_as_unexplained_overlay(self, tmp_path: Path) -> None:
        base = _native_pe()
        path = tmp_path / "dropped.exe"
        path.write_bytes(base + b"SELF-EXTRACT" * 4)
        info = _pe_overlay(path)
        assert info is not None
        assert info["offset"] == len(base)
        assert info["size"] == len("SELF-EXTRACT") * 4
        assert info["certificate_size"] == 0
        assert info["extra_size"] == info["size"]

    def test_a_signed_pe_overlay_is_all_certificate(self, tmp_path: Path) -> None:
        raw = _sign_native_pe(payload=b"PKCS7-BODY")
        path = tmp_path / "signed.exe"
        path.write_bytes(raw)
        info = _pe_overlay(path)
        assert info is not None
        # Every trailing byte is the WIN_CERTIFICATE: nothing unexplained.
        assert info["offset"] == len(_native_pe())
        assert info["certificate_size"] == info["size"]
        assert info["extra_size"] == 0

    def test_a_signed_pe_with_a_stowaway_shows_the_extra_bytes(self, tmp_path: Path) -> None:
        stowaway = b"HIDDEN-PAYLOAD" * 3
        path = tmp_path / "signed-plus.exe"
        path.write_bytes(_sign_native_pe(payload=b"PKCS7-BODY") + stowaway)
        info = _pe_overlay(path)
        assert info is not None
        # The cert share is unchanged; the appended bytes surface as extra.
        assert info["extra_size"] == len(stowaway)
        assert info["certificate_size"] == info["size"] - len(stowaway)

    def test_a_lying_section_size_cannot_invent_an_overlay(self, tmp_path: Path) -> None:
        # Rewrite the (zero) section count is not possible here, so forge a
        # single section whose raw size claims to run past EOF: the image end
        # clamps to the file, so no phantom overlay appears.
        base = bytearray(_native_pe())
        # Turn it into a 1-section PE by bumping NumberOfSections and appending
        # a section header claiming a huge raw size at a tail pointer.
        e = struct.unpack_from("<I", base, 0x3C)[0]
        struct.pack_into("<H", base, e + 4 + 2, 1)  # NumberOfSections = 1
        section = bytearray(40)
        struct.pack_into("<I", section, 16, 0xFFFF)  # SizeOfRawData: lies past EOF
        struct.pack_into("<I", section, 20, len(base) + 40)  # PointerToRawData
        forged = bytes(base) + bytes(section)
        path = tmp_path / "liar.exe"
        path.write_bytes(forged)
        # image end clamps to the file size, so there is no trailing data to
        # report even though the section claims thousands of bytes.
        assert _pe_overlay(path) is None

    def test_non_pe_has_no_overlay(self, tmp_path: Path) -> None:
        path = tmp_path / "nope.bin"
        path.write_bytes(b"not a pe at all, just bytes")
        assert _pe_overlay(path) is None


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


def test_session_over_a_native_pe_carries_only_the_authenticode_verdict(tmp_path: Path) -> None:
    path = tmp_path / "native.exe"
    path.write_bytes(_native_pe())
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.PE
    assert session.architecture is Architecture.X86
    # A native PE has no .NET block, but it does now carry the whole-PE
    # Authenticode verdict -- unsigned here, a real answer rather than empty.
    assert session.metadata == {"pe": {"authenticode": {"signed": False}}}


def test_session_over_a_signed_pe_carries_the_authenticode_range(tmp_path: Path) -> None:
    path = tmp_path / "signed.exe"
    path.write_bytes(_sign_native_pe(payload=b"PKCS7-BODY"))
    session = SessionRegistry().create(str(path))
    assert session.target is TargetKind.PE
    assert session.metadata["pe"]["authenticode"]["signed"] is True
    assert session.metadata["pe"]["authenticode"]["authenticode"] is True
