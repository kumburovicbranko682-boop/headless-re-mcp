"""Cross-validate the tool-free PE Authenticode fact against pefile.

A session over a PE now reports whether the image carries an embedded
Authenticode signature and where the certificate blob sits, read straight from
the security data directory (index 4, whose first field is a file offset to the
WIN_CERTIFICATE table at the file tail, not an RVA). That reader and its unit
fixtures are both ours, so nothing proved the directory is decoded the way an
independent PE parser reads it. pefile is that referee: it exposes the same
directory as ``DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_SECURITY]`` (VirtualAddress
= the file offset, Size = the blob length). Two checks close the loop:

* the committed managed fixture, unsigned, must read as unsigned in both views
  -- pefile sees a zero-size security directory, the session reports signed
  False;
* a synthetically-signed copy -- a WIN_CERTIFICATE glued to the tail and the
  directory pointed at it -- must have the session's offset/size equal
  pefile's VirtualAddress/Size byte for byte, and pefile must actually surface
  the certificate blob it points to.

pefile ships in the project's ``pe`` extra, so this needs no system tool and
runs on every platform. skip != pass: it skips only if pefile or the fixture
is absent.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "dotnet" / "minimal_assembly.exe"
_SECURITY_DIR_INDEX = 4


def _pefile() -> object | None:
    try:
        import pefile
    except ImportError:
        return None
    return pefile


def _security_directory(pefile_mod: object, data: bytes) -> tuple[int, int]:
    """pefile's independent read of the security directory: (offset, size)."""
    pe = pefile_mod.PE(data=data)  # type: ignore[attr-defined]
    index = pefile_mod.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]  # type: ignore[attr-defined]
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    return int(entry.VirtualAddress), int(entry.Size)


def _sign(raw: bytes, payload: bytes = b"PKCS7-SIGNATURE-BODY") -> bytes:
    """Glue a WIN_CERTIFICATE to the tail and point the security directory at it."""
    data = bytearray(raw)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    optional = e_lfanew + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    directories = optional + (108 if magic == 0x20B else 92) + 4
    security_entry = directories + _SECURITY_DIR_INDEX * 8
    blob = struct.pack("<IHH", 8 + len(payload), 0x0200, 0x0002) + payload
    struct.pack_into("<II", data, security_entry, len(data), len(blob))
    return bytes(data) + blob


def _session_authenticode(path: Path) -> dict:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["pe"]["authenticode"]
    finally:
        service.close_all()


@pytest.mark.integration
def test_unsigned_pe_agrees_with_pefile() -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE Authenticode gate not run (skip != pass)")

    offset, size = _security_directory(pefile_mod, _FIXTURE.read_bytes())
    # pefile sees no certificate table: the committed assembly is unsigned.
    assert size == 0
    assert _session_authenticode(_FIXTURE) == {"signed": False}


@pytest.mark.integration
def test_signed_pe_range_agrees_with_pefile(tmp_path: Path) -> None:
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE Authenticode gate not run (skip != pass)")

    signed_bytes = _sign(_FIXTURE.read_bytes())
    signed = tmp_path / "signed.exe"
    signed.write_bytes(signed_bytes)

    offset, size = _security_directory(pefile_mod, signed_bytes)
    # pefile must decode a non-empty certificate table and surface the blob the
    # directory points at -- proof the entry is well-formed, not just non-zero.
    assert size > 0
    pe = pefile_mod.PE(data=signed_bytes)  # type: ignore[attr-defined]
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY  # parsed
    tail = signed_bytes[offset : offset + size]
    assert b"PKCS7-SIGNATURE-BODY" in tail

    info = _session_authenticode(signed)
    assert info["signed"] is True
    # The reader's range is pefile's security directory, byte for byte.
    assert info["offset"] == offset
    assert info["size"] == size
    assert info["within_file"] is True
    assert info["type"] == "pkcs_signed_data"
    assert info["authenticode"] is True
    assert info["revision"] == "2.0"


def _session_pe_overlay(path: Path) -> dict | None:
    service = AnalysisService()
    try:
        created = service.create_session(str(path))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["pe"].get("overlay")
    finally:
        service.close_all()


@pytest.mark.integration
def test_pe_overlay_offset_agrees_with_pefile(tmp_path: Path) -> None:
    """The reader's overlay start is pefile's overlay start, and its split is honest.

    A PE ends at its furthest raw section end; pefile computes that same
    boundary as get_overlay_data_start_offset. The reader reports appended data
    past it, split into the Authenticode certificate's share and the
    unexplained remainder. Three shapes, each refereed by pefile's independent
    boundary: the clean fixture (no overlay, pefile agrees there is none), the
    fixture with a payload glued on (overlay at pefile's boundary, all
    unexplained), and a signed-plus-stowaway copy (the cert share equals the
    security directory size, the remainder is exactly the stowaway).
    """
    if not _FIXTURE.is_file():
        pytest.skip(f"fixture missing: {_FIXTURE}")
    pefile_mod = _pefile()
    if pefile_mod is None:
        pytest.skip("pefile not installed — PE overlay gate not run (skip != pass)")

    # Clean: both readers see no trailing data.
    clean_pe = pefile_mod.PE(data=_FIXTURE.read_bytes())  # type: ignore[attr-defined]
    assert clean_pe.get_overlay_data_start_offset() is None
    assert _session_pe_overlay(_FIXTURE) is None

    # A payload glued onto the unsigned fixture: pefile's overlay boundary is
    # the reader's offset, and every trailing byte is unexplained.
    payload = b"SELF-EXTRACTING-STUB" * 3
    dropped_bytes = _FIXTURE.read_bytes() + payload
    dropped = tmp_path / "dropped.exe"
    dropped.write_bytes(dropped_bytes)
    dropped_pe = pefile_mod.PE(data=dropped_bytes)  # type: ignore[attr-defined]
    pefile_boundary = dropped_pe.get_overlay_data_start_offset()
    assert pefile_boundary is not None
    overlay = _session_pe_overlay(dropped)
    assert overlay is not None
    assert overlay["offset"] == pefile_boundary
    assert overlay["size"] == len(payload)
    assert overlay["certificate_size"] == 0
    assert overlay["extra_size"] == len(payload)
    # The stub text carries no magic: the kind is honest None.
    assert overlay["kind"] is None

    # Signed, then a stowaway glued after the certificate: pefile still marks
    # the overlay at the last section end, the reader attributes the cert's
    # bytes to the signature (its size equals pefile's security directory) and
    # leaves precisely the stowaway as extra.
    stowaway = b"HIDDEN" * 5
    signed_plus = _sign(_FIXTURE.read_bytes()) + stowaway
    signed_path = tmp_path / "signed-plus.exe"
    signed_path.write_bytes(signed_plus)
    signed_pe = pefile_mod.PE(data=signed_plus)  # type: ignore[attr-defined]
    _cert_off, cert_size = _security_directory(pefile_mod, signed_plus)
    boundary = signed_pe.get_overlay_data_start_offset()
    assert boundary is not None
    overlay = _session_pe_overlay(signed_path)
    assert overlay is not None
    assert overlay["offset"] == boundary
    assert overlay["certificate_size"] == cert_size
    assert overlay["extra_size"] == len(stowaway)
    # Prose behind the certificate carries no magic: the kind is honest None.
    assert overlay["kind"] is None

    # An *archive* stowed behind the certificate: the kind sniff must skip
    # the WIN_CERTIFICATE furniture (whose own header carries no magic) and
    # name the zip behind it -- a sniff that read the overlay's first bytes
    # instead of the unexplained region's would answer None here.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("payload.txt", "stage two")
    archive_stowaway = tmp_path / "signed-sfx.exe"
    archive_stowaway.write_bytes(_sign(_FIXTURE.read_bytes()) + buffer.getvalue())
    overlay = _session_pe_overlay(archive_stowaway)
    assert overlay is not None
    assert overlay["extra_size"] == len(buffer.getvalue())
    assert overlay["kind"] == "zip"
