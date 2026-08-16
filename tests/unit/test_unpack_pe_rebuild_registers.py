"""A rebuilt PE must enter the artifacts table so retention can see it."""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_pe(path: Path) -> None:
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
    image[0x200:0x202] = b"\xC3\x90"
    path.write_bytes(image)


def test_unpack_pe_rebuild_registers_the_image_so_gc_can_see_it(tmp_path: Path) -> None:
    """A successful remap wrote a PE that artifacts.list and gc could not see.

    Measured: unpack.pe.rebuild returned ok=True and a 1024-byte
    artifact_root/unpack/<id>/pe-rebuilt-*.exe. artifacts.list total was 0.
    gc_artifacts(max_total_bytes=1) removed 0. close_session and close_all
    left the file. An unattended rebuild loop then fills the volume with
    images retention cannot reclaim.
    """
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        dump = settings.artifact_root.expanduser().resolve() / "dump.exe"
        dump.write_bytes(binary.read_bytes())
        rebuilt = service.unpack_pe_rebuild(session_id, str(dump), entry_point_rva=0x1000)
        assert rebuilt.ok and rebuilt.data is not None, rebuilt.error
        out = Path(str(rebuilt.data["output_path"]))
        assert out.is_file()
        assert out.stat().st_size == 1024
        assert rebuilt.data.get("artifact_id")

        listed = service.artifacts_list(session_id)
        assert listed.ok and listed.data is not None, listed.error
        assert listed.data["total"] == 1
        row = listed.data["artifacts"][0]
        assert Path(str(row["path"])) == out
        assert int(row["size"]) == 1024
        assert row["kind"] == "pe_rebuilt"

        newer = settings.artifact_root.expanduser().resolve() / "newer.bin"
        newer.write_bytes(b"x" * 2048)
        service.record_artifact(
            session_id=session_id,
            kind="probe",
            path=newer,
            sha256="ab",
            source="test",
        )
        collected = service.repository.gc_artifacts(max_total_bytes=1)
        assert collected["count"] >= 1
        assert not out.is_file()
    finally:
        service.close_all()
