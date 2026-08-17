"""unpack.verify must refuse non-PE sessions even when a PE sits in artifacts."""

from __future__ import annotations

import struct
import zipfile
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


def _write_apk(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")


def test_unpack_verify_on_apk_session_is_target_mismatch(tmp_path: Path) -> None:
    """A PE in the APK session artifact tree used to verify as success.

    Measured: unpack.verify only checked path ownership, then scan_pe. An APK
    session with unpack/<id>/planted.exe returned ok=True and advanced the
    unpack claim path. The caller was sent to IDA on a session that has no PE.
    """
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    service = AnalysisService(settings)
    apk = tmp_path / "app.apk"
    _write_apk(apk)
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        planted = settings.artifact_root / "unpack" / session_id / "planted.exe"
        planted.parent.mkdir(parents=True, exist_ok=True)
        _write_pe(planted)

        verified = service.unpack_verify(
            session_id,
            str(planted),
            use_die=False,
            open_ida=False,
        )
        assert verified.ok is False
        assert verified.error is not None
        assert verified.error.code == "target_mismatch"
    finally:
        service.close_all()
