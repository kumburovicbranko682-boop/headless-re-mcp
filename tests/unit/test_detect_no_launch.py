"""Detect path must not launch the session binary as a process."""

from __future__ import annotations

import struct
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
    path.write_bytes(image)


def test_detect_scan_does_not_open_dynamic_or_launch(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "target.exe"
    _write_pe(binary)
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=None,
    )
    service = AnalysisService(settings)
    session_id = service.create_session(str(binary)).data["session"]["id"]

    calls: list[str] = []

    def boom(*_a, **_k):  # noqa: ANN001
        calls.append("open_dynamic")
        raise AssertionError("detect must not open dynamic backend")

    monkeypatch.setattr(service, "open_dynamic", boom)
    monkeypatch.setattr(service, "dynamic_launch", boom)

    result = service.detect_scan(session_id, use_die=False)
    assert result.ok
    assert calls == []
