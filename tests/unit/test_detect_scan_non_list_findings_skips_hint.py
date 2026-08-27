"""detect_scan tolerates a serialized report whose findings are not a list.

The stealth-hint step indexes into ``report_dict["findings"]`` as a list. A
serialization that produced anything else -- a corrupted model, a future
schema change, a subclass overriding to_dict -- would raise mid-scan on a
result that had otherwise succeeded. The guard skips the hint instead, and
this pins that skip.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection.models import DetectionReport


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
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        diec=None,
    )


def _session_id(result: Any) -> str:
    data = result.data
    assert isinstance(data, dict)
    return str(data["session"]["id"])


def test_a_report_with_non_list_findings_still_succeeds_without_a_stealth_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "fixture.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path))
    session_id = _session_id(service.create_session(str(binary)))

    original = DetectionReport.to_dict

    def findings_not_a_list(self: DetectionReport) -> dict[str, Any]:
        data = original(self)
        data["findings"] = None
        return data

    monkeypatch.setattr(DetectionReport, "to_dict", findings_not_a_list)

    hinted: list[str] = []
    monkeypatch.setattr(
        service.registry,
        "update_metadata",
        lambda sid, hint: hinted.append(sid),
    )

    result = service.detect_scan(session_id, use_die=False)

    assert result.ok and result.data is not None
    assert result.data["report"]["findings"] is None
    # The isinstance guard was false, so the stealth-hint metadata write that
    # the list branch performs never ran.
    assert hinted == []
