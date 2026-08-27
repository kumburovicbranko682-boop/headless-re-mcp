"""The service validates slice_arch against the session before Ghidra runs.

The r2 guard (test_r2_slice_arch_service_guard) pins the shared validator; this
pins the ghidra endpoints' use of it plus the one rule that is Ghidra's alone:
a fat/universal Mach-O *requires* slice_arch, because Ghidra's headless
importer offers no load spec for the fat container itself. Without the guard,
such a request would burn a full analyzeHeadless run only to fail with a
stderr dump the session metadata could have predicted. A stub GhidraClient
captures the resolved selector, so these tests need no Ghidra.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path
from typing import Any

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Architecture
from headless_re_mcp.core.service import AnalysisService

_LE64 = b"\xcf\xfa\xed\xfe"


def _thin(cputype: int) -> bytes:
    return _LE64 + struct.pack("<IIIII", cputype, 3, 2, 0, 0) + struct.pack("<II", 0, 0)


def _write_fat(path: Path, cputypes: tuple[int, ...]) -> Path:
    blobs = [(c, _thin(c)) for c in cputypes]
    cursor = (8 + 20 * len(blobs) + 0xFFF) & ~0xFFF
    placed: list[tuple[int, int, bytes]] = []
    for cputype, blob in blobs:
        placed.append((cputype, cursor, blob))
        cursor += (len(blob) + 0xFFF) & ~0xFFF
    header = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(blobs))
    for cputype, offset, blob in placed:
        header += struct.pack(">IIIII", cputype, 3, offset, len(blob), 12)
    image = bytearray(header)
    for _cputype, offset, blob in placed:
        image = image.ljust(offset, b"\x00") + blob
    path.write_bytes(bytes(image))
    return path


def _write_elf(path: Path) -> Path:
    ident = bytearray(64)
    ident[:4] = b"\x7fELF"
    ident[4] = 2
    ident[5] = 1
    ident[18:20] = (0x3E).to_bytes(2, "little")
    path.write_bytes(bytes(ident))
    return path


class _CaptureGhidra:
    """Records the slice_arch each call resolved to; returns trivial payloads."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.seen: list[tuple[str, Architecture | None]] = []

    def functions(self, binary: Path, project: Path, **kwargs: Any) -> dict[str, Any]:
        self.seen.append(("functions", kwargs.get("slice_arch")))
        return {"mode": "functions", "items": []}

    def symbols(self, binary: Path, project: Path, **kwargs: Any) -> dict[str, Any]:
        self.seen.append(("symbols", kwargs.get("slice_arch")))
        return {"mode": "symbols", "items": []}

    def xrefs(self, binary: Path, project: Path, address: Any, **kwargs: Any) -> dict[str, Any]:
        self.seen.append(("xrefs", kwargs.get("slice_arch")))
        return {"mode": "xrefs", "items": []}

    def decompile(self, binary: Path, project: Path, address: Any, **kwargs: Any) -> dict[str, Any]:
        self.seen.append(("decompile", kwargs.get("slice_arch")))
        return {"mode": "decompile", "decompiled": ""}

    def analyze_binary(self, binary: Path, project: Path, **kwargs: Any) -> dict[str, Any]:
        self.seen.append(("analyze", kwargs.get("slice_arch")))
        return {"project_dir": str(project), "stdout_excerpt": "", "note": ""}


def _service(tmp_path: Path, monkeypatch: Any) -> tuple[AnalysisService, _CaptureGhidra]:
    tracker = _CaptureGhidra()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.GhidraClient",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings), tracker


def test_slice_arch_reaches_the_client_on_every_ghidra_endpoint(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_fat(tmp_path / "u", (0x01000007, 0x0100000C))
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        assert created.data["session"]["target"] == "macho"
        sid = str(created.data["session"]["id"])
        assert service.ghidra_functions(sid, slice_arch="arm64").ok
        assert service.ghidra_symbols(sid, slice_arch="x64").ok
        assert service.ghidra_xrefs(sid, "0x0", slice_arch="arm64").ok
        assert service.ghidra_decompile(sid, "0x0", slice_arch="x64").ok
        assert service.ghidra_analyze(sid, slice_arch="arm64").ok
        assert tracker.seen == [
            ("functions", Architecture.ARM64),
            ("symbols", Architecture.X64),
            ("xrefs", Architecture.ARM64),
            ("decompile", Architecture.X64),
            ("analyze", Architecture.ARM64),
        ]
    finally:
        service.close_all()


def test_a_fat_without_slice_arch_is_rejected_before_ghidra_runs(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_fat(tmp_path / "u", (0x01000007, 0x0100000C))
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        sid = str(created.data["session"]["id"])
        for result in (
            service.ghidra_functions(sid),
            service.ghidra_symbols(sid),
            service.ghidra_xrefs(sid, "0x0"),
            service.ghidra_decompile(sid, "0x0"),
            service.ghidra_analyze(sid),
        ):
            assert result.ok is False
            assert result.error is not None
            assert result.error.code == "invalid_params"
            assert "slice_arch" in result.error.message
            assert result.error.details.get("available_slices") == ["arm64", "x64"]
        assert tracker.seen == [], "no headless run for a fat with no slice named"
    finally:
        service.close_all()


def test_an_absent_slice_is_rejected(tmp_path: Path, monkeypatch: Any) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_fat(tmp_path / "u", (0x01000007, 0x0100000C))
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        sid = str(created.data["session"]["id"])
        result = service.ghidra_functions(sid, slice_arch="arm")
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
        assert result.error.details.get("available_slices") == ["arm64", "x64"]
        assert tracker.seen == []
    finally:
        service.close_all()


def test_slice_arch_on_a_non_fat_target_is_rejected(tmp_path: Path, monkeypatch: Any) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_elf(tmp_path / "a.elf")
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        sid = str(created.data["session"]["id"])
        result = service.ghidra_functions(sid, slice_arch="x64")
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
        assert "fat" in result.error.message
        assert tracker.seen == []
    finally:
        service.close_all()


def test_a_non_fat_target_passes_none_through(tmp_path: Path, monkeypatch: Any) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_elf(tmp_path / "a.elf")
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        sid = str(created.data["session"]["id"])
        assert service.ghidra_functions(sid).ok
        assert tracker.seen == [("functions", None)]
    finally:
        service.close_all()
