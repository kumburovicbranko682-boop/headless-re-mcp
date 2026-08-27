"""The service validates slice_arch against the session before spawning r2.

slice_arch's failure modes are silent: on a non-fat target r2's ``-a``/``-b``
would override format autodetection and disassemble the wrong ISA, and on a fat
that lacks the requested slice r2 quietly falls back to its host-dependent
default pick. Both return well-formed garbage, so the service rejects anything
but a known Architecture the session's recorded fat slice table contains --
before a subprocess starts. A stub R2Client captures the resolved selector, so
these tests need no radare2.
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


class _CaptureR2:
    """Records the slice_arch each call resolved to; returns a trivial payload."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.seen: list[Architecture | None] = []

    def run(
        self, binary: Path, commands: list[str], *, timeout: float = 30.0, slice_arch: Any = None
    ) -> dict[str, Any]:
        del binary, commands, timeout
        self.seen.append(slice_arch)
        return {"raw": "[]", "commands": [], "parsed": False}


def _service(tmp_path: Path, monkeypatch: Any) -> tuple[AnalysisService, _CaptureR2]:
    tracker = _CaptureR2()
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ext.R2Client",
        lambda *args, **kwargs: tracker,
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings), tracker


def test_slice_arch_reaches_the_client_for_a_matching_fat_slice(
    tmp_path: Path, monkeypatch: Any
) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_fat(tmp_path / "u", (0x01000007, 0x0100000C))
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        assert created.data["session"]["target"] == "macho"
        sid = str(created.data["session"]["id"])
        result = service.r2_functions(sid, slice_arch="arm64")
        assert result.ok, result.error
        assert tracker.seen == [Architecture.ARM64]
    finally:
        service.close_all()


def test_slice_arch_absent_from_this_fat_is_rejected(tmp_path: Path, monkeypatch: Any) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_fat(tmp_path / "u", (0x01000007, 0x0100000C))
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        sid = str(created.data["session"]["id"])
        # This universal binary is x86_64 + arm64; there is no 32-bit arm slice.
        result = service.r2_functions(sid, slice_arch="arm")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert result.error.details.get("available_slices") == ["arm64", "x64"]
        # No subprocess was reached: the guard runs before the client is called.
        assert tracker.seen == []
    finally:
        service.close_all()


def test_unknown_slice_arch_name_is_rejected(tmp_path: Path, monkeypatch: Any) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_fat(tmp_path / "u", (0x01000007, 0x0100000C))
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        sid = str(created.data["session"]["id"])
        result = service.r2_functions(sid, slice_arch="mips")
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
        assert tracker.seen == []
    finally:
        service.close_all()


def test_slice_arch_on_a_non_fat_target_is_rejected(tmp_path: Path, monkeypatch: Any) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_elf(tmp_path / "a.elf")
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        assert created.data["session"]["target"] == "elf"
        sid = str(created.data["session"]["id"])
        result = service.r2_functions(sid, slice_arch="x64")
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
        assert "fat" in result.error.message
        assert tracker.seen == []
    finally:
        service.close_all()


def test_no_slice_arch_passes_none_through(tmp_path: Path, monkeypatch: Any) -> None:
    service, tracker = _service(tmp_path, monkeypatch)
    binary = _write_elf(tmp_path / "a.elf")
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None
        sid = str(created.data["session"]["id"])
        assert service.r2_functions(sid).ok
        assert tracker.seen == [None]
    finally:
        service.close_all()
