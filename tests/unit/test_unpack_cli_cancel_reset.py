"""A stale cancel latch must not abort the next CLI dump on the same session.

unpack.auto resets the session's cancel event before it runs (service_unpack).
The xvlkc / vmp_dump / scylla CLI endpoints entered the same cancel scope but
did not reset it, so once unpack.cancel set the latch -- or an earlier dump was
cancelled -- every later dump on that still-open session cancelled itself the
moment it started, with no way back short of closing the session.

These tests set the latch the way unpack.cancel does, then run a dump whose
fake runner mimics _capture_process: it raises BoundedCancelled if the latch is
set when it executes. With the reset in place the runner sees a clear latch and
the dump proceeds.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import (
    BoundedCancelled,
    active_bound_cancel,
)
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.unpack.scylla import ScyllaResult
from headless_re_mcp.unpack.xvlkc import XvlkcResult


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into("<HHIIIHH", image, file_header, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x10B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 28, 0x400000)
    struct.pack_into("<II", image, optional + 56, 0x1000, 0x200)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    path.write_bytes(image)


def _cancel_aware(observed: dict[str, Any], result_cls: type) -> Any:
    def runner(
        executable: Path,
        input_path: Path,
        output_path: Path,
        *,
        input_sha256: str,
        timeout: float = 120.0,
        max_file_size: int = 0,
        max_output_size: int = 0,
    ) -> Any:
        del executable, timeout, max_file_size, max_output_size
        stop = active_bound_cancel()
        observed["latch_set_at_call"] = bool(stop is not None and stop.is_set())
        observed["ran"] = True
        # Mimic _capture_process: honor the bound cancel event.
        if stop is not None and stop.is_set():
            raise BoundedCancelled()
        output_path.write_bytes(input_path.read_bytes())
        return result_cls(
            executable="cli",
            input_path=str(input_path),
            output_path=str(output_path.resolve()),
            input_sha256=input_sha256,
            output_sha256=file_sha256(output_path),
            returncode=0,
            stdout="ok",
            stderr="",
            duration_ms=1,
        )

    return runner


def test_xvlkc_dump_after_a_prior_cancel_is_not_aborted(tmp_path: Path) -> None:
    observed: dict[str, Any] = {}
    exe = tmp_path / "xvlkc.exe"
    exe.write_bytes(b"placeholder")
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            xvlkc=exe,
        ),
        xvlkc_runner=_cancel_aware(observed, XvlkcResult),
    )
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        # A previous unpack.cancel on this session left the latch set.
        service._signal_unpack_cancel(session_id)
        result = service.unpack_xvlkc_unpack(session_id)
        assert observed.get("ran") is True
        assert observed.get("latch_set_at_call") is False
        assert result.ok is True, result.error
    finally:
        service.close_all()


def test_scylla_rebuild_after_a_prior_cancel_is_not_aborted(tmp_path: Path) -> None:
    observed: dict[str, Any] = {}
    exe = tmp_path / "Scylla.exe"
    exe.write_bytes(b"placeholder")
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            scylla=exe,
        ),
        scylla_runner=_cancel_aware(observed, ScyllaResult),
    )
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        service._signal_unpack_cancel(session_id)
        result = service.unpack_scylla_rebuild(session_id)
        assert observed.get("ran") is True
        assert observed.get("latch_set_at_call") is False
        assert result.ok is True, result.error
    finally:
        service.close_all()
