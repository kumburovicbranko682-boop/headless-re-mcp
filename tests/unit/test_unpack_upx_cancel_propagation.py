"""A caller cancel during unpack.auto's UPX phase must surface as cancellation.

unpack.auto wraps the UPX orchestration in a bound_cancel_scope and catches
BoundedCancelled to record a clean cancelled state. The UPX test/unpack
endpoints used to catch it in their generic ``except BaseException`` and route
it through ``_failure()`` -- which has no BoundedCancelled case, so the cancel
became an internal_error incident and a false ``upx_test_failed`` /
``upx_unpack_failed`` unpack state instead of "cancelled".
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    # A full PE32+ that satisfies scan_pe (upx.unpack and the unpack planner
    # both scan the input): positive section/file alignments, a data-directory
    # count and one section.
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


def _cancelling_tester(*args: Any, **kwargs: Any) -> Any:
    raise BoundedCancelled()


def _service(tmp_path: Path) -> AnalysisService:
    exe = tmp_path / "upx.exe"
    exe.write_bytes(b"placeholder")
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            upx=exe,
        ),
        upx_tester=_cancelling_tester,
        upx_unpacker=_cancelling_tester,
    )


def test_unpack_upx_test_reraises_cancel(tmp_path: Path) -> None:
    """The endpoint must let BoundedCancelled propagate, not fold it into a Result."""
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path)
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        with pytest.raises(BoundedCancelled):
            service.unpack_upx_test(session_id)
    finally:
        service.close_all()


def test_unpack_upx_unpack_reraises_cancel(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path)
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        with pytest.raises(BoundedCancelled):
            service.unpack_upx_unpack(session_id)
    finally:
        service.close_all()


def test_unpack_auto_upx_cancel_records_cancelled_not_failed(tmp_path: Path) -> None:
    """End to end: a cancel in the UPX phase surfaces as a cancel, not a failure.

    Before the fix the UPX endpoint swallowed BoundedCancelled into _failure(),
    so the auto flow saw ``upx_test_failed`` and returned ok=True with phase
    ``failed`` while logging a spurious internal_error incident. After it, the
    cancel reaches unpack.auto's own ``except BoundedCancelled`` handler, which
    reports the cancel fail-closed as ``unpack_cancelled``.
    """
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path)
    try:
        session_id = service.create_session(str(binary)).data["session"]["id"]
        result = service.unpack_start(
            session_id,
            use_die=False,
            execute_upx=True,
            force_route="upx",
        )
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "unpack_cancelled"
    finally:
        service.close_all()
