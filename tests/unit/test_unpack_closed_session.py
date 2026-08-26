"""A retained CLOSED session must not start unpack orchestration."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


def _write_verified_clr_pe(path: Path) -> None:
    image = bytearray(0x800)
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
    dir_base = optional + 112
    struct.pack_into("<II", image, dir_base + 14 * 8, 0x1100, 72)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    cor_off = 0x300
    struct.pack_into("<I", image, cor_off, 72)
    struct.pack_into("<HH", image, cor_off + 4, 2, 5)
    struct.pack_into("<II", image, cor_off + 8, 0x1200, 0x40)
    struct.pack_into("<I", image, cor_off + 16, 0x1)
    struct.pack_into("<I", image, cor_off + 20, 0x06000001)
    meta_off = 0x400
    version = b"v4.0.30319\0"
    version_padded = version + b"\0" * ((4 - (len(version) % 4)) % 4)
    image[meta_off : meta_off + 4] = b"BSJB"
    struct.pack_into("<HH", image, meta_off + 4, 1, 1)
    struct.pack_into("<I", image, meta_off + 8, 0)
    struct.pack_into("<I", image, meta_off + 12, len(version))
    image[meta_off + 16 : meta_off + 16 + len(version_padded)] = version_padded
    cursor = meta_off + 16 + len(version_padded)
    struct.pack_into("<HH", image, cursor, 0, 0)
    path.write_bytes(image)


def test_unpack_start_on_a_closed_session_does_not_install_state(tmp_path: Path) -> None:
    """A retained CLOSED session still resolved, so a late start installed unpack state.

    Measured: after close_session, unpack.start returned ok=True with phase
    detected / route dotnet, and _unpack_owner kept that session. session.close
    cannot reap an orchestration that started after it returned. The model then
    treats the dead session as unpacking.
    """
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.unpack_start(session_id, use_die=False, execute_upx=False)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
        assert service._unpack_owner.get(session_id) is None
    finally:
        service.close_all()


def test_unpack_plan_on_a_closed_session_is_refused(tmp_path: Path) -> None:
    """unpack.plan on a closed session still returned a route the model would follow."""
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        closed = service.close_session(session_id)
        assert closed.ok, closed.error

        result = service.unpack_plan(session_id, use_die=False)
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert "closed" in result.error.message
    finally:
        service.close_all()


def test_unpack_start_close_race_does_not_recreate_cancel_event(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Close clears unpack state, but start recreated one cancel Event afterward.

    One plan/close race leaves one entry forever. Repeating the race for unique
    session ids therefore grows _unpack_cancel_events without the registry's
    closed-session bound.
    """
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        )
    )
    try:
        created = service.create_session(str(binary))
        assert created.ok and created.data is not None, created.error
        session_id = created.data["session"]["id"]
        original_plan = service.unpack_plan

        def plan_then_close(*args, **kwargs):
            planned = original_plan(*args, **kwargs)
            assert planned.ok, planned.error
            closed = service.close_session(session_id)
            assert closed.ok, closed.error
            return planned

        monkeypatch.setattr(service, "unpack_plan", plan_then_close)

        result = service.unpack_start(session_id, use_die=False, execute_upx=False)

        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_request"
        assert session_id not in service._unpack_cancel_events
    finally:
        service.close_all()