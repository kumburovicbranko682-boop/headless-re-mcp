"""Edge-path coverage for core/service_static.py.

Covers the optional start/end search parameters, the batch/patch validation
guards, and the oversized-text spill helper's write-failure and
registration-failure arms. These run without a live IDA worker: the search
methods build their params before the request is dispatched, and the spill
helper is driven directly.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_static
from headless_re_mcp.core.limits import MAX_STATIC_INLINE_TEXT
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


def _service(tmp_path: Path) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(settings)


def _pe_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


# --- search/patch/batch parameter and validation arms ---


def test_search_methods_accept_optional_bounds(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        # No IDA worker is configured, so each request fails, but the optional
        # start/end params are wired in before dispatch.
        for call in (
            service.static_search_bytes(
                session_id, pattern="90 90", start=0x1000, end=0x2000
            ),
            service.static_search_text(
                session_id, text="hello", start=0x1000, end=0x2000
            ),
            service.static_search_immediate(
                session_id, value=0x1234, start=0x1000, end=0x2000
            ),
        ):
            assert call.ok is False and call.error is not None
    finally:
        service.close_all()


def test_bytes_patch_accepts_base64(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.static_bytes_patch(session_id, address=0x1000, base64="kJA=")
        assert result.ok is False and result.error is not None
    finally:
        service.close_all()


def test_static_batch_rejects_a_non_list(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.static_batch(session_id, commands="not-a-list")  # type: ignore[arg-type]
        assert result.ok is False and result.error is not None
    finally:
        service.close_all()


# --- _maybe_spill_static_text arms ---


def test_spill_ignores_non_string_text(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        data = {"decompiled": 12345}
        out = service._maybe_spill_static_text(
            "sess", data, kind="decompile", text_key="decompiled"
        )
        assert out is data
    finally:
        service.close_all()


def test_spill_reports_a_write_failure(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = "spill-write"
        # Plant a regular file where the oversized/ directory should be so the
        # mkdir fails and the helper degrades to a preview + reason.
        oversized = (
            service.settings.artifact_root.expanduser().resolve()
            / "static"
            / session_id
        )
        oversized.mkdir(parents=True, exist_ok=True)
        (oversized / "oversized").write_bytes(b"not a directory")

        big = "Z" * (MAX_STATIC_INLINE_TEXT + 64)
        out = service._maybe_spill_static_text(
            session_id, {"listing": big}, kind="listing", text_key="listing"
        )
        assert out["truncated"] is True
        assert "spill_failed" in out
        assert "artifact" not in out
    finally:
        service.close_all()


def test_spill_reports_a_registration_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("cannot register artifact")

    monkeypatch.setattr(service_static, "_record_artifact", _boom)
    try:
        session_id = "spill-register"
        big = "Q" * (MAX_STATIC_INLINE_TEXT + 64)
        out = service._maybe_spill_static_text(
            session_id, {"listing": big}, kind="listing", text_key="listing"
        )
        assert out["truncated"] is True
        assert "artifact" in out  # the file was written
        assert "artifact_unregistered" in out
    finally:
        service.close_all()
