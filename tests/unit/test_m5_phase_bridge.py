"""Tests for M5 phase_bridge (6th-agent close-the-loop helpers)."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.phase_bridge import (
    note_dump_success,
    note_imports_rebuilt,
    note_verified,
)
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    create_unpack_session,
    transition,
)
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker


def test_phase_bridge_advances_dumped_imports_verified() -> None:
    state = create_unpack_session("s1", route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="run")
    state = transition(state, UnpackPhase.OEP_CANDIDATE, event="oep", message="oep")
    state = note_dump_success(
        state,
        output_path="C:/sample/tmp/dump.bin",
        sha256="a" * 64,
        module_base=0x140000000,
    )
    assert state.phase == UnpackPhase.DUMPED
    assert any(item.kind == "module_dump" for item in state.artifacts)

    state = note_imports_rebuilt(
        state,
        output_path="C:/sample/tmp/rebuilt.exe",
        sha256="b" * 64,
    )
    assert state.phase == UnpackPhase.IMPORTS_REBUILT

    state = note_verified(state, path="C:/sample/tmp/rebuilt.exe", sha256="b" * 64)
    assert state.phase == UnpackPhase.VERIFIED
    assert state.to_dict()["claims_universal_unpack"] is False


def test_note_verified_does_not_hop_from_oep_candidate() -> None:
    state = create_unpack_session("s1", route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="run")
    state = transition(state, UnpackPhase.OEP_CANDIDATE, event="oep", message="oep")
    updated = note_verified(state, path="C:/sample/tmp/dump.bin", sha256="a" * 64)
    assert updated.phase == UnpackPhase.OEP_CANDIDATE
    assert any(item.event == "verify_phase_skipped" for item in updated.timeline)


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


def test_confirm_oep_auto_dump_advances_session(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
        ),
        dynamic_worker_factory=lambda session, cfg: worker,
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
    )
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="run")
    service._store_unpack_session(state)

    result = service.unpack_confirm_oep(
        session_id,
        oep_rva=0x1000,
        module_base=worker.module_base,
        auto_dump=True,
    )
    assert result.ok and result.data is not None, result.error
    assert result.data["auto_dump"] is True
    assert result.data["unpack"]["phase"] == "dumped"
    assert result.data["dump"] is not None
    assert Path(str(result.data["dump"]["output_path"])).is_file()
