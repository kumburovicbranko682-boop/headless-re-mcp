"""Bounded probe on unpack.start for native/VM routes."""

from __future__ import annotations

import struct
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.session import UnpackPhase, create_unpack_session, transition
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker


def _write_pe(path: Path, *, upx_sections: bool = False) -> None:
    image = bytearray(0x400)
    pe_offset = 0x80
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\0\0"
    file_header = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH",
        image,
        file_header,
        0x8664,
        2 if upx_sections else 1,
        0,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000 if upx_sections else 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    if upx_sections:
        image[section : section + 8] = b"UPX0\0\0\0\0"
        struct.pack_into("<IIII", image, section + 8, 0x1000, 0x1000, 0, 0)
        struct.pack_into("<I", image, section + 36, 0xE0000000)
        section2 = section + 40
        image[section2 : section2 + 8] = b"UPX1\0\0\0\0"
        struct.pack_into("<IIII", image, section2 + 8, 0x200, 0x2000, 0x200, 0x200)
        struct.pack_into("<I", image, section2 + 36, 0xE0000020)
        image[0x200:0x202] = b"\xC3\x90"
    else:
        image[section : section + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", image, section + 36, 0x60000020)
        image[0x200:0x202] = b"\xC3\x90"
    path.write_bytes(image)


def test_bounded_probe_when_dynamic_open(tmp_path: Path) -> None:
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

    # Force generic_dynamic path by starting from a manually seeded session state
    # after plan would say none — call probe helper via unpack_start with ASPack-like
    # finding injected through classify is heavy; exercise helper via start after
    # faking route by calling the private probe after creating running state.
    state = create_unpack_session(session_id, route="bounded_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="run")
    state, probe = service._bounded_runtime_probe(
        state,
        session_id,
        route="bounded_dynamic",
    )
    assert probe["dynamic_open"] is True
    assert probe["module_base"] == worker.module_base
    assert probe["claims_universal_unpack"] is False
    assert state.module_base == worker.module_base
    # Fake worker may or may not be "paused"; either scored or deferred is fine.
    assert "oep_scored" in probe
