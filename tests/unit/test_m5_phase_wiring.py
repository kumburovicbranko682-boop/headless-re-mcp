"""M5 dump/IAT/verify paths must advance UnpackSessionState phases."""

from __future__ import annotations

import struct
from dataclasses import replace
from pathlib import Path

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    add_artifact,
    create_unpack_session,
    transition,
)
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker


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


def _service(tmp_path: Path, dynamic: FakeDynamicWorker) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: dynamic,
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
    )


def _seed_oep_candidate(service: AnalysisService, session_id: str) -> None:
    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    state = transition(
        state,
        UnpackPhase.OEP_CANDIDATE,
        event="oep_ready",
        message="oep candidate",
    )
    state = replace(state, confirmed_oep_rva=0x1000)
    service._store_unpack_session(state)


def test_dump_rebuild_verify_advances_phases(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok
    _seed_oep_candidate(service, session_id)

    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x200)
    assert dumped.ok and dumped.data is not None
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.DUMPED
    assert any(item.kind == "module_dump" for item in state.artifacts)
    dump_sha = str(dumped.data["sha256"])
    assert any(item.sha256 == dump_sha for item in state.artifacts)
    assert any(item.event == "module_dumped" for item in state.timeline)

    dump_path = str(dumped.data["output_path"])
    Path(dump_path).write_bytes(binary.read_bytes())
    rebuilt = service.unpack_pe_rebuild(
        session_id,
        dump_path,
        entry_point_rva=0x1000,
        iat_va=worker.module_base + 0x2000,
        iat_size=0x20,
    )
    assert rebuilt.ok and rebuilt.data is not None
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.IMPORTS_REBUILT
    assert any(item.kind == "pe_rebuilt" for item in state.artifacts)
    assert any(item.event == "imports_rebuilt" for item in state.timeline)

    verified = service.unpack_verify(
        session_id,
        str(rebuilt.data["output_path"]),
        use_die=False,
        open_ida=False,
    )
    assert verified.ok and verified.data is not None
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.VERIFIED
    assert any(item.kind == "verified_pe" for item in state.artifacts)
    assert any(item.event == "verified" for item in state.timeline)


def test_dump_advances_from_running_with_confirmed_oep(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    state = replace(state, confirmed_oep_rva=0x1500)
    service._store_unpack_session(state)

    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x200)
    assert dumped.ok
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.DUMPED
    assert any(item.event == "oep_confirmed_pre_dump" for item in state.timeline)
    assert any(item.event == "module_dumped" for item in state.timeline)


def test_iat_rebuild_advances_from_oep_candidate_with_dump_artifact(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    dump_file = (
        service.settings.artifact_root.expanduser().resolve()
        / "unpack"
        / session_id
        / "pre-dump.bin"
    )
    dump_file.parent.mkdir(parents=True, exist_ok=True)
    # Memory-layout dump: .text at RVA 0x1000 must be non-zero for rebuild_gate.
    pe = binary.read_bytes()
    mem_image = bytearray(0x2100)
    mem_image[: len(pe)] = pe
    mem_image[0x1000:0x1100] = b"\x90" * 0x100
    dump_file.write_bytes(mem_image)

    state = create_unpack_session(session_id, route="generic_dynamic")
    state = transition(state, UnpackPhase.RUNNING, event="run", message="running")
    state = transition(
        state,
        UnpackPhase.OEP_CANDIDATE,
        event="oep_ready",
        message="oep candidate",
    )
    state = add_artifact(
        state,
        kind="module_dump",
        path=str(dump_file),
        sha256="a" * 64,
        phase=UnpackPhase.DUMPED,
    )
    service._store_unpack_session(state)

    rebuilt = service.unpack_iat_rebuild(
        session_id,
        str(dump_file),
        iat_va=worker.module_base + 0x2000,
        size=0x20,
        oep_rva=0x1000,
    )
    assert rebuilt.ok and rebuilt.data is not None
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.IMPORTS_REBUILT
    assert any(item.event == "dump_inferred" for item in state.timeline)
    assert any(item.kind == "iat_rebuilt" for item in state.artifacts)


def test_no_unpack_session_keeps_dump_working(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok

    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x200)
    assert dumped.ok and dumped.data is not None
    assert session_id not in service._unpack_sessions

    dump_path = str(dumped.data["output_path"])
    Path(dump_path).write_bytes(binary.read_bytes())
    rebuilt = service.unpack_pe_rebuild(
        session_id,
        dump_path,
        entry_point_rva=0x1000,
        iat_va=worker.module_base + 0x2000,
        iat_size=0x20,
    )
    assert rebuilt.ok
    verified = service.unpack_verify(
        session_id,
        str(rebuilt.data["output_path"]),
        use_die=False,
    )
    assert verified.ok
    assert session_id not in service._unpack_sessions


def test_pe_rebuild_without_iat_does_not_claim_imports_rebuilt(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    worker = FakeDynamicWorker()
    service = _service(tmp_path, worker)
    session_id = service.create_session(str(binary)).data["session"]["id"]
    assert service.open_dynamic(session_id).ok
    _seed_oep_candidate(service, session_id)

    dumped = service.unpack_dump_module(session_id, worker.module_base, size=0x200)
    assert dumped.ok
    dump_path = str(dumped.data["output_path"])
    Path(dump_path).write_bytes(binary.read_bytes())

    rebuilt = service.unpack_pe_rebuild(
        session_id,
        dump_path,
        entry_point_rva=0x1000,
    )
    assert rebuilt.ok
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.DUMPED
    assert not any(item.event == "imports_rebuilt" for item in state.timeline)
