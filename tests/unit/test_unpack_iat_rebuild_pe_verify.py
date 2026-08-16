"""unpack.iat.rebuild must not treat a failed PE self-check as IAT-complete."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection import PeFormatError
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
    struct.pack_into("<HHIIIHH", image, file_header, 0x8664, 2, 0, 0, 0, 0xF0, 0x2022)
    optional = file_header + 20
    struct.pack_into("<HBB", image, optional, 0x20B, 14, 0)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x140000000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x3000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[section + 40 : section + 48] = b".rdata\0\0"
    struct.pack_into("<IIII", image, section + 48, 0x200, 0x2000, 0x200, 0)
    struct.pack_into("<I", image, section + 76, 0x40000040)
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


def _ready_iat_rebuild(tmp_path: Path) -> tuple[AnalysisService, str, Path, FakeDynamicWorker]:
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
    pe = binary.read_bytes()
    mem_image = bytearray(0x3000)
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
    return service, session_id, dump_file, worker


def test_iat_rebuild_does_not_succeed_when_pe_self_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def _broken_scan_pe(path: Path, **kwargs: object) -> object:
        raise PeFormatError("built-in parser rejected the rebuilt image")

    monkeypatch.setattr("headless_re_mcp.core.service_unpack.scan_pe", _broken_scan_pe)

    rebuilt = service.unpack_iat_rebuild(
        session_id,
        str(dump_file),
        iat_va=worker.module_base + 0x2000,
        size=0x20,
        oep_rva=0x1000,
    )

    assert rebuilt.ok is False
    assert rebuilt.error is not None
    assert rebuilt.error.code == "invalid_pe"
    assert rebuilt.data is not None
    pe_verify = rebuilt.data.get("pe_verify")
    assert isinstance(pe_verify, dict)
    assert pe_verify.get("ok") is False
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.OEP_CANDIDATE
    assert not any(item.kind == "iat_rebuilt" for item in state.artifacts)


def test_pe_rebuild_does_not_succeed_when_pe_self_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, dump_file, worker = _ready_iat_rebuild(tmp_path)

    def _broken_scan_pe(path: Path, **kwargs: object) -> object:
        raise PeFormatError("built-in parser rejected the rebuilt image")

    monkeypatch.setattr("headless_re_mcp.core.service_unpack.scan_pe", _broken_scan_pe)

    rebuilt = service.unpack_pe_rebuild(
        session_id,
        str(dump_file),
        entry_point_rva=0x1000,
        iat_va=worker.module_base + 0x2000,
        iat_size=0x20,
    )

    assert rebuilt.ok is False
    assert rebuilt.error is not None
    assert rebuilt.error.code == "invalid_pe"
    assert rebuilt.data is not None
    pe_verify = rebuilt.data.get("pe_verify")
    assert isinstance(pe_verify, dict)
    assert pe_verify.get("ok") is False
    state = service._unpack_sessions[session_id]
    assert state.phase == UnpackPhase.OEP_CANDIDATE
    assert not any(item.kind == "pe_rebuilt" for item in state.artifacts)
