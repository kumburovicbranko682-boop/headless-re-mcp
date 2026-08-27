"""unpack_dump_module stage-guard/headers paths and unpack_stub_coupling paths.

The happy M4 flow never trips the mid-dump guards or a headers failure, and it
does not exercise stub coupling at all. These drive those branches through the
real service against fake workers.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import FakeDynamicWorker, FakeStaticWorker

_MODULE_BASE = 0x140000000


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
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _service(tmp_path: Path, worker: FakeDynamicWorker) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
    )
    return AnalysisService(
        settings,
        dynamic_worker_factory=lambda session, cfg: worker,
        static_worker_factory=lambda session, cfg: FakeStaticWorker(),
    )


def _open_session(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session_id = str(created.data["session"]["id"])
    assert service.open_dynamic(session_id).ok
    return session_id


def _blocked(stage: str) -> Result[dict[str, object]]:
    return Result(
        ok=False,
        error=RpcError(code="unpack_active", message=f"blocked at {stage}"),
        meta={"unpack": {"stage": stage}},
    )


def _stage_blocker(target: str):  # type: ignore[no-untyped-def]
    def guard(session_id: str, *, stage: str) -> Result[dict[str, object]] | None:
        return _blocked(stage) if stage == target else None

    return guard


def test_dump_aborts_when_the_headers_stage_guard_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("dump_module_headers"))

    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)

    assert not result.ok and result.data is not None
    assert result.data["aborted_after_dump"] is True
    assert result.data["partial_artifacts_retained"] is True
    assert result.data["safe_rollback"] is False
    assert result.data["claims_universal_unpack"] is False


def test_dump_records_a_headers_failure_but_still_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)

    def failing_headers(sid: str, base: int, **kwargs: object) -> Result[dict[str, object]]:
        return Result(ok=False, error=RpcError(code="headers_unreadable", message="no headers"))

    monkeypatch.setattr(service, "pe_headers_runtime", failing_headers)

    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)

    assert result.ok and result.data is not None
    assert result.data["headers_ok"] is False
    assert result.data["headers"] is None
    assert result.data["headers_error"]["code"] == "headers_unreadable"


def test_dump_aborts_when_the_advance_stage_guard_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("dump_module_advance"))

    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)

    assert not result.ok and result.data is not None
    assert result.data["aborted_before_phase_advance"] is True
    assert result.data["partial_artifacts_retained"] is True
    assert result.data["safe_rollback"] is False


def test_stub_coupling_analyzes_a_dump_inside_the_artifact_root(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)
    dumped = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)
    assert dumped.ok and dumped.data is not None
    dump_path = str(dumped.data["output_path"])

    result = service.unpack_stub_coupling(session_id, dump_path)

    assert result.ok and result.data is not None
    assert "stub_coupling" in result.data
    assert result.data["claims_universal_unpack"] is False
    assert result.data["stage_label"]


def test_stub_coupling_rejects_a_dump_outside_the_artifact_root(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)
    outsider = tmp_path / "loose.bin"
    outsider.write_bytes(b"\x00" * 64)

    result = service.unpack_stub_coupling(session_id, str(outsider))

    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_stub_coupling_blocked_by_the_stage_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("stub_coupling"))

    result = service.unpack_stub_coupling(session_id, str(tmp_path / "artifacts"))

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_stub_coupling_of_a_missing_dump_fails_cleanly(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)

    result = service.unpack_stub_coupling(session_id, str(tmp_path / "artifacts" / "gone.bin"))

    assert not result.ok and result.error is not None


def test_dump_returns_early_when_the_first_stage_guard_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)
    monkeypatch.setattr(service, "_guard_unpack_active", _stage_blocker("dump_module"))

    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)

    assert not result.ok and result.error is not None
    assert result.error.code == "unpack_active"


def test_dump_propagates_a_failed_module_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)

    def failing_dump(sid: str, base: int, **kwargs: object) -> Result[dict[str, object]]:
        return Result(ok=False, error=RpcError(code="dump_failed", message="no module"))

    monkeypatch.setattr(service, "modules_dump", failing_dump)

    result = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)

    assert not result.ok and result.error is not None
    assert result.error.code == "dump_failed"


def test_stub_coupling_emits_a_rebuild_gate_hint_when_analysis_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the parse reports ok, the method derives a layout-less rebuild gate
    # hint and a pause-quality read from the stub statistics alone.
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    session_id = _open_session(service, binary)
    dumped = service.unpack_dump_module(session_id, _MODULE_BASE, size=0x200)
    assert dumped.ok and dumped.data is not None
    dump_path = str(dumped.data["output_path"])

    from headless_re_mcp.core import service_unpack

    def fake_coupling(path: object, **kwargs: object) -> dict[str, object]:
        return {
            "ok": True,
            "still_vm_stub_count": 2,
            "api_call_site_count": 5,
            "code_nonzero_ratio": 0.3,
        }

    monkeypatch.setattr(service_unpack, "analyze_dump_stub_coupling", fake_coupling)

    result = service.unpack_stub_coupling(session_id, dump_path)

    assert result.ok and result.data is not None
    assert result.data["rebuild_gate_hint"] is not None
    assert result.data["pause_quality"] is not None
