"""The unpack pipeline orchestrator must bound rebuilds, gate paths and stage state.

``UnpackMixin`` routes a session through dump -> IAT/PE rebuild -> verify and
tracks an unpack session state across the stages. The rebuild helpers refuse a
dump too large to hold in memory before allocating, every path argument must
resolve inside the session artifact root, and status/cancel/artifacts refuse
when no unpack session has been started. The dynamic backend is absent here, so
the file-driven rebuild/verify paths and the state machine are exercised
directly and the memory guard is pinned with an injected estimate.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.core import service_unpack
from headless_re_mcp.core.service import AnalysisService
from tests.unit.test_dynamic_service import (
    FakeDynamicWorker,
    _service,
)
from tests.unit.test_pe_rebuild import _make_runtime_dump

JsonObject = dict[str, Any]


def _write_scannable_pe(path: Path) -> None:
    """A minimal file-layout x64 PE (one .text section) that ``scan_pe`` accepts."""
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


def _session(tmp_path: Path) -> tuple[AnalysisService, str]:
    binary = tmp_path / "sample.exe"
    _write_scannable_pe(binary)
    service = _service(tmp_path, FakeDynamicWorker())
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    return service, str(session["id"])


def _artifact_dump(service: AnalysisService, session_id: str, data: bytes, name: str) -> Path:
    root = service.settings.artifact_root.expanduser().resolve()
    directory = root / "unpack" / session_id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(data)
    return path


# --------------------------------------------------------------------------
# rebuild memory-fit helpers
# --------------------------------------------------------------------------


def test_refuse_rebuild_allows_a_dump_that_fits(tmp_path: Path) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"\x00" * 1024)
    assert service_unpack._refuse_rebuild_that_will_not_fit(dump) is None


def test_refuse_rebuild_returns_none_when_the_path_is_gone(tmp_path: Path) -> None:
    # observed_size is derived from stat(); a missing path is a soft None so the
    # rebuild proceeds and fails later with a real, specific error.
    missing = tmp_path / "gone.bin"
    assert service_unpack._refuse_rebuild_that_will_not_fit(missing) is None


def test_refuse_rebuild_refuses_a_dump_that_will_not_fit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda size: (True, size * 4, 1024),
    )
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"\x00" * 4096)
    refusal = service_unpack._refuse_rebuild_that_will_not_fit(dump)
    assert refusal is not None
    assert refusal.error is not None and refusal.error.code == "dump_too_large"


def test_read_dump_for_rebuild_reads_the_whole_file(tmp_path: Path) -> None:
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"abc123")
    payload, refusal = service_unpack._read_dump_for_rebuild(dump)
    assert refusal is None
    assert payload == b"abc123"


def test_read_dump_for_rebuild_propagates_a_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda size: (True, size * 4, 1),
    )
    dump = tmp_path / "dump.bin"
    dump.write_bytes(b"\x00" * 32)
    payload, refusal = service_unpack._read_dump_for_rebuild(dump)
    assert payload is None
    assert refusal is not None and refusal.error is not None


# --------------------------------------------------------------------------
# unpack.pe.rebuild (file-driven, no dynamic backend)
# --------------------------------------------------------------------------


def test_pe_rebuild_remaps_a_runtime_dump(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    dump = _artifact_dump(service, session_id, _make_runtime_dump(), "dump.bin")
    result = service.unpack_pe_rebuild(session_id, str(dump))
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["pe_verify"]["ok"] is True
    assert Path(result.data["output_path"]).is_file()


def test_pe_rebuild_rejects_a_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    outside = tmp_path / "loose.bin"
    outside.write_bytes(_make_runtime_dump())
    result = service.unpack_pe_rebuild(session_id, str(outside))
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_params"


def test_pe_rebuild_rejects_a_missing_dump(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_pe_rebuild(session_id, str(tmp_path / "nope.bin"))
    assert result.ok is False and result.error is not None


def test_pe_rebuild_refuses_a_dump_too_large_for_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(tmp_path)
    dump = _artifact_dump(service, session_id, _make_runtime_dump(), "dump.bin")
    monkeypatch.setattr(
        service_unpack,
        "rebuild_would_exhaust_memory",
        lambda size: (True, size * 4, 1),
    )
    result = service.unpack_pe_rebuild(session_id, str(dump))
    assert result.ok is False and result.error is not None
    assert result.error.code == "dump_too_large"


# --------------------------------------------------------------------------
# unpack.iat.rebuild (path gate + delegate failure without a debuggee)
# --------------------------------------------------------------------------


def test_iat_rebuild_rejects_a_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    outside = tmp_path / "loose.bin"
    outside.write_bytes(_make_runtime_dump())
    result = service.unpack_iat_rebuild(session_id, str(outside), iat_va=0x1000, size=16)
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_params"


def test_iat_rebuild_without_a_debuggee_returns_the_read_failure(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    dump = _artifact_dump(service, session_id, _make_runtime_dump(), "dump.bin")
    # imports.read needs a paused debuggee; a static session has none, so the
    # rebuild surfaces that failure rather than proceeding blind.
    result = service.unpack_iat_rebuild(session_id, str(dump), iat_va=0x1000, size=16)
    assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------
# scan / validate / dump delegate to the dynamic backend
# --------------------------------------------------------------------------


def test_iat_scan_without_a_debuggee_fails(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_iat_scan(session_id, 0x140000000)
    assert result.ok is False and result.error is not None


def test_iat_validate_without_a_debuggee_fails(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_iat_validate(session_id, iat_va=0x1000, size=16)
    assert result.ok is False and result.error is not None


def test_dump_module_without_a_debuggee_fails(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_dump_module(session_id, 0x140000000)
    assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------
# unpack.stub_coupling (file-driven)
# --------------------------------------------------------------------------


def test_stub_coupling_analyzes_a_dump(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    dump = _artifact_dump(service, session_id, _make_runtime_dump(), "dump.bin")
    result = service.unpack_stub_coupling(session_id, str(dump))
    assert result.ok, result.error
    assert result.data is not None
    assert "stub_coupling" in result.data


def test_stub_coupling_rejects_a_path_outside_the_artifact_root(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    outside = tmp_path / "loose.bin"
    outside.write_bytes(_make_runtime_dump())
    result = service.unpack_stub_coupling(session_id, str(outside))
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_params"


def test_stub_coupling_rejects_a_missing_dump(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_stub_coupling(session_id, str(tmp_path / "nope.bin"))
    assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------
# unpack.verify (file-driven)
# --------------------------------------------------------------------------


def test_verify_reparses_a_rebuilt_pe(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    # A file-layout PE the built-in parser accepts, under the session dir.
    pe = _artifact_dump(service, session_id, _make_runtime_dump(), "candidate.exe")
    # Remap first so the on-disk file is file-aligned for scan_pe.
    rebuilt = service.unpack_pe_rebuild(session_id, str(pe))
    assert rebuilt.ok, rebuilt.error
    assert rebuilt.data is not None
    result = service.unpack_verify(session_id, str(rebuilt.data["output_path"]))
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["die"]["status"] == "unavailable"


def test_verify_rejects_a_path_outside_the_session_dir(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    outside = tmp_path / "loose.exe"
    outside.write_bytes(_make_runtime_dump())
    result = service.unpack_verify(session_id, str(outside))
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_params"


def test_verify_rejects_a_missing_path(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_verify(session_id, str(tmp_path / "nope.exe"))
    assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------
# unpack.plan
# --------------------------------------------------------------------------


def test_plan_builds_a_non_authoritative_plan(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_plan(session_id)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert "plan" in result.data


def test_plan_refuses_a_closed_session(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    assert service.close_session(session_id).ok
    result = service.unpack_plan(session_id)
    assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------
# unpack.start -> status / artifacts / cancel state machine
# --------------------------------------------------------------------------


def test_start_creates_a_session_then_status_and_artifacts_report_it(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    started = service.unpack_start(session_id, execute_upx=False)
    assert started.ok, started.error

    status = service.unpack_status(session_id)
    assert status.ok and status.data is not None
    assert "unpack" in status.data

    artifacts = service.unpack_artifacts(session_id)
    assert artifacts.ok and artifacts.data is not None
    assert "artifacts" in artifacts.data

    cancelled = service.unpack_cancel(session_id)
    assert cancelled.ok and cancelled.data is not None
    assert cancelled.data["original_input_preserved"] is True


@pytest.mark.parametrize(
    "op",
    [
        lambda s, sid: s.unpack_status(sid),
        lambda s, sid: s.unpack_artifacts(sid),
        lambda s, sid: s.unpack_cancel(sid),
    ],
)
def test_status_ops_report_no_unpack_session(tmp_path: Path, op: Any) -> None:
    service, session_id = _session(tmp_path)
    result = op(service, session_id)
    assert result.ok is False and result.error is not None
    assert result.error.code == "unpack_not_started"


# --------------------------------------------------------------------------
# unpack.score_oep
# --------------------------------------------------------------------------


def test_score_oep_ranks_supplied_observations(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    observations = [
        {"kind": "new_executable_region", "rva": 0x1000, "source": "test"},
        {"kind": "entry_point_hit", "rva": 0x1000, "source": "test"},
    ]
    result = service.unpack_score_oep(
        session_id,
        module_base=0x140000000,
        module_size=0x10000,
        observations=observations,
    )
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["authoritative"] is False
    assert result.data["auto_collected"] is False


def test_score_oep_without_a_debuggee_reports_the_collection_failure(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    # No observations -> auto-collect from the dynamic backend, which is absent.
    result = service.unpack_score_oep(
        session_id,
        module_base=0x140000000,
        module_size=0x10000,
    )
    assert result.ok is False and result.error is not None


# --------------------------------------------------------------------------
# unpack.confirm_oep guards
# --------------------------------------------------------------------------


def test_confirm_oep_rejects_a_negative_rva(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_confirm_oep(session_id, oep_rva=-1)
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_params"


def test_confirm_oep_rejects_a_non_boolean_auto_dump(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_confirm_oep(
        session_id, oep_rva=0x1000, auto_dump="yes"  # type: ignore[arg-type]
    )
    assert result.ok is False and result.error is not None
    assert result.error.code == "invalid_params"


def test_confirm_oep_reports_no_unpack_session(tmp_path: Path) -> None:
    service, session_id = _session(tmp_path)
    result = service.unpack_confirm_oep(session_id, oep_rva=0x1000)
    assert result.ok is False and result.error is not None
    assert result.error.code == "unpack_not_started"
