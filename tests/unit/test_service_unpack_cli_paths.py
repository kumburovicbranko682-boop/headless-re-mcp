"""Failure- and branch-path tests for the UPX / external unpack CLI mixin.

These exercise the guards, tool-error remapping, and secondary branches in
``UnpackCliMixin`` that the happy-path adapter tests in
``test_m7_external_adapters`` do not reach: capability/input-change guards,
architecture mismatch, DIE-rescan failure, ``open_ida`` re-analysis, the
external-probe blocked/ready arms, caller-cancel and tool-error mapping for the
optional dumpers, and the ``unpack.auto`` route dispatch.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.scylla import ScyllaError, ScyllaResult
from headless_re_mcp.unpack.session import UnpackPhase
from headless_re_mcp.unpack.upx import UpxOperation, UpxResult
from headless_re_mcp.unpack.vmp_dumper import VmpDumperError, VmpDumperResult
from headless_re_mcp.unpack.xvlkc import XvlkcError, XvlkcResult

JsonObject = dict[str, Any]

_SETTINGS_KEYS = {"upx", "diec", "xvlkc", "vmp_dumper", "scylla"}
_RUNNER_KEYS = {
    "upx_tester",
    "upx_unpacker",
    "die_scanner",
    "xvlkc_runner",
    "vmp_dumper_runner",
    "scylla_runner",
}


def _write_minimal_pe(path: Path) -> None:
    """A scan_pe-valid PE32 (positive alignments, one section, no directories)."""
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
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", image, optional + 56, 0x2000, 0x200)
    struct.pack_into("<HH", image, optional + 68, 3, 0x8160)
    struct.pack_into("<I", image, optional + 92, 16)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x100, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x202] = b"\xc3\x90"
    path.write_bytes(image)


def _write_pe64(path: Path) -> None:
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


def _service(tmp_path: Path, **kwargs: Any) -> AnalysisService:
    settings_kw = {k: v for k, v in kwargs.items() if k in _SETTINGS_KEYS}
    runner_kw = {k: v for k, v in kwargs.items() if k in _RUNNER_KEYS}
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        **settings_kw,
    )
    return AnalysisService(settings, **runner_kw)


def _pe_session(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _tool(tmp_path: Path, name: str) -> Path:
    path = tmp_path / name
    path.write_bytes(b"placeholder")
    return path


def _upx_result(executable: Path, input_path: Path, output_path: Path) -> UpxResult:
    return UpxResult(
        operation=UpxOperation.UNPACK,
        executable=executable,
        input_path=input_path,
        input_sha256=file_sha256(input_path),
        input_size=input_path.stat().st_size,
        output_path=output_path,
        output_sha256=file_sha256(output_path),
        output_size=output_path.stat().st_size,
        version="4.0",
        ok=True,
        stdout="unpacked",
        stderr="",
        returncode=0,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )


# --- unpack.upx.test guards -------------------------------------------------


def test_upx_test_reports_missing_cli(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, upx=None)
    session_id = _pe_session(service, binary)
    result = service.unpack_upx_test(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_upx_test_detects_input_change(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, upx=_tool(tmp_path, "upx"))
    session_id = _pe_session(service, binary)
    binary.write_bytes(binary.read_bytes() + b"tampered")
    result = service.unpack_upx_test(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "input_changed"


# --- unpack.upx.unpack guards and branches ----------------------------------


def test_upx_unpack_rejects_non_bool_open_ida(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, upx=_tool(tmp_path, "upx"))
    session_id = _pe_session(service, binary)
    result = service.unpack_upx_unpack(session_id, open_ida="yes")  # type: ignore[arg-type]
    assert not result.ok
    assert result.error is not None


def test_upx_unpack_reports_missing_cli(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, upx=None)
    session_id = _pe_session(service, binary)
    result = service.unpack_upx_unpack(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_upx_unpack_detects_input_change(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, upx=_tool(tmp_path, "upx"))
    session_id = _pe_session(service, binary)
    binary.write_bytes(binary.read_bytes() + b"tampered")
    result = service.unpack_upx_unpack(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_upx_unpack_flags_architecture_mismatch(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def fake_unpacker(executable: Path, input_path: Path, output_path: Path, **_: Any) -> UpxResult:
        _write_pe64(output_path)
        return _upx_result(executable, input_path, output_path)

    service = _service(tmp_path, upx=_tool(tmp_path, "upx"), upx_unpacker=fake_unpacker)
    session_id = _pe_session(service, binary)
    result = service.unpack_upx_unpack(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "architecture_mismatch"


def test_upx_unpack_records_die_failure_and_reanalysis(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def fake_unpacker(executable: Path, input_path: Path, output_path: Path, **_: Any) -> UpxResult:
        output_path.write_bytes(input_path.read_bytes())
        return _upx_result(executable, input_path, output_path)

    def boom_die(*_args: Any, **_kwargs: Any) -> Any:
        raise DieScanError("timeout", "diec stalled")

    service = _service(
        tmp_path,
        upx=_tool(tmp_path, "upx"),
        diec=_tool(tmp_path, "diec"),
        upx_unpacker=fake_unpacker,
        die_scanner=boom_die,
    )
    session_id = _pe_session(service, binary)
    result = service.unpack_upx_unpack(session_id, open_ida=True)
    assert result.ok and result.data is not None
    assert result.data["die_rescan"] == {"status": "failed", "error": "diec stalled"}
    reanalyze = result.data["reanalyze"]
    assert reanalyze is not None
    assert reanalyze["session"] is not None
    assert reanalyze["static_open_ok"] is False


def test_upx_unpack_reports_child_open_failure(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def fake_unpacker(executable: Path, input_path: Path, output_path: Path, **_: Any) -> UpxResult:
        output_path.write_bytes(input_path.read_bytes())
        return _upx_result(executable, input_path, output_path)

    service = _service(tmp_path, upx=_tool(tmp_path, "upx"), upx_unpacker=fake_unpacker)
    session_id = _pe_session(service, binary)

    def failing_create(*_args: Any, **_kwargs: Any) -> Result[JsonObject]:
        return Result(ok=False, error=RpcError(code="denied", message="no child"))

    service.create_session = failing_create  # type: ignore[method-assign]
    result = service.unpack_upx_unpack(session_id, open_ida=True)
    assert result.ok and result.data is not None
    reanalyze = result.data["reanalyze"]
    assert reanalyze == {
        "session": None,
        "static_open_ok": False,
        "error": {"code": "denied", "message": "no child", "details": {}, "retryable": False},
    }


# --- unpack.external.probe blocked/ready arms -------------------------------


def test_external_probe_reports_blocked_tools(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(
        tmp_path,
        xvlkc=tmp_path / "missing-xvlkc",
        vmp_dumper=tmp_path / "missing-vmp",
        scylla=tmp_path / "missing-scylla",
    )
    session_id = _pe_session(service, binary)
    result = service.unpack_external_probe(session_id)
    assert result.ok and result.data is not None
    assert result.data["xvlkc"]["status"] == "blocked"
    assert result.data["vmp_dumper"]["status"] == "blocked"
    assert result.data["scylla"]["status"] == "blocked"


def test_external_probe_reports_ready_tools(tmp_path: Path, monkeypatch: Any) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(
        tmp_path,
        xvlkc=_tool(tmp_path, "xvlkc"),
        vmp_dumper=_tool(tmp_path, "vmp"),
        scylla=_tool(tmp_path, "scylla"),
    )
    session_id = _pe_session(service, binary)
    monkeypatch.setattr(
        "headless_re_mcp.unpack.xvlkc.probe_xvlkc", lambda _p: (True, "xvlkc banner")
    )
    monkeypatch.setattr(
        "headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper", lambda _p: (True, "vmp banner")
    )
    monkeypatch.setattr(
        "headless_re_mcp.unpack.scylla.probe_scylla", lambda _p: (False, "scylla noise")
    )
    result = service.unpack_external_probe(session_id)
    assert result.ok and result.data is not None
    assert result.data["xvlkc"]["status"] == "ready"
    assert result.data["xvlkc"]["probe_ok"] is True
    assert result.data["vmp_dumper"]["status"] == "ready"
    assert result.data["scylla"]["status"] == "blocked"
    assert result.data["scylla"]["probe_ok"] is False


# --- unpack.xvlkc.unpack failure arms ---------------------------------------


def test_xvlkc_detects_input_change(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, xvlkc=_tool(tmp_path, "xvlkc"))
    session_id = _pe_session(service, binary)
    binary.write_bytes(binary.read_bytes() + b"tampered")
    result = service.unpack_xvlkc_unpack(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_xvlkc_reports_caller_cancel(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def cancel_runner(*_args: Any, **_kwargs: Any) -> XvlkcResult:
        raise BoundedCancelled()

    service = _service(tmp_path, xvlkc=_tool(tmp_path, "xvlkc"), xvlkc_runner=cancel_runner)
    session_id = _pe_session(service, binary)
    result = service.unpack_xvlkc_unpack(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "unpack_cancelled"


def test_xvlkc_maps_tool_error(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def failing_runner(*_args: Any, **_kwargs: Any) -> XvlkcResult:
        raise XvlkcError("output_missing", "no dump", details={"why": "x"})

    service = _service(tmp_path, xvlkc=_tool(tmp_path, "xvlkc"), xvlkc_runner=failing_runner)
    session_id = _pe_session(service, binary)
    result = service.unpack_xvlkc_unpack(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "output_missing"
    assert result.error.details == {"why": "x"}


# --- unpack.vmp.dump pid resolution and failure arms ------------------------


def test_vmp_detects_input_change(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, vmp_dumper=_tool(tmp_path, "vmp"))
    session_id = _pe_session(service, binary)
    binary.write_bytes(binary.read_bytes() + b"tampered")
    result = service.unpack_vmp_dump(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "input_changed"


def _vmp_result(executable: Path, input_path: Path, output_path: Path, pid: int) -> VmpDumperResult:
    return VmpDumperResult(
        executable=str(executable),
        input_path=str(input_path),
        output_path=str(output_path.resolve()),
        input_sha256=file_sha256(input_path),
        output_sha256=file_sha256(output_path),
        returncode=0,
        stdout="File written to: x",
        stderr="",
        duration_ms=1,
        dump_ok=True,
        imports_rebuilt=True,
        vm_restored=False,
        pid=pid,
        module_name="sample.exe",
        mode="process",
    )


def test_vmp_resolves_pid_from_dynamic_state(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def fake_runner(
        executable: Path, input_path: Path, output_path: Path, *, pid: int, **_: Any
    ) -> VmpDumperResult:
        assert pid == 4242
        output_path.write_bytes(input_path.read_bytes())
        return _vmp_result(executable, input_path, output_path, pid)

    service = _service(tmp_path, vmp_dumper=_tool(tmp_path, "vmp"), vmp_dumper_runner=fake_runner)
    session_id = _pe_session(service, binary)
    service.dynamic_state = lambda *_a, **_k: Result(ok=True, data={"paused": True})  # type: ignore[method-assign]
    service._annotate_debuggee_pids = lambda _sid, _state: {"debuggee_pid": 4242}  # type: ignore[method-assign]
    result = service.unpack_vmp_dump(session_id)
    assert result.ok and result.data is not None
    assert result.data["pid"] == 4242


def test_vmp_swallows_dynamic_state_error(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, vmp_dumper=_tool(tmp_path, "vmp"))
    session_id = _pe_session(service, binary)

    def boom(*_a: Any, **_k: Any) -> Result[JsonObject]:
        raise RuntimeError("state probe failed")

    service.dynamic_state = boom  # type: ignore[method-assign]
    result = service.unpack_vmp_dump(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "debuggee_required"


def test_vmp_reports_caller_cancel(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def cancel_runner(*_args: Any, **_kwargs: Any) -> VmpDumperResult:
        raise BoundedCancelled()

    service = _service(tmp_path, vmp_dumper=_tool(tmp_path, "vmp"), vmp_dumper_runner=cancel_runner)
    session_id = _pe_session(service, binary)
    service.registry.update_metadata(session_id, {"debuggee_pid": 4242})
    result = service.unpack_vmp_dump(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "unpack_cancelled"


def test_vmp_maps_tool_error(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def failing_runner(*_args: Any, **_kwargs: Any) -> VmpDumperResult:
        raise VmpDumperError("output_ambiguous", "two dumps", details={"n": 2})

    service = _service(
        tmp_path, vmp_dumper=_tool(tmp_path, "vmp"), vmp_dumper_runner=failing_runner
    )
    session_id = _pe_session(service, binary)
    service.registry.update_metadata(session_id, {"debuggee_pid": 4242})
    result = service.unpack_vmp_dump(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "output_ambiguous"
    assert result.error.details == {"n": 2}


# --- unpack.scylla.rebuild failure arms -------------------------------------


def test_scylla_detects_input_change(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    service = _service(tmp_path, scylla=_tool(tmp_path, "scylla"))
    session_id = _pe_session(service, binary)
    binary.write_bytes(binary.read_bytes() + b"tampered")
    result = service.unpack_scylla_rebuild(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_scylla_reports_caller_cancel(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def cancel_runner(*_args: Any, **_kwargs: Any) -> ScyllaResult:
        raise BoundedCancelled()

    service = _service(tmp_path, scylla=_tool(tmp_path, "scylla"), scylla_runner=cancel_runner)
    session_id = _pe_session(service, binary)
    result = service.unpack_scylla_rebuild(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "unpack_cancelled"


def test_scylla_maps_tool_error(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)

    def failing_runner(*_args: Any, **_kwargs: Any) -> ScyllaResult:
        raise ScyllaError("process_failed", "scylla crashed", details={"rc": 9})

    service = _service(tmp_path, scylla=_tool(tmp_path, "scylla"), scylla_runner=failing_runner)
    session_id = _pe_session(service, binary)
    result = service.unpack_scylla_rebuild(session_id)
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "process_failed"
    assert result.error.details == {"rc": 9}


# --- unpack.auto route dispatch ---------------------------------------------


def test_auto_returns_started_when_status_unavailable(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.unpack_start = lambda *_a, **_k: Result(  # type: ignore[method-assign]
        ok=False, error=RpcError(code="unpack_already_active", message="busy")
    )
    service.unpack_status = lambda *_a, **_k: Result(  # type: ignore[method-assign]
        ok=False, error=RpcError(code="not_found", message="gone")
    )
    result = service.unpack_auto("sid")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "unpack_already_active"


def test_auto_passes_through_non_dict_unpack(tmp_path: Path) -> None:
    service = _service(tmp_path)
    started = Result(ok=True, data={"unpack": "not-a-dict"})
    service.unpack_start = lambda *_a, **_k: started  # type: ignore[method-assign]
    result = service.unpack_auto("sid")
    assert result is started


def test_auto_reports_dotnet_route_failure(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.unpack_start = lambda *_a, **_k: Result(  # type: ignore[method-assign]
        ok=True,
        data={
            "unpack": {
                "route": "dotnet",
                "phase": UnpackPhase.FAILED.value,
                "failure": {"code": "clr_verify_failed", "message": "bad clr"},
            }
        },
    )
    result = service.unpack_auto("sid")
    assert not result.ok
    assert result.error is not None
    assert result.error.code == "clr_verify_failed"
    assert result.error.details["next"] == ["dotnet.inspect"]


def test_auto_reports_awaiting_oep_for_dynamic_route(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.unpack_start = lambda *_a, **_k: Result(  # type: ignore[method-assign]
        ok=True, data={"unpack": {"route": "generic_dynamic", "phase": "planned"}}
    )
    result = service.unpack_auto("sid")
    assert result.ok and result.data is not None
    assert result.data["status"] == "awaiting_oep"
    assert result.data["next"] == "unpack.confirm_oep"


def test_auto_wraps_unexpected_error(tmp_path: Path) -> None:
    service = _service(tmp_path)

    def boom(*_a: Any, **_k: Any) -> Result[JsonObject]:
        raise RuntimeError("planner blew up")

    service.unpack_start = boom  # type: ignore[method-assign]
    result = service.unpack_auto("sid")
    assert not result.ok
    assert result.error is not None
