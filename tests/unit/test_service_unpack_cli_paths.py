"""Guard, probe, and error-arm coverage for UnpackCliMixin.

These wrappers front the optional external unpackers (official UPX, XVLKC,
upstream VMPDump, Scylla). None of those executables exist in CI, so this file
drives the platform-independent arms directly: the "not configured" and
"input changed after session creation" guards, the ``unpack.external.probe``
status branches, the caller-cancel / structured-error handlers on each runner,
and the ``unpack.auto`` fan-out. Runners are replaced with in-process fakes so
no subprocess is ever launched.
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.scylla import ScyllaError
from headless_re_mcp.unpack.vmp_dumper import VmpDumperError
from headless_re_mcp.unpack.xvlkc import XvlkcError

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    """A PE32+ image that satisfies scan_pe (the unpack paths scan the input)."""
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


def _touch(path: Path, data: bytes = b"placeholder") -> Path:
    path.write_bytes(data)
    return path


def _make_service(
    tmp_path: Path,
    *,
    upx: Path | None = None,
    diec: Path | None = None,
    xvlkc: Path | None = None,
    vmp_dumper: Path | None = None,
    scylla: Path | None = None,
) -> AnalysisService:
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        upx=upx,
        diec=diec,
        xvlkc=xvlkc,
        vmp_dumper=vmp_dumper,
        scylla=scylla,
    )
    return AnalysisService(settings)


def _session(service: AnalysisService, tmp_path: Path, name: str = "sample.exe") -> str:
    binary = tmp_path / name
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _code(result: Result[JsonObject]) -> str | None:
    return result.error.code if result.error is not None else None


class _FakeUpxResult:
    def __init__(self, output_path: Path, output_sha256: str) -> None:
        self.output_path = output_path
        self.output_sha256 = output_sha256

    def to_dict(self) -> JsonObject:
        return {"tool": "upx", "output_path": str(self.output_path)}


def _raise_cancel(*_args: Any, **_kwargs: Any) -> Any:
    raise BoundedCancelled()


# --------------------------------------------------------------------------- #
# unpack.upx.test / unpack.upx.unpack guards
# --------------------------------------------------------------------------- #
def test_upx_test_capability_unavailable(tmp_path: Path) -> None:
    service = _make_service(tmp_path, upx=None)
    try:
        session_id = _session(service, tmp_path)
        result = service.unpack_upx_test(session_id)
        assert _code(result) == "capability_unavailable"
    finally:
        service.close_all()


def test_upx_test_reports_input_changed(tmp_path: Path) -> None:
    service = _make_service(tmp_path, upx=_touch(tmp_path / "upx.exe"))
    try:
        binary = tmp_path / "sample.exe"
        session_id = _session(service, tmp_path)
        binary.write_bytes(b"tampered-after-session")
        result = service.unpack_upx_test(session_id)
        assert _code(result) == "input_changed"
        assert result.error is not None
        assert result.error.details["session_id"] == session_id
    finally:
        service.close_all()


def test_upx_unpack_rejects_non_bool_open_ida(tmp_path: Path) -> None:
    service = _make_service(tmp_path, upx=_touch(tmp_path / "upx.exe"))
    try:
        session_id = _session(service, tmp_path)
        result = service.unpack_upx_unpack(session_id, open_ida="yes")  # type: ignore[arg-type]
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()


def test_upx_unpack_capability_unavailable(tmp_path: Path) -> None:
    service = _make_service(tmp_path, upx=None)
    try:
        session_id = _session(service, tmp_path)
        result = service.unpack_upx_unpack(session_id)
        assert _code(result) == "capability_unavailable"
    finally:
        service.close_all()


def test_upx_unpack_reports_input_changed(tmp_path: Path) -> None:
    service = _make_service(tmp_path, upx=_touch(tmp_path / "upx.exe"))
    try:
        binary = tmp_path / "sample.exe"
        session_id = _session(service, tmp_path)
        binary.write_bytes(b"tampered")
        result = service.unpack_upx_unpack(session_id)
        assert _code(result) == "input_changed"
    finally:
        service.close_all()


def test_upx_unpack_flags_architecture_mismatch(tmp_path: Path, monkeypatch: Any) -> None:
    service = _make_service(tmp_path, upx=_touch(tmp_path / "upx.exe"))
    try:
        binary = tmp_path / "sample.exe"
        session_id = _session(service, tmp_path)
        out = tmp_path / "artifacts" / "out.exe"

        def _unpacker(_upx: Any, _inp: Any, _out: Any, **_kw: Any) -> _FakeUpxResult:
            return _FakeUpxResult(out, "0" * 64)

        service._upx_unpacker = _unpacker  # type: ignore[assignment]

        def _fake_scan(target: Any, *_a: Any, **_k: Any) -> Any:
            arch = "x64" if Path(target) == binary else "x86"
            pe = SimpleNamespace(
                entry_point_rva=0x1000,
                sections=[object()],
                imports=SimpleNamespace(function_count=3),
            )
            return SimpleNamespace(architecture=arch, pe=pe)

        monkeypatch.setattr("headless_re_mcp.core.service_unpack_cli.scan_pe", _fake_scan)
        result = service.unpack_upx_unpack(session_id, open_ida=False)
        assert _code(result) == "architecture_mismatch"
    finally:
        service.close_all()


def test_upx_unpack_records_die_rescan_failure(tmp_path: Path) -> None:
    service = _make_service(
        tmp_path,
        upx=_touch(tmp_path / "upx.exe"),
        diec=_touch(tmp_path / "diec.exe"),
    )
    try:
        session_id = _session(service, tmp_path)
        input_path = Path(service.registry.get(session_id).require_pe())

        def _unpacker(_upx: Any, inp: Any, out: Any, **_kw: Any) -> _FakeUpxResult:
            Path(out).write_bytes(Path(inp).read_bytes())
            return _FakeUpxResult(Path(out), file_sha256(Path(out)))

        def _die(*_a: Any, **_k: Any) -> Any:
            raise DieScanError("die_failed", "diec exploded")

        service._upx_unpacker = _unpacker  # type: ignore[assignment]
        service._die_scanner = _die
        assert input_path.is_file()
        result = service.unpack_upx_unpack(session_id, open_ida=False)
        assert result.ok and result.data is not None
        assert result.data["die_rescan"]["status"] == "failed"
    finally:
        service.close_all()


def test_upx_unpack_reanalyze_success(tmp_path: Path) -> None:
    service = _make_service(tmp_path, upx=_touch(tmp_path / "upx.exe"))
    try:
        session_id = _session(service, tmp_path)

        def _unpacker(_upx: Any, inp: Any, out: Any, **_kw: Any) -> _FakeUpxResult:
            Path(out).write_bytes(Path(inp).read_bytes())
            return _FakeUpxResult(Path(out), file_sha256(Path(out)))

        service._upx_unpacker = _unpacker  # type: ignore[assignment]
        service.create_session = lambda _b: Result[JsonObject](  # type: ignore[misc, assignment]
            ok=True, data={"session": {"id": "child-id"}}, error=None
        )
        service.open_static = lambda _s: Result[JsonObject](  # type: ignore[assignment]
            ok=True, data={"opened": True}, error=None
        )
        result = service.unpack_upx_unpack(session_id, open_ida=True)
        assert result.ok and result.data is not None
        assert result.data["reanalyze"]["static_open_ok"] is True
    finally:
        service.close_all()


def test_upx_unpack_reanalyze_child_failure(tmp_path: Path) -> None:
    service = _make_service(tmp_path, upx=_touch(tmp_path / "upx.exe"))
    try:
        session_id = _session(service, tmp_path)

        def _unpacker(_upx: Any, inp: Any, out: Any, **_kw: Any) -> _FakeUpxResult:
            Path(out).write_bytes(Path(inp).read_bytes())
            return _FakeUpxResult(Path(out), file_sha256(Path(out)))

        service._upx_unpacker = _unpacker  # type: ignore[assignment]
        service.create_session = lambda _b: Result[JsonObject](  # type: ignore[misc, assignment]
            ok=False,
            data=None,
            error=RpcError(code="invalid_request", message="bad child"),
        )
        result = service.unpack_upx_unpack(session_id, open_ida=True)
        assert result.ok and result.data is not None
        assert result.data["reanalyze"]["static_open_ok"] is False
        assert result.data["reanalyze"]["error"]["code"] == "invalid_request"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# unpack.external.probe status branches
# --------------------------------------------------------------------------- #
def test_external_probe_reports_blocked_when_not_a_file(tmp_path: Path) -> None:
    service = _make_service(
        tmp_path,
        xvlkc=tmp_path / "missing-xvlkc",
        vmp_dumper=tmp_path / "missing-vmp",
        scylla=tmp_path / "missing-scylla",
    )
    try:
        session_id = _session(service, tmp_path)
        result = service.unpack_external_probe(session_id)
        assert result.ok and result.data is not None
        assert result.data["xvlkc"]["status"] == "blocked"
        assert result.data["vmp_dumper"]["status"] == "blocked"
        assert result.data["scylla"]["status"] == "blocked"
    finally:
        service.close_all()


def test_external_probe_runs_probes_when_present(tmp_path: Path, monkeypatch: Any) -> None:
    service = _make_service(
        tmp_path,
        xvlkc=_touch(tmp_path / "xvlkc.exe"),
        vmp_dumper=_touch(tmp_path / "vmp.exe"),
        scylla=_touch(tmp_path / "scylla.exe"),
    )
    try:
        session_id = _session(service, tmp_path)
        monkeypatch.setattr(
            "headless_re_mcp.unpack.xvlkc.probe_xvlkc",
            lambda _exe, **_k: (True, "xvlkc banner"),
        )
        monkeypatch.setattr(
            "headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper",
            lambda _exe, **_k: (False, "vmp usage"),
        )
        monkeypatch.setattr(
            "headless_re_mcp.unpack.scylla.probe_scylla",
            lambda _exe, **_k: (True, ""),
        )
        result = service.unpack_external_probe(session_id)
        assert result.ok and result.data is not None
        assert result.data["xvlkc"]["status"] == "ready"
        assert result.data["xvlkc"]["probe_ok"] is True
        assert result.data["vmp_dumper"]["status"] == "blocked"
        assert result.data["scylla"]["status"] == "ready"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# XVLKC runner arms
# --------------------------------------------------------------------------- #
def test_xvlkc_reports_input_changed(tmp_path: Path) -> None:
    service = _make_service(tmp_path, xvlkc=_touch(tmp_path / "xvlkc.exe"))
    try:
        binary = tmp_path / "sample.exe"
        session_id = _session(service, tmp_path)
        binary.write_bytes(b"tampered")
        result = service.unpack_xvlkc_unpack(session_id)
        assert _code(result) == "input_changed"
    finally:
        service.close_all()


def test_xvlkc_cancel_surfaces_as_unpack_cancelled(tmp_path: Path) -> None:
    service = _make_service(tmp_path, xvlkc=_touch(tmp_path / "xvlkc.exe"))
    try:
        session_id = _session(service, tmp_path)
        service._xvlkc_runner = _raise_cancel
        result = service.unpack_xvlkc_unpack(session_id)
        assert _code(result) == "unpack_cancelled"
    finally:
        service.close_all()


def test_xvlkc_structured_error_is_preserved(tmp_path: Path) -> None:
    service = _make_service(tmp_path, xvlkc=_touch(tmp_path / "xvlkc.exe"))
    try:
        session_id = _session(service, tmp_path)

        def _runner(*_a: Any, **_k: Any) -> Any:
            raise XvlkcError("xvlkc_failed", "boom", details={"hint": "x"})

        service._xvlkc_runner = _runner
        result = service.unpack_xvlkc_unpack(session_id)
        assert _code(result) == "xvlkc_failed"
        assert result.error is not None
        assert result.error.details["hint"] == "x"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# VMPDump runner arms
# --------------------------------------------------------------------------- #
def test_vmp_reports_input_changed(tmp_path: Path) -> None:
    service = _make_service(tmp_path, vmp_dumper=_touch(tmp_path / "vmp.exe"))
    try:
        binary = tmp_path / "sample.exe"
        session_id = _session(service, tmp_path)
        binary.write_bytes(b"tampered")
        result = service.unpack_vmp_dump(session_id, pid=4321)
        assert _code(result) == "input_changed"
    finally:
        service.close_all()


def test_vmp_resolves_debuggee_from_dynamic_state(tmp_path: Path) -> None:
    service = _make_service(tmp_path, vmp_dumper=_touch(tmp_path / "vmp.exe"))
    try:
        session_id = _session(service, tmp_path)
        service.dynamic_state = lambda _s: Result[JsonObject](  # type: ignore[assignment]
            ok=True, data={"running": True}, error=None
        )
        service._annotate_debuggee_pids = lambda _s, _d: {"debuggee_pid": 4321}  # type: ignore[assignment]

        def _runner(*_a: Any, **_k: Any) -> Any:
            raise VmpDumperError("vmp_failed", "dump blew up")

        service._vmp_dumper_runner = _runner
        result = service.unpack_vmp_dump(session_id)
        assert _code(result) == "vmp_failed"
    finally:
        service.close_all()


def test_vmp_swallows_debuggee_resolution_errors(tmp_path: Path) -> None:
    service = _make_service(tmp_path, vmp_dumper=_touch(tmp_path / "vmp.exe"))
    try:
        session_id = _session(service, tmp_path)

        def _boom(_s: str) -> Any:
            raise RuntimeError("state unavailable")

        service.dynamic_state = _boom  # type: ignore[assignment]
        result = service.unpack_vmp_dump(session_id)
        assert _code(result) == "debuggee_required"
    finally:
        service.close_all()


def test_vmp_cancel_surfaces_as_unpack_cancelled(tmp_path: Path) -> None:
    service = _make_service(tmp_path, vmp_dumper=_touch(tmp_path / "vmp.exe"))
    try:
        session_id = _session(service, tmp_path)
        service._vmp_dumper_runner = _raise_cancel
        result = service.unpack_vmp_dump(session_id, pid=4321)
        assert _code(result) == "unpack_cancelled"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# Scylla runner arms
# --------------------------------------------------------------------------- #
def test_scylla_reports_input_changed(tmp_path: Path) -> None:
    service = _make_service(tmp_path, scylla=_touch(tmp_path / "scylla.exe"))
    try:
        binary = tmp_path / "sample.exe"
        session_id = _session(service, tmp_path)
        binary.write_bytes(b"tampered")
        result = service.unpack_scylla_rebuild(session_id)
        assert _code(result) == "input_changed"
    finally:
        service.close_all()


def test_scylla_cancel_surfaces_as_unpack_cancelled(tmp_path: Path) -> None:
    service = _make_service(tmp_path, scylla=_touch(tmp_path / "scylla.exe"))
    try:
        session_id = _session(service, tmp_path)
        service._scylla_runner = _raise_cancel
        result = service.unpack_scylla_rebuild(session_id)
        assert _code(result) == "unpack_cancelled"
    finally:
        service.close_all()


def test_scylla_structured_error_is_preserved(tmp_path: Path) -> None:
    service = _make_service(tmp_path, scylla=_touch(tmp_path / "scylla.exe"))
    try:
        session_id = _session(service, tmp_path)

        def _runner(*_a: Any, **_k: Any) -> Any:
            raise ScyllaError("scylla_failed", "iat rebuild failed")

        service._scylla_runner = _runner
        result = service.unpack_scylla_rebuild(session_id)
        assert _code(result) == "scylla_failed"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# unpack.auto fan-out
# --------------------------------------------------------------------------- #
def test_auto_reuses_active_session_status(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.unpack_start = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=False,
            data=None,
            error=RpcError(code="unpack_already_active", message="busy"),
        )
        service.unpack_status = lambda _s: Result[JsonObject](  # type: ignore[assignment]
            ok=False, data=None, error=RpcError(code="not_found", message="gone")
        )
        result = service.unpack_auto(session_id)
        assert _code(result) == "unpack_already_active"
    finally:
        service.close_all()


def test_auto_passes_through_non_dict_unpack(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.unpack_start = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True, data={"unpack": "not-a-dict"}, error=None
        )
        result = service.unpack_auto(session_id)
        assert result.ok and result.data is not None
        assert result.data["unpack"] == "not-a-dict"
    finally:
        service.close_all()


def test_auto_reports_dotnet_route_failure(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.unpack_start = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True,
            data={
                "unpack": {
                    "route": "dotnet",
                    "phase": "failed",
                    "failure": {"code": "dotnet_boom", "message": "no clr"},
                }
            },
            error=None,
        )
        result = service.unpack_auto(session_id)
        assert _code(result) == "dotnet_boom"
        assert result.error is not None
        assert result.error.details["next"] == ["dotnet.inspect"]
    finally:
        service.close_all()


def test_auto_reports_generic_dynamic_awaiting_oep(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        service.unpack_start = lambda *a, **k: Result[JsonObject](  # type: ignore[method-assign]
            ok=True,
            data={"unpack": {"route": "generic_dynamic", "phase": "observing"}},
            error=None,
        )
        result = service.unpack_auto(session_id)
        assert result.ok and result.data is not None
        assert result.data["status"] == "awaiting_oep"
        assert result.data["next"] == "unpack.confirm_oep"
    finally:
        service.close_all()


def test_auto_wraps_unexpected_errors(tmp_path: Path) -> None:
    service = _make_service(tmp_path)
    try:
        session_id = _session(service, tmp_path)

        def _boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("planner exploded")

        service.unpack_start = _boom  # type: ignore[method-assign]
        result = service.unpack_auto(session_id)
        assert result.ok is False
        assert result.error is not None
    finally:
        service.close_all()
