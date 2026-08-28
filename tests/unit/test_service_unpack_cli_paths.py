"""Branch and error paths across the UPX / external unpack CLI mixin.

The happy fixture flows in ``test_upx_fixtures`` and ``test_unpack_auto`` need
the real official-UPX toolchain and are skipped on Linux CI. These drive the
remaining guard/branch/error arcs of ``UnpackCliMixin`` -- capability and
input-changed refusals, DIE rescans, IDA reanalyze, external-probe status
tri-states, cancel/typed-error mapping, VMP debuggee resolution, and the
``unpack_auto`` route dispatch -- against the real service with stubbed runners.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_unpack_cli
from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.scylla import ScyllaError
from headless_re_mcp.unpack.vmp_dumper import VmpDumperError
from headless_re_mcp.unpack.xvlkc import XvlkcError
from tests.unit.test_service_unpack_dump_and_stub_paths import _write_pe

JsonObject = dict[str, Any]


def _settings(tmp_path: Path, **tools: Any) -> Settings:
    return Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        **tools,
    )


def _service(tmp_path: Path, **tools: Any) -> tuple[AnalysisService, str, Path]:
    binary = tmp_path / "sample.exe"
    _write_pe(binary)
    service = AnalysisService(_settings(tmp_path, **tools))
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None
    return service, str(created.data["session"]["id"]), binary


class _FakeUpx:
    """Minimal stand-in for ``UpxResult`` as consumed by unpack_upx_unpack."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path
        self.output_sha256 = "0" * 64

    def to_dict(self) -> JsonObject:
        return {"ok": True}


class _FakeExt:
    """Minimal stand-in for the external dumper result dataclasses."""

    def __init__(self, output_path: str) -> None:
        self.output_path = output_path
        self.output_sha256 = "0" * 64
        self.dump_ok = True
        self.imports_rebuilt = True
        self.vm_restored = False

    def to_dict(self) -> JsonObject:
        return {"ok": True}


def _fake_scan(arch_for: Any) -> Any:
    def scan(path: Any, *args: Any, **kwargs: Any) -> Any:
        return SimpleNamespace(
            architecture=arch_for(str(path)),
            format="PE",
            pe=SimpleNamespace(
                entry_point_rva=0x1000,
                sections=[0, 0],
                imports=SimpleNamespace(function_count=3),
            ),
        )

    return scan


def _touch(path: Path) -> Path:
    path.write_text("stub", encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# unpack_upx_test
# --------------------------------------------------------------------------- #
def test_upx_test_refuses_when_upx_is_unconfigured(tmp_path: Path) -> None:
    service, session_id, _binary = _service(tmp_path)

    result = service.unpack_upx_test(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_upx_test_refuses_when_the_input_changed(tmp_path: Path) -> None:
    service, session_id, binary = _service(tmp_path, upx=tmp_path / "upx.exe")
    binary.write_bytes(b"MZ tampered payload")

    result = service.unpack_upx_test(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "input_changed"


# --------------------------------------------------------------------------- #
# unpack_upx_unpack
# --------------------------------------------------------------------------- #
def test_upx_unpack_rejects_a_non_boolean_open_ida(tmp_path: Path) -> None:
    service, session_id, _binary = _service(tmp_path, upx=tmp_path / "upx.exe")

    result = service.unpack_upx_unpack(session_id, open_ida="yes")  # type: ignore[arg-type]

    assert result.ok is False
    assert result.error is not None


def test_upx_unpack_refuses_when_upx_is_unconfigured(tmp_path: Path) -> None:
    service, session_id, _binary = _service(tmp_path)

    result = service.unpack_upx_unpack(session_id, open_ida=False)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_upx_unpack_refuses_when_the_input_changed(tmp_path: Path) -> None:
    service, session_id, binary = _service(tmp_path, upx=tmp_path / "upx.exe")
    binary.write_bytes(b"MZ tampered payload")

    result = service.unpack_upx_unpack(session_id, open_ida=False)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_upx_unpack_rejects_an_architecture_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(tmp_path, upx=tmp_path / "upx.exe")
    monkeypatch.setattr(
        service_unpack_cli,
        "scan_pe",
        _fake_scan(lambda p: "x86" if "upx-unpacked" in p else "x64"),
    )
    monkeypatch.setattr(service, "_upx_unpacker", lambda exe, inp, out, **kw: _FakeUpx(out))

    result = service.unpack_upx_unpack(session_id, open_ida=False)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "architecture_mismatch"


def test_upx_unpack_succeeds_without_a_die_rescan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(tmp_path, upx=tmp_path / "upx.exe")
    monkeypatch.setattr(service_unpack_cli, "scan_pe", _fake_scan(lambda p: "x64"))
    monkeypatch.setattr(service, "_upx_unpacker", lambda exe, inp, out, **kw: _FakeUpx(out))

    result = service.unpack_upx_unpack(session_id, open_ida=False)

    assert result.ok and result.data is not None
    assert result.data["die_rescan"] is None
    assert result.data["reanalyze"] is None


def test_upx_unpack_records_a_die_rescan_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(
        tmp_path, upx=tmp_path / "upx.exe", diec=tmp_path / "diec.exe"
    )
    monkeypatch.setattr(service_unpack_cli, "scan_pe", _fake_scan(lambda p: "x64"))
    monkeypatch.setattr(service, "_upx_unpacker", lambda exe, inp, out, **kw: _FakeUpx(out))

    def raising_die(*args: Any, **kwargs: Any) -> Any:
        raise DieScanError("die_process_failed", "diec exploded")

    monkeypatch.setattr(service, "_die_scanner", raising_die)

    result = service.unpack_upx_unpack(session_id, open_ida=False)

    assert result.ok and result.data is not None
    die_rescan = result.data["die_rescan"]
    assert isinstance(die_rescan, dict)
    assert die_rescan["status"] == "failed"


def test_upx_unpack_reanalyzes_a_child_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(tmp_path, upx=tmp_path / "upx.exe")
    monkeypatch.setattr(service_unpack_cli, "scan_pe", _fake_scan(lambda p: "x64"))

    def unpack_writes_real_pe(exe: Any, inp: Any, out: Path, **kw: Any) -> _FakeUpx:
        _write_pe(out)
        return _FakeUpx(out)

    monkeypatch.setattr(service, "_upx_unpacker", unpack_writes_real_pe)

    result = service.unpack_upx_unpack(session_id, open_ida=True)

    assert result.ok and result.data is not None
    reanalyze = result.data["reanalyze"]
    assert isinstance(reanalyze, dict)
    assert reanalyze["session"] is not None


def test_upx_unpack_reports_a_failed_child_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(tmp_path, upx=tmp_path / "upx.exe")
    monkeypatch.setattr(service_unpack_cli, "scan_pe", _fake_scan(lambda p: "x64"))
    monkeypatch.setattr(service, "_upx_unpacker", lambda exe, inp, out, **kw: _FakeUpx(out))
    monkeypatch.setattr(
        service,
        "create_session",
        lambda locator: Result(
            ok=False, error=RpcError(code="invalid_pe", message="child rejected")
        ),
    )

    result = service.unpack_upx_unpack(session_id, open_ida=True)

    assert result.ok and result.data is not None
    reanalyze = result.data["reanalyze"]
    assert isinstance(reanalyze, dict)
    assert reanalyze["static_open_ok"] is False
    assert reanalyze["session"] is None


# --------------------------------------------------------------------------- #
# unpack_external_probe
# --------------------------------------------------------------------------- #
def test_external_probe_reports_blocked_when_tools_are_missing(tmp_path: Path) -> None:
    service, session_id, _binary = _service(
        tmp_path,
        xvlkc=tmp_path / "absent-xvlkc.exe",
        vmp_dumper=tmp_path / "absent-vmp.exe",
        scylla=tmp_path / "absent-scylla.exe",
    )

    result = service.unpack_external_probe(session_id)

    assert result.ok and result.data is not None
    assert result.data["xvlkc"]["status"] == "blocked"
    assert result.data["vmp_dumper"]["status"] == "blocked"
    assert result.data["scylla"]["status"] == "blocked"


def test_external_probe_wraps_an_unexpected_failure(tmp_path: Path) -> None:
    service, _session_id, _binary = _service(tmp_path)

    result = service.unpack_external_probe("session-does-not-exist")

    assert result.ok is False
    assert result.error is not None


def test_external_probe_reports_ready_when_probes_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(
        tmp_path,
        xvlkc=_touch(tmp_path / "xvlkc.exe"),
        vmp_dumper=_touch(tmp_path / "vmp.exe"),
        scylla=_touch(tmp_path / "scylla.exe"),
    )
    monkeypatch.setattr("headless_re_mcp.unpack.xvlkc.probe_xvlkc", lambda p: (True, "xvlkc ok"))
    monkeypatch.setattr(
        "headless_re_mcp.unpack.vmp_dumper.probe_vmp_dumper", lambda p: (True, "vmp ok")
    )
    monkeypatch.setattr("headless_re_mcp.unpack.scylla.probe_scylla", lambda p: (True, "scylla ok"))

    result = service.unpack_external_probe(session_id)

    assert result.ok and result.data is not None
    assert result.data["xvlkc"]["status"] == "ready"
    assert result.data["vmp_dumper"]["status"] == "ready"
    assert result.data["scylla"]["status"] == "ready"


# --------------------------------------------------------------------------- #
# unpack_xvlkc_unpack
# --------------------------------------------------------------------------- #
def test_xvlkc_refuses_when_the_input_changed(tmp_path: Path) -> None:
    service, session_id, binary = _service(tmp_path, xvlkc=tmp_path / "xvlkc.exe")
    binary.write_bytes(b"MZ tampered payload")

    result = service.unpack_xvlkc_unpack(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_xvlkc_maps_a_caller_cancel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _binary = _service(tmp_path, xvlkc=tmp_path / "xvlkc.exe")

    def cancel(*args: Any, **kwargs: Any) -> Any:
        raise BoundedCancelled()

    monkeypatch.setattr(service, "_xvlkc_runner", cancel)

    result = service.unpack_xvlkc_unpack(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unpack_cancelled"


def test_xvlkc_maps_a_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _binary = _service(tmp_path, xvlkc=tmp_path / "xvlkc.exe")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise XvlkcError("xvlkc_failed", "no unpack", details={"why": "test"})

    monkeypatch.setattr(service, "_xvlkc_runner", boom)

    result = service.unpack_xvlkc_unpack(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "xvlkc_failed"


# --------------------------------------------------------------------------- #
# unpack_vmp_dump
# --------------------------------------------------------------------------- #
def test_vmp_refuses_when_the_input_changed(tmp_path: Path) -> None:
    service, session_id, binary = _service(tmp_path, vmp_dumper=tmp_path / "vmp.exe")
    binary.write_bytes(b"MZ tampered payload")

    result = service.unpack_vmp_dump(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_vmp_resolves_a_debuggee_pid_from_dynamic_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(tmp_path, vmp_dumper=tmp_path / "vmp.exe")
    monkeypatch.setattr(service, "dynamic_state", lambda sid: Result(ok=True, data={"pid": 4321}))
    monkeypatch.setattr(
        service, "_annotate_debuggee_pids", lambda sid, state: {"debuggee_pid": 4321}
    )
    monkeypatch.setattr(service, "_vmp_dumper_runner", lambda *a, **k: _FakeExt("/tmp/vmp-out.exe"))

    result = service.unpack_vmp_dump(session_id)

    assert result.ok and result.data is not None
    assert result.data["pid"] == 4321


def test_vmp_requires_a_debuggee_when_dynamic_state_has_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(tmp_path, vmp_dumper=tmp_path / "vmp.exe")
    monkeypatch.setattr(service, "dynamic_state", lambda sid: Result(ok=True, data={}))
    monkeypatch.setattr(service, "_annotate_debuggee_pids", lambda sid, state: {"debuggee_pid": 0})

    result = service.unpack_vmp_dump(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "debuggee_required"


def test_vmp_requires_a_debuggee_when_dynamic_state_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id, _binary = _service(tmp_path, vmp_dumper=tmp_path / "vmp.exe")

    def boom(sid: str) -> Any:
        raise RuntimeError("no dynamic backend")

    monkeypatch.setattr(service, "dynamic_state", boom)

    result = service.unpack_vmp_dump(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "debuggee_required"


def test_vmp_maps_a_caller_cancel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _binary = _service(tmp_path, vmp_dumper=tmp_path / "vmp.exe")

    def cancel(*args: Any, **kwargs: Any) -> Any:
        raise BoundedCancelled()

    monkeypatch.setattr(service, "_vmp_dumper_runner", cancel)

    result = service.unpack_vmp_dump(session_id, pid=1234)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unpack_cancelled"


def test_vmp_maps_a_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _binary = _service(tmp_path, vmp_dumper=tmp_path / "vmp.exe")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise VmpDumperError("vmp_failed", "no dump", details={"why": "test"})

    monkeypatch.setattr(service, "_vmp_dumper_runner", boom)

    result = service.unpack_vmp_dump(session_id, pid=1234)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "vmp_failed"


# --------------------------------------------------------------------------- #
# unpack_scylla_rebuild
# --------------------------------------------------------------------------- #
def test_scylla_refuses_when_the_input_changed(tmp_path: Path) -> None:
    service, session_id, binary = _service(tmp_path, scylla=tmp_path / "scylla.exe")
    binary.write_bytes(b"MZ tampered payload")

    result = service.unpack_scylla_rebuild(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_scylla_maps_a_caller_cancel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _binary = _service(tmp_path, scylla=tmp_path / "scylla.exe")

    def cancel(*args: Any, **kwargs: Any) -> Any:
        raise BoundedCancelled()

    monkeypatch.setattr(service, "_scylla_runner", cancel)

    result = service.unpack_scylla_rebuild(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unpack_cancelled"


def test_scylla_maps_a_typed_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id, _binary = _service(tmp_path, scylla=tmp_path / "scylla.exe")

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise ScyllaError("scylla_failed", "no rebuild", details={"why": "test"})

    monkeypatch.setattr(service, "_scylla_runner", boom)

    result = service.unpack_scylla_rebuild(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "scylla_failed"


# --------------------------------------------------------------------------- #
# unpack_auto
# --------------------------------------------------------------------------- #
def _auto(tmp_path: Path) -> tuple[AnalysisService, str]:
    service, session_id, _binary = _service(tmp_path)
    return service, session_id


def _started(unpack: JsonObject, **extra: Any) -> Result[JsonObject]:
    data: JsonObject = {"unpack": unpack, "claims_universal_unpack": False}
    data.update(extra)
    return Result(ok=True, data=data)


def test_auto_returns_started_when_active_status_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    monkeypatch.setattr(
        service,
        "unpack_start",
        lambda sid, **kw: Result(
            ok=False, error=RpcError(code="unpack_already_active", message="busy")
        ),
    )
    monkeypatch.setattr(
        service,
        "unpack_status",
        lambda sid: Result(ok=False, error=RpcError(code="no_session", message="x")),
    )

    result = service.unpack_auto(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unpack_already_active"


def test_auto_returns_started_when_unpack_payload_is_not_a_dict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    monkeypatch.setattr(
        service,
        "unpack_start",
        lambda sid, **kw: Result(
            ok=True, data={"unpack": "not-a-dict", "claims_universal_unpack": False}
        ),
    )

    result = service.unpack_auto(session_id)

    assert result.ok and result.data is not None
    assert result.data["unpack"] == "not-a-dict"


def test_auto_returns_a_plain_start_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    monkeypatch.setattr(
        service,
        "unpack_start",
        lambda sid, **kw: Result(ok=False, error=RpcError(code="unpack_failed", message="nope")),
    )

    result = service.unpack_auto(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "unpack_failed"


def test_auto_reports_a_failed_dotnet_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    unpack = {
        "route": "dotnet",
        "phase": "failed",
        "failure": {"code": "dotnet_boom", "message": "clr failed"},
    }
    monkeypatch.setattr(service, "unpack_start", lambda sid, **kw: _started(unpack))

    result = service.unpack_auto(session_id)

    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "dotnet_boom"


def test_auto_dotnet_uses_the_bounded_probe_hints(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    unpack = {"route": "dotnet", "phase": "detected", "plan": {}}
    probe = {
        "next": ["dotnet.deobfuscate"],
        "clr_verified": True,
        "dotnet_inspect": {"managed": True},
    }
    monkeypatch.setattr(
        service, "unpack_start", lambda sid, **kw: _started(unpack, bounded_probe=probe)
    )

    result = service.unpack_auto(session_id)

    assert result.ok and result.data is not None
    assert result.data["status"] == "routed_m6"
    assert result.data["next"] == ["dotnet.deobfuscate"]
    assert result.data["clr_verified"] is True


def test_auto_dotnet_recovers_hints_from_the_timeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    unpack = {
        "route": "dotnet",
        "phase": "detected",
        "timeline": [
            {
                "event": "routed_m6",
                "details": {"next": ["dotnet.verify"], "clr_verified": False},
            }
        ],
    }
    monkeypatch.setattr(service, "unpack_start", lambda sid, **kw: _started(unpack))

    result = service.unpack_auto(session_id)

    assert result.ok and result.data is not None
    assert result.data["status"] == "routed_m6"
    assert result.data["next"] == ["dotnet.verify"]


def test_auto_dotnet_skips_non_dict_timeline_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    unpack = {
        "route": "dotnet",
        "phase": "detected",
        "timeline": [
            {"event": "routed_m6", "details": "not-a-dict"},
            {"event": "noise"},
        ],
    }
    monkeypatch.setattr(service, "unpack_start", lambda sid, **kw: _started(unpack))

    result = service.unpack_auto(session_id)

    assert result.ok and result.data is not None
    assert result.data["status"] == "routed_m6"
    assert result.data["next"] == ["dotnet.deobfuscate", "dotnet.verify"]


def test_auto_dotnet_falls_back_without_a_timeline_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    unpack = {
        "route": "dotnet",
        "phase": "detected",
        "timeline": [{"event": "noise"}],
    }
    monkeypatch.setattr(service, "unpack_start", lambda sid, **kw: _started(unpack))

    result = service.unpack_auto(session_id)

    assert result.ok and result.data is not None
    assert result.data["status"] == "routed_m6"
    assert result.data["next"] == ["dotnet.deobfuscate", "dotnet.verify"]
    assert "clr_verified" not in result.data


def test_auto_routes_generic_dynamic_to_confirm_oep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _auto(tmp_path)
    unpack = {"route": "generic_dynamic", "phase": "detected", "plan": {}}
    monkeypatch.setattr(service, "unpack_start", lambda sid, **kw: _started(unpack))

    result = service.unpack_auto(session_id)

    assert result.ok and result.data is not None
    assert result.data["status"] == "awaiting_oep"
    assert result.data["next"] == "unpack.confirm_oep"


def test_auto_wraps_an_unexpected_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, session_id = _auto(tmp_path)

    def boom(sid: str, **kw: Any) -> Any:
        raise RuntimeError("orchestration exploded")

    monkeypatch.setattr(service, "unpack_start", boom)

    result = service.unpack_auto(session_id)

    assert result.ok is False
    assert result.error is not None
