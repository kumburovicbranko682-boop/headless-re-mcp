"""Error-path coverage for the .NET service mixin (service_dotnet.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_dotnet as service_dotnet
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.de4dot import De4dotError
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerError
from tests.unit.test_dotnet_inspect import _write_native_pe, _write_verified_clr_pe


def _service(
    tmp_path: Path,
    *,
    de4dot: Path | None = None,
    net_reactor_slayer: Path | None = None,
    **runners: Any,
) -> AnalysisService:
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            de4dot=de4dot,
            net_reactor_slayer=net_reactor_slayer,
        ),
        **runners,
    )


def _open(service: AnalysisService, exe: Path) -> str:
    created = service.create_session(str(exe))
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _managed(tmp_path: Path) -> Path:
    exe = tmp_path / "managed.exe"
    _write_verified_clr_pe(exe)
    return exe


def _native(tmp_path: Path) -> Path:
    exe = tmp_path / "native.exe"
    _write_native_pe(exe)
    return exe


def test_inspect_rejects_a_non_boolean_flag(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_inspect(session_id, require_verified="yes")  # type: ignore[arg-type]
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"


def test_inspect_maps_a_clr_verification_failure(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _native(tmp_path))
    result = service.dotnet_inspect(session_id, require_verified=True)
    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"


def test_deobfuscate_requires_a_configured_cli(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_deobfuscate(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_deobfuscate_refuses_a_mutated_input(tmp_path: Path) -> None:
    exe = _managed(tmp_path)
    service = _service(tmp_path, de4dot=tmp_path / "de4dot.exe")
    session_id = _open(service, exe)
    exe.write_bytes(exe.read_bytes() + b"\0")  # still verified CLR, new sha256
    result = service.dotnet_deobfuscate(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "input_changed"


def test_deobfuscate_maps_a_runner_failure(tmp_path: Path) -> None:
    def runner(*args: Any, **kwargs: Any) -> Any:
        raise De4dotError("process_failed", "de4dot blew up", details={"returncode": 2})

    service = _service(tmp_path, de4dot=tmp_path / "de4dot.exe", de4dot_runner=runner)
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_deobfuscate(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "process_failed"
    assert result.error.details["returncode"] == 2


def test_reactor_unpack_requires_a_configured_cli(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_reactor_unpack(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "capability_unavailable"


def test_reactor_unpack_refuses_a_mutated_input(tmp_path: Path) -> None:
    exe = _managed(tmp_path)
    service = _service(tmp_path, net_reactor_slayer=tmp_path / "nrs.exe")
    session_id = _open(service, exe)
    exe.write_bytes(exe.read_bytes() + b"\0")
    result = service.dotnet_reactor_unpack(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "input_changed"


def test_reactor_unpack_maps_a_runner_failure(tmp_path: Path) -> None:
    def runner(*args: Any, **kwargs: Any) -> Any:
        raise NetReactorSlayerError("timeout", "slayer stalled")

    service = _service(
        tmp_path,
        net_reactor_slayer=tmp_path / "nrs.exe",
        net_reactor_slayer_runner=runner,
    )
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_reactor_unpack(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "timeout"


def test_enumerate_maps_a_clr_verification_failure(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _native(tmp_path))
    result = service.dotnet_enumerate(session_id, "types", require_verified=True)
    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"


def test_il_returns_the_disassembly_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    monkeypatch.setattr(
        service_dotnet,
        "disassemble_method_il",
        lambda path, token, *, require_verified: {"token": token, "il": ["nop"]},
    )
    result = service.dotnet_il(session_id, 0x06000001)
    assert result.ok and result.data is not None
    assert result.data["token"] == 0x06000001


def test_il_maps_a_clr_verification_failure(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _native(tmp_path))
    result = service.dotnet_il(session_id, 0x06000001)
    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"


def test_xrefs_maps_a_clr_verification_failure(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _native(tmp_path))
    result = service.dotnet_xrefs(session_id)
    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"


def test_verify_maps_a_clr_verification_failure_on_an_owned_artifact(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    owned_dir = (tmp_path / "artifacts").resolve() / "dotnet" / session_id
    owned_dir.mkdir(parents=True)
    artifact = owned_dir / "candidate.exe"
    _write_native_pe(artifact)
    result = service.dotnet_verify(session_id, str(artifact), require_verified=True)
    assert not result.ok and result.error is not None
    assert result.error.code == "not_dotnet"


def test_il_error_type_is_the_shared_inspect_error() -> None:
    assert issubclass(DotnetInspectError, ValueError)


def test_every_method_maps_an_unknown_session_to_a_failure(tmp_path: Path) -> None:
    service = _service(tmp_path)
    results = [
        service.dotnet_inspect("missing"),
        service.dotnet_deobfuscate("missing"),
        service.dotnet_reactor_unpack("missing"),
        service.dotnet_enumerate("missing", "types"),
        service.dotnet_il("missing", 0x06000001),
        service.dotnet_xrefs("missing"),
        service.dotnet_verify("missing", str(tmp_path)),
    ]
    for result in results:
        assert not result.ok and result.error is not None


def _close(service: AnalysisService, session_id: str) -> None:
    closed = service.close_session(session_id)
    assert closed.ok


def test_deobfuscate_and_reactor_refuse_a_closed_session(tmp_path: Path) -> None:
    service = _service(
        tmp_path, de4dot=tmp_path / "de4dot.exe", net_reactor_slayer=tmp_path / "nrs.exe"
    )
    session_id = _open(service, _managed(tmp_path))
    _close(service, session_id)
    for call in (service.dotnet_deobfuscate, service.dotnet_reactor_unpack):
        result = call(session_id)
        assert not result.ok and result.error is not None


class _FakeRunResult:
    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path

    def to_dict(self) -> dict[str, Any]:
        return {"output_path": str(self.output_path)}


def test_deobfuscate_detects_a_session_closed_mid_run(tmp_path: Path) -> None:
    exe = _managed(tmp_path)
    holder: dict[str, Any] = {}

    def runner(cli: Path, source: Path, out_path: Path, **kwargs: Any) -> _FakeRunResult:
        _write_verified_clr_pe(out_path)
        _close(holder["service"], holder["session_id"])
        return _FakeRunResult(out_path)

    service = _service(tmp_path, de4dot=tmp_path / "de4dot.exe", de4dot_runner=runner)
    holder["service"] = service
    holder["session_id"] = _open(service, exe)
    result = service.dotnet_deobfuscate(holder["session_id"])
    assert not result.ok and result.error is not None


def test_reactor_unpack_detects_a_session_closed_mid_run(tmp_path: Path) -> None:
    exe = _managed(tmp_path)
    holder: dict[str, Any] = {}

    def runner(cli: Path, source: Path, out_path: Path, **kwargs: Any) -> _FakeRunResult:
        _write_verified_clr_pe(out_path)
        _close(holder["service"], holder["session_id"])
        return _FakeRunResult(out_path)

    service = _service(
        tmp_path,
        net_reactor_slayer=tmp_path / "nrs.exe",
        net_reactor_slayer_runner=runner,
    )
    holder["service"] = service
    holder["session_id"] = _open(service, exe)
    result = service.dotnet_reactor_unpack(holder["session_id"])
    assert not result.ok and result.error is not None


class _FakePage:
    def to_dict(self) -> dict[str, Any]:
        return {"items": [], "total": 0}


def test_inspect_succeeds_on_a_verified_assembly(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_inspect(session_id)
    assert result.ok and result.data is not None
    assert result.data["verified_clr"] is True


def test_deobfuscate_registers_a_successful_run(tmp_path: Path) -> None:
    def runner(cli: Path, source: Path, out_path: Path, **kwargs: Any) -> _FakeRunResult:
        _write_verified_clr_pe(out_path)
        return _FakeRunResult(out_path)

    service = _service(tmp_path, de4dot=tmp_path / "de4dot.exe", de4dot_runner=runner)
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_deobfuscate(session_id)
    assert result.ok and result.data is not None
    assert result.data["claims_universal_unpack"] is False
    assert result.data["input_unchanged"] is True


def test_reactor_unpack_registers_a_successful_run(tmp_path: Path) -> None:
    def runner(cli: Path, source: Path, out_path: Path, **kwargs: Any) -> _FakeRunResult:
        _write_verified_clr_pe(out_path)
        return _FakeRunResult(out_path)

    service = _service(
        tmp_path, net_reactor_slayer=tmp_path / "nrs.exe", net_reactor_slayer_runner=runner
    )
    session_id = _open(service, _managed(tmp_path))
    result = service.dotnet_reactor_unpack(session_id)
    assert result.ok and result.data is not None
    assert result.data["authorized_samples_only"] is True


def test_verify_rejects_a_path_outside_the_session_artifacts(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    stray = tmp_path / "outside.exe"
    _write_verified_clr_pe(stray)
    result = service.dotnet_verify(session_id, str(stray))
    assert not result.ok and result.error is not None
    assert result.error.code == "invalid_params"
    assert result.error.details["allowed_roots"]


def test_verify_succeeds_on_an_owned_verified_artifact(tmp_path: Path) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    owned_dir = (tmp_path / "artifacts").resolve() / "dotnet" / session_id
    owned_dir.mkdir(parents=True)
    artifact = owned_dir / "candidate.exe"
    _write_verified_clr_pe(artifact)
    result = service.dotnet_verify(session_id, str(artifact), require_verified=True)
    assert result.ok and result.data is not None
    assert result.data["ok"] is True
    assert result.data["claims_universal_unpack"] is False


def test_enumerate_and_xrefs_return_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    session_id = _open(service, _managed(tmp_path))
    monkeypatch.setattr(
        service_dotnet,
        "enumerate_metadata",
        lambda path, kind, *, offset, limit, require_verified: _FakePage(),
    )
    monkeypatch.setattr(
        service_dotnet,
        "list_memberref_xrefs",
        lambda path, *, offset, limit, require_verified: _FakePage(),
    )
    enumerated = service.dotnet_enumerate(session_id, "types")
    assert enumerated.ok and enumerated.data is not None
    assert enumerated.data["total"] == 0
    xrefs = service.dotnet_xrefs(session_id)
    assert xrefs.ok and xrefs.data is not None
    assert xrefs.data["items"] == []
