""".NET service-facade guards: refusals, error mapping, and input-change checks.

The happy paths of ``dotnet_deobfuscate`` / ``dotnet_reactor_unpack`` are pinned
elsewhere; this file covers the guard and error branches around them. It uses a
real ``AnalysisService`` with a verified-CLR fixture and patches the underlying
``inspect_dotnet`` / ``enumerate_metadata`` / ``disassemble_method_il`` /
``list_memberref_xrefs`` on the service module so each error envelope is exercised
without a real CLR parse.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.core.service_dotnet as service_dotnet
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.de4dot import De4dotError, De4dotResult
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerError, NetReactorSlayerResult
from tests.unit.test_dotnet_de4dot import _write_verified_clr_pe


def _service(tmp_path: Path, **settings_overrides: Any) -> tuple[AnalysisService, str, Path]:
    binary = tmp_path / "managed.exe"
    _write_verified_clr_pe(binary)
    settings = Settings(
        ida_home=None,
        x64dbg_source=None,
        x64dbg_headless_x64=None,
        x64dbg_headless_x86=None,
        artifact_root=tmp_path / "artifacts",
        **settings_overrides,
    )
    service = AnalysisService(settings, **_runner_kwargs(settings_overrides))
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, str(created.data["session"]["id"]), binary


def _runner_kwargs(settings_overrides: dict[str, Any]) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    if "de4dot" in settings_overrides:
        kwargs["de4dot_runner"] = _passthrough_de4dot
    if "net_reactor_slayer" in settings_overrides:
        kwargs["net_reactor_slayer_runner"] = _passthrough_nrs
    return kwargs


def _passthrough_de4dot(
    executable: Path, input_path: Path, output_path: Path, **kwargs: Any
) -> De4dotResult:
    output_path.write_bytes(input_path.read_bytes())
    return De4dotResult(
        executable=str(executable),
        input_path=str(input_path),
        output_path=str(output_path.resolve()),
        input_sha256=file_sha256(input_path),
        output_sha256=file_sha256(output_path),
        returncode=0,
        stdout="ok",
        stderr="",
        duration_ms=1,
    )


def _passthrough_nrs(
    executable: Path, input_path: Path, output_path: Path, **kwargs: Any
) -> NetReactorSlayerResult:
    output_path.write_bytes(input_path.read_bytes())
    return NetReactorSlayerResult(
        executable=str(executable),
        input_path=str(input_path),
        output_path=str(output_path.resolve()),
        input_sha256=file_sha256(input_path),
        output_sha256=file_sha256(output_path),
        returncode=0,
        stdout="ok",
        stderr="",
        duration_ms=1,
    )


# ---------------------------------------------------------------------------
# dotnet_inspect
# ---------------------------------------------------------------------------


def test_inspect_rejects_a_non_boolean_require_verified(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path)
    try:
        result = service.dotnet_inspect(session_id, require_verified="yes")  # type: ignore[arg-type]
        assert not result.ok and result.error is not None
        assert result.error.code == "invalid_params"
    finally:
        service.close_all()


def test_inspect_maps_a_dotnet_inspect_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "inspect_dotnet",
        lambda pe, require_verified: (_ for _ in ()).throw(
            DotnetInspectError("not_dotnet", "no CLR header", details={"why": "native"})
        ),
    )
    try:
        result = service.dotnet_inspect(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "not_dotnet"
        assert result.error.details == {"why": "native"}
    finally:
        service.close_all()


def test_inspect_maps_an_unexpected_error_to_a_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "inspect_dotnet",
        lambda pe, require_verified: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    try:
        result = service.dotnet_inspect(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code not in {"not_dotnet", "invalid_params"}
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# dotnet_deobfuscate guards
# ---------------------------------------------------------------------------


def test_deobfuscate_without_a_configured_de4dot_is_unavailable(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path)  # de4dot omitted -> None
    try:
        result = service.dotnet_deobfuscate(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "capability_unavailable"
        assert "de4dot" in result.error.message
    finally:
        service.close_all()


def test_deobfuscate_refuses_a_closed_session(tmp_path: Path) -> None:
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"x")
    service, session_id, _ = _service(tmp_path, de4dot=de4dot)
    try:
        service.close_session(session_id)
        result = service.dotnet_deobfuscate(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code in {"invalid_request", "invalid_state"}
    finally:
        service.close_all()


def test_deobfuscate_detects_input_changed_after_session_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"x")
    service, session_id, binary = _service(tmp_path, de4dot=de4dot)
    # inspect_dotnet is called before the sha check; keep it cheap and passing.
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )
    binary.write_bytes(binary.read_bytes() + b"tampered")
    try:
        result = service.dotnet_deobfuscate(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "input_changed"
        assert result.error.details["expected_sha256"] != result.error.details["actual_sha256"]
    finally:
        service.close_all()


def test_deobfuscate_rechecks_state_after_the_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A session closed while de4dot ran must not be reported as a success."""
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"x")
    service, session_id, _ = _service(tmp_path, de4dot=de4dot)
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )

    def closing_runner(
        executable: Path, input_path: Path, output_path: Path, **kwargs: Any
    ) -> De4dotResult:
        result = _passthrough_de4dot(executable, input_path, output_path, **kwargs)
        service.close_session(session_id)  # the session dies mid-run
        return result

    service._de4dot_runner = closing_runner
    try:
        result = service.dotnet_deobfuscate(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code in {"invalid_request", "invalid_state"}
    finally:
        service.close_all()


def test_deobfuscate_maps_a_de4dot_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"x")

    def boom_runner(executable: Path, input_path: Path, output_path: Path, **kwargs: Any) -> Any:
        raise De4dotError("process_failed", "de4dot exited 1", details={"rc": 1})

    service, session_id, _ = _service(tmp_path, de4dot=de4dot)
    service._de4dot_runner = boom_runner
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )
    try:
        result = service.dotnet_deobfuscate(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "process_failed"
        assert result.error.details == {"rc": 1}
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# dotnet_reactor_unpack guards
# ---------------------------------------------------------------------------


def test_reactor_unpack_without_a_configured_cli_is_unavailable(tmp_path: Path) -> None:
    service, session_id, _ = _service(tmp_path)
    try:
        result = service.dotnet_reactor_unpack(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "capability_unavailable"
        assert "NETReactorSlayer" in result.error.message
    finally:
        service.close_all()


def test_reactor_unpack_detects_input_changed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nrs = tmp_path / "nrs.exe"
    nrs.write_bytes(b"x")
    service, session_id, binary = _service(tmp_path, net_reactor_slayer=nrs)
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )
    binary.write_bytes(binary.read_bytes() + b"tampered")
    try:
        result = service.dotnet_reactor_unpack(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "input_changed"
    finally:
        service.close_all()


def test_reactor_unpack_refuses_a_closed_session(tmp_path: Path) -> None:
    nrs = tmp_path / "nrs.exe"
    nrs.write_bytes(b"x")
    service, session_id, _ = _service(tmp_path, net_reactor_slayer=nrs)
    try:
        service.close_session(session_id)
        result = service.dotnet_reactor_unpack(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code in {"invalid_request", "invalid_state"}
    finally:
        service.close_all()


def test_reactor_unpack_rechecks_state_after_the_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nrs = tmp_path / "nrs.exe"
    nrs.write_bytes(b"x")
    service, session_id, _ = _service(tmp_path, net_reactor_slayer=nrs)
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )

    def closing_runner(
        executable: Path, input_path: Path, output_path: Path, **kwargs: Any
    ) -> NetReactorSlayerResult:
        result = _passthrough_nrs(executable, input_path, output_path, **kwargs)
        service.close_session(session_id)
        return result

    service._net_reactor_slayer_runner = closing_runner
    try:
        result = service.dotnet_reactor_unpack(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code in {"invalid_request", "invalid_state"}
    finally:
        service.close_all()


def test_reactor_unpack_maps_a_slayer_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nrs = tmp_path / "nrs.exe"
    nrs.write_bytes(b"x")

    def boom_runner(executable: Path, input_path: Path, output_path: Path, **kwargs: Any) -> Any:
        raise NetReactorSlayerError("process_failed", "slayer exited 2", details={"rc": 2})

    service, session_id, _ = _service(tmp_path, net_reactor_slayer=nrs)
    service._net_reactor_slayer_runner = boom_runner
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )
    try:
        result = service.dotnet_reactor_unpack(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "process_failed"
        assert result.error.details == {"rc": 2}
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# enumerate / il / xrefs / verify error mapping
# ---------------------------------------------------------------------------


class _FakePage:
    def to_dict(self) -> dict[str, Any]:
        return {"rows": [], "total": 0}


def test_enumerate_returns_the_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(service_dotnet, "enumerate_metadata", lambda pe, kind, **kw: _FakePage())
    try:
        result = service.dotnet_enumerate(session_id, "TypeDef")
        assert result.ok and result.data is not None
        assert result.data["rows"] == [] and result.data["total"] == 0
    finally:
        service.close_all()


def test_enumerate_maps_an_unexpected_error_to_a_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "enumerate_metadata",
        lambda pe, kind, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    try:
        result = service.dotnet_enumerate(session_id, "TypeDef")
        assert not result.ok and result.error is not None
    finally:
        service.close_all()


def test_enumerate_maps_a_dotnet_inspect_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "enumerate_metadata",
        lambda pe, kind, **kw: (_ for _ in ()).throw(
            DotnetInspectError("invalid_params", "unknown table", details={"kind": kind})
        ),
    )
    try:
        result = service.dotnet_enumerate(session_id, "NoSuchTable")
        assert not result.ok and result.error is not None
        assert result.error.code == "invalid_params"
        assert result.error.details == {"kind": "NoSuchTable"}
    finally:
        service.close_all()


def test_il_returns_the_disassembly_and_maps_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "disassemble_method_il",
        lambda pe, token, **kw: {"token": token, "instructions": []},
    )
    try:
        ok = service.dotnet_il(session_id, 0x06000001)
        assert ok.ok and ok.data is not None
        assert ok.data["token"] == 0x06000001
    finally:
        pass

    monkeypatch.setattr(
        service_dotnet,
        "disassemble_method_il",
        lambda pe, token, **kw: (_ for _ in ()).throw(
            DotnetInspectError("not_found", "no such method")
        ),
    )
    try:
        bad = service.dotnet_il(session_id, 0x06000002)
        assert not bad.ok and bad.error is not None
        assert bad.error.code == "not_found"
    finally:
        service.close_all()


def test_il_maps_an_unexpected_error_to_a_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "disassemble_method_il",
        lambda pe, token, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    try:
        result = service.dotnet_il(session_id, 0x06000001)
        assert not result.ok and result.error is not None
    finally:
        service.close_all()


def test_xrefs_returns_the_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(service_dotnet, "list_memberref_xrefs", lambda pe, **kw: _FakePage())
    try:
        result = service.dotnet_xrefs(session_id)
        assert result.ok and result.data is not None
        assert result.data["total"] == 0
    finally:
        service.close_all()


def test_xrefs_maps_an_unexpected_error_to_a_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "list_memberref_xrefs",
        lambda pe, **kw: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    try:
        result = service.dotnet_xrefs(session_id)
        assert not result.ok and result.error is not None
    finally:
        service.close_all()


def test_xrefs_maps_a_dotnet_inspect_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, session_id, _ = _service(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "list_memberref_xrefs",
        lambda pe, **kw: (_ for _ in ()).throw(DotnetInspectError("not_dotnet", "no metadata")),
    )
    try:
        result = service.dotnet_xrefs(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "not_dotnet"
    finally:
        service.close_all()


def test_verify_rejects_a_path_outside_the_session_artifacts(tmp_path: Path) -> None:
    service, session_id, binary = _service(tmp_path)
    try:
        result = service.dotnet_verify(session_id, str(binary))
        assert not result.ok and result.error is not None
        assert result.error.code == "invalid_params"
        assert "session artifact" in result.error.message
        assert result.error.details["allowed_roots"]
    finally:
        service.close_all()


def test_verify_reports_an_owned_verified_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"x")
    service, session_id, _ = _service(tmp_path, de4dot=de4dot)
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )
    produced = service.dotnet_deobfuscate(session_id)
    assert produced.ok and produced.data is not None
    artifact = Path(str(produced.data["de4dot"]["output_path"]))
    try:
        result = service.dotnet_verify(session_id, str(artifact))
        assert result.ok and result.data is not None
        assert result.data["ok"] is True
        assert result.data["claims_universal_unpack"] is False
    finally:
        service.close_all()


def test_verify_maps_an_unexpected_error_to_a_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"x")
    service, session_id, _ = _service(tmp_path, de4dot=de4dot)
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )
    produced = service.dotnet_deobfuscate(session_id)
    assert produced.ok and produced.data is not None
    artifact = Path(str(produced.data["de4dot"]["output_path"]))
    monkeypatch.setattr(
        service_dotnet,
        "inspect_dotnet",
        lambda pe, require_verified: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    try:
        result = service.dotnet_verify(session_id, str(artifact))
        assert not result.ok and result.error is not None
    finally:
        service.close_all()


def test_verify_maps_a_dotnet_inspect_error_for_an_owned_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"x")
    service, session_id, _ = _service(tmp_path, de4dot=de4dot)
    # Produce an owned artifact under dotnet/<id>/ via a real deobfuscate run.
    monkeypatch.setattr(
        service_dotnet, "inspect_dotnet", lambda pe, require_verified: _FakeReport()
    )
    produced = service.dotnet_deobfuscate(session_id)
    assert produced.ok and produced.data is not None
    artifact = Path(str(produced.data["de4dot"]["output_path"]))

    monkeypatch.setattr(
        service_dotnet,
        "inspect_dotnet",
        lambda pe, require_verified: (_ for _ in ()).throw(
            DotnetInspectError("not_dotnet", "no CLR header")
        ),
    )
    try:
        result = service.dotnet_verify(session_id, str(artifact))
        assert not result.ok and result.error is not None
        assert result.error.code == "not_dotnet"
    finally:
        service.close_all()


class _FakeReport:
    """Minimal stand-in for a DotnetInspectReport used by the deobfuscate flow."""

    kind = type("Kind", (), {"value": "verified"})()
    metadata_stats = None
    verified_clr = True

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "verified", "verified_clr": True}
