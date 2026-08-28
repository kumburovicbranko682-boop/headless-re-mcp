"""The .NET service mixin's guard and error-mapping arms.

The dotnet suites drive the happy paths (inspect a verified image, register a
de4dot/NRS output) and the closed-session guards, which leaves every
error-to-RpcError mapping and a few parameter guards unexecuted: the
non-boolean require_verified refusal, the capability-unavailable answers when
a CLI is not configured, the input-changed check that refuses to run a
deobfuscator on a file that no longer matches the session, the runner-raised
De4dot/NRS failures, and the DotnetInspectError arms of inspect, enumerate,
il, xrefs, and verify -- plus the whole dotnet_il body, which no test reached.
This file pins each against a real AnalysisService session, using a native PE
where a genuine verification failure is the point and a stubbed metadata
function where the contract under test is purely the wrapper's mapping.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_dotnet
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.de4dot import De4dotError
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerError
from tests.unit.test_dotnet_inspect import _write_native_pe, _write_verified_clr_pe

JsonObject = dict[str, Any]


def _service(tmp_path: Path, **settings: Any) -> AnalysisService:
    runner_kwargs = {
        key: settings.pop(key)
        for key in ("de4dot_runner", "net_reactor_slayer_runner")
        if key in settings
    }
    return AnalysisService(
        Settings(
            ida_home=None,
            x64dbg_source=None,
            x64dbg_headless_x64=None,
            x64dbg_headless_x86=None,
            artifact_root=tmp_path / "artifacts",
            **settings,
        ),
        **runner_kwargs,
    )


def _session_over(service: AnalysisService, binary: Path) -> str:
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _managed(tmp_path: Path, name: str = "managed.exe") -> Path:
    binary = tmp_path / name
    _write_verified_clr_pe(binary)
    return binary


def _native(tmp_path: Path, name: str = "native.exe") -> Path:
    binary = tmp_path / name
    _write_native_pe(binary)
    return binary


# --------------------------------------------------------------------------- #
# dotnet_inspect: parameter guard and verification failure                    #
# --------------------------------------------------------------------------- #
def test_inspect_rejects_a_non_boolean_require_verified(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_inspect(sid, require_verified="yes")  # type: ignore[arg-type]
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_params"
        assert "boolean" in result.error.message
    finally:
        service.close_all()


def test_inspect_maps_a_verification_failure_to_its_error_code(tmp_path: Path) -> None:
    """A native PE cannot be verified as managed; the code must survive intact."""
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _native(tmp_path))
        result = service.dotnet_inspect(sid, require_verified=True)
        assert not result.ok
        assert result.error is not None
        assert result.error.code in {"not_dotnet", "clr_unverified"}
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# dotnet_deobfuscate: capability, input-changed, runner failure               #
# --------------------------------------------------------------------------- #
def test_deobfuscate_without_de4dot_is_capability_unavailable(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_deobfuscate(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
        assert "de4dot" in result.error.message
    finally:
        service.close_all()


def test_deobfuscate_refuses_a_session_whose_input_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The image passed inspection but no longer hashes to the session's sha."""
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")
    service = _service(tmp_path, de4dot=de4dot, de4dot_runner=_unreached_runner)
    try:
        sid = _session_over(service, _managed(tmp_path))
        monkeypatch.setattr(service_dotnet, "file_sha256", lambda _path: "f" * 64)
        result = service.dotnet_deobfuscate(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "input_changed"
        assert result.error.details["expected_sha256"] != "f" * 64
    finally:
        service.close_all()


def test_deobfuscate_maps_a_runner_failure_to_its_error_code(tmp_path: Path) -> None:
    de4dot = tmp_path / "de4dot.exe"
    de4dot.write_bytes(b"placeholder")

    def failing_runner(*_args: Any, **_kwargs: Any) -> Any:
        raise De4dotError("process_failed", "de4dot exited 1", details={"exit_code": 1})

    service = _service(tmp_path, de4dot=de4dot, de4dot_runner=failing_runner)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_deobfuscate(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "process_failed"
        assert result.error.details["exit_code"] == 1
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# dotnet_reactor_unpack: capability, input-changed, runner failure            #
# --------------------------------------------------------------------------- #
def test_reactor_unpack_without_the_cli_is_capability_unavailable(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_reactor_unpack(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "capability_unavailable"
        assert "NETReactorSlayer" in result.error.message
    finally:
        service.close_all()


def test_reactor_unpack_refuses_a_session_whose_input_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nrs = tmp_path / "nrs.exe"
    nrs.write_bytes(b"placeholder")
    service = _service(
        tmp_path, net_reactor_slayer=nrs, net_reactor_slayer_runner=_unreached_runner
    )
    try:
        sid = _session_over(service, _managed(tmp_path))
        monkeypatch.setattr(service_dotnet, "file_sha256", lambda _path: "e" * 64)
        result = service.dotnet_reactor_unpack(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "input_changed"
    finally:
        service.close_all()


def test_reactor_unpack_maps_a_runner_failure_to_its_error_code(tmp_path: Path) -> None:
    nrs = tmp_path / "nrs.exe"
    nrs.write_bytes(b"placeholder")

    def failing_runner(*_args: Any, **_kwargs: Any) -> Any:
        raise NetReactorSlayerError("output_missing", "no output produced")

    service = _service(tmp_path, net_reactor_slayer=nrs, net_reactor_slayer_runner=failing_runner)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_reactor_unpack(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "output_missing"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# dotnet_enumerate / dotnet_il / dotnet_xrefs error mapping and the il body    #
# --------------------------------------------------------------------------- #
def test_enumerate_maps_a_dotnet_inspect_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raising(*_args: Any, **_kwargs: Any) -> Any:
        raise DotnetInspectError("clr_unverified", "no tables", details={"kind": "table"})

    monkeypatch.setattr(service_dotnet, "enumerate_metadata", raising)
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_enumerate(sid, "TypeDef")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "clr_unverified"
        assert result.error.details["kind"] == "table"
    finally:
        service.close_all()


def test_il_disassembles_a_method_on_the_happy_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No test reached dotnet_il at all; pin its success body and its argument."""
    seen: JsonObject = {}

    def fake_disassemble(pe: Path, method_token: int, *, require_verified: bool) -> JsonObject:
        seen["token"] = method_token
        seen["require_verified"] = require_verified
        return {"method_token": method_token, "instructions": [{"op": "ret"}]}

    monkeypatch.setattr(service_dotnet, "disassemble_method_il", fake_disassemble)
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_il(sid, 0x06000001, require_verified=False)
        assert result.ok and result.data is not None, result.error
        assert result.data["method_token"] == 0x06000001
        assert result.data["instructions"] == [{"op": "ret"}]
        assert seen == {"token": 0x06000001, "require_verified": False}
    finally:
        service.close_all()


def test_il_maps_a_dotnet_inspect_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def raising(*_args: Any, **_kwargs: Any) -> Any:
        raise DotnetInspectError("method_not_found", "no such token")

    monkeypatch.setattr(service_dotnet, "disassemble_method_il", raising)
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_il(sid, 0x06000009)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "method_not_found"
    finally:
        service.close_all()


def test_xrefs_maps_a_dotnet_inspect_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def raising(*_args: Any, **_kwargs: Any) -> Any:
        raise DotnetInspectError("clr_unverified", "unverified image")

    monkeypatch.setattr(service_dotnet, "list_memberref_xrefs", raising)
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        result = service.dotnet_xrefs(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "clr_unverified"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# dotnet_verify: a session-owned but unverifiable artifact                     #
# --------------------------------------------------------------------------- #
def test_verify_maps_a_dotnet_inspect_error_on_an_owned_artifact(tmp_path: Path) -> None:
    """The path is inside the session's dotnet root, so ownership passes and the
    failure is genuinely the CLR check, not the boundary guard."""
    service = _service(tmp_path)
    try:
        sid = _session_over(service, _managed(tmp_path))
        owned_dir = service.settings.artifact_root.expanduser().resolve() / "dotnet" / sid
        owned_dir.mkdir(parents=True, exist_ok=True)
        artifact = owned_dir / "candidate.exe"
        _write_native_pe(artifact)

        result = service.dotnet_verify(sid, str(artifact), require_verified=True)

        assert not result.ok
        assert result.error is not None
        assert result.error.code in {"not_dotnet", "clr_unverified"}
    finally:
        service.close_all()


def _unreached_runner(*_args: Any, **_kwargs: Any) -> Any:  # pragma: no cover
    raise AssertionError("the runner must not be reached once input_changed fires")
