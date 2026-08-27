"""Guard and error-mapping paths of the .NET analysis service mixin.

The success paths (inspect / deobfuscate / reactor / enumerate / verify) are
covered by the existing suite; this drives the arms around them: the boolean
guard on inspect, the capability-unavailable and input-changed refusals on the
deobfuscators, the whole ``dotnet_il`` method, and the ``DotnetInspectError``
-> envelope mapping on every read. Backends are faked in the module namespace.
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_dotnet as service_dotnet
from headless_re_mcp.core.models import Session, SessionState, TargetKind
from headless_re_mcp.core.service_dotnet import DotnetAnalysisMixin
from headless_re_mcp.core.session import SessionRegistry, file_sha256
from headless_re_mcp.dotnet.clr_inspect import DotnetInspectError
from headless_re_mcp.dotnet.de4dot import De4dotError
from headless_re_mcp.dotnet.net_reactor_slayer import NetReactorSlayerError


class _SeqRegistry:
    """Returns the session with a state that advances per get() call."""

    def __init__(self, session: Session, states: list[SessionState]) -> None:
        self._session = session
        self._states = states
        self._i = 0

    def get(self, session_id: str) -> Session:
        state = self._states[min(self._i, len(self._states) - 1)]
        self._i += 1
        return self._session.model_copy(update={"state": state})


def _write_min_pe(path: Path, machine: int = 0x8664) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(image))


class _Host(DotnetAnalysisMixin):
    def __init__(self, settings: Any, registry: SessionRegistry) -> None:
        self.settings = settings
        self.registry = registry
        self._de4dot_runner = lambda *a, **k: None
        self._net_reactor_slayer_runner = lambda *a, **k: None


def _host(tmp_path: Path, *, de4dot: Path | None = None, nrs: Path | None = None) -> tuple[
    _Host, str, Path
]:
    pe = tmp_path / "app.exe"
    _write_min_pe(pe)
    registry = SessionRegistry()
    session = registry.create(pe)
    settings = SimpleNamespace(de4dot=de4dot, net_reactor_slayer=nrs, artifact_root=tmp_path)
    return _Host(settings, registry), session.id, pe


class _Report:
    def to_dict(self) -> dict[str, Any]:
        return {"clr": True}


# ---------------------------------------------------------------------------
# dotnet_inspect


def test_inspect_rejects_a_non_boolean_flag(tmp_path: Path) -> None:
    host, sid, _pe = _host(tmp_path)

    result = host.dotnet_inspect(sid, require_verified=1)  # type: ignore[arg-type]

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_inspect_maps_an_inspect_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise DotnetInspectError("not_dotnet", "not a .NET assembly", details={"why": "no clr"})

    monkeypatch.setattr(service_dotnet, "inspect_dotnet", _raise)

    result = host.dotnet_inspect(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_dotnet"


# ---------------------------------------------------------------------------
# dotnet_deobfuscate


def test_deobfuscate_reports_missing_de4dot(tmp_path: Path) -> None:
    host, sid, _pe = _host(tmp_path, de4dot=None)

    result = host.dotnet_deobfuscate(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_deobfuscate_refuses_a_changed_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    host, sid, pe = _host(tmp_path, de4dot=exe)
    monkeypatch.setattr(service_dotnet, "inspect_dotnet", lambda *a, **k: _Report())
    pe.write_bytes(b"the-input-was-swapped-after-open")  # sha now differs from session

    result = host.dotnet_deobfuscate(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_deobfuscate_maps_a_de4dot_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    host, sid, _pe = _host(tmp_path, de4dot=exe)

    def _raise(*a: Any, **k: Any) -> Any:
        raise De4dotError("process_failed", "de4dot blew up")

    monkeypatch.setattr(service_dotnet, "inspect_dotnet", _raise)

    result = host.dotnet_deobfuscate(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "process_failed"


# ---------------------------------------------------------------------------
# dotnet_reactor_unpack


def test_reactor_reports_missing_slayer(tmp_path: Path) -> None:
    host, sid, _pe = _host(tmp_path, nrs=None)

    result = host.dotnet_reactor_unpack(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "capability_unavailable"


def test_reactor_refuses_a_changed_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    host, sid, pe = _host(tmp_path, nrs=exe)
    monkeypatch.setattr(service_dotnet, "inspect_dotnet", lambda *a, **k: _Report())
    pe.write_bytes(b"swapped-after-open")

    result = host.dotnet_reactor_unpack(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "input_changed"


def test_reactor_maps_a_slayer_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "NETReactorSlayer.CLI.exe"
    exe.write_bytes(b"placeholder")
    host, sid, _pe = _host(tmp_path, nrs=exe)

    def _raise(*a: Any, **k: Any) -> Any:
        raise NetReactorSlayerError("process_failed", "slayer blew up")

    monkeypatch.setattr(service_dotnet, "inspect_dotnet", _raise)

    result = host.dotnet_reactor_unpack(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "process_failed"


# ---------------------------------------------------------------------------
# dotnet_enumerate


def test_enumerate_maps_an_inspect_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise DotnetInspectError("invalid_params", "unknown table kind")

    monkeypatch.setattr(service_dotnet, "enumerate_metadata", _raise)

    result = host.dotnet_enumerate(sid, "TypeDef")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_enumerate_maps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(service_dotnet, "enumerate_metadata", _raise)

    result = host.dotnet_enumerate(sid, "TypeDef")

    assert not result.ok


# ---------------------------------------------------------------------------
# dotnet_il


def test_il_returns_the_disassembly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)
    monkeypatch.setattr(
        service_dotnet,
        "disassemble_method_il",
        lambda *a, **k: {"instructions": [{"op": "ret"}], "token": 0x06000001},
    )

    result = host.dotnet_il(sid, 0x06000001)

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["instructions"][0]["op"] == "ret"


def test_il_maps_an_inspect_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise DotnetInspectError("invalid_params", "not a MethodDef token")

    monkeypatch.setattr(service_dotnet, "disassemble_method_il", _raise)

    result = host.dotnet_il(sid, 0x02000001)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_il_maps_an_unexpected_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise RuntimeError("decoder crashed")

    monkeypatch.setattr(service_dotnet, "disassemble_method_il", _raise)

    result = host.dotnet_il(sid, 0x06000001)

    assert not result.ok


# ---------------------------------------------------------------------------
# dotnet_xrefs


def test_xrefs_maps_an_inspect_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise DotnetInspectError("not_dotnet", "no metadata")

    monkeypatch.setattr(service_dotnet, "list_memberref_xrefs", _raise)

    result = host.dotnet_xrefs(sid)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_dotnet"


def test_xrefs_maps_an_unexpected_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(service_dotnet, "list_memberref_xrefs", _raise)

    result = host.dotnet_xrefs(sid)

    assert not result.ok


# ---------------------------------------------------------------------------
# dotnet_verify


def test_verify_rejects_a_path_that_does_not_exist(tmp_path: Path) -> None:
    host, sid, _pe = _host(tmp_path)

    result = host.dotnet_verify(sid, str(tmp_path / "missing.exe"))

    assert not result.ok


def test_verify_maps_an_inspect_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)
    target = tmp_path / "artifact.exe"
    target.write_bytes(b"artifact-bytes")
    monkeypatch.setattr(service_dotnet, "_session_owns_artifact_path", lambda *a, **k: True)

    def _raise(*a: Any, **k: Any) -> Any:
        raise DotnetInspectError("not_dotnet", "artifact is not a .NET image")

    monkeypatch.setattr(service_dotnet, "inspect_dotnet", _raise)

    result = host.dotnet_verify(sid, str(target))

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_dotnet"


# ---------------------------------------------------------------------------
# unexpected-error and state-gate arms


def test_inspect_maps_an_unexpected_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host, sid, _pe = _host(tmp_path)

    def _raise(*a: Any, **k: Any) -> Any:
        raise RuntimeError("segfault in reader")

    monkeypatch.setattr(service_dotnet, "inspect_dotnet", _raise)

    result = host.dotnet_inspect(sid)

    assert not result.ok


def test_deobfuscate_is_refused_on_a_failed_session(tmp_path: Path) -> None:
    host, sid, _pe = _host(tmp_path, de4dot=tmp_path / "de4dot.exe")
    host.registry.transition(sid, SessionState.FAILED)

    result = host.dotnet_deobfuscate(sid)

    assert not result.ok


def test_reactor_is_refused_on_a_failed_session(tmp_path: Path) -> None:
    host, sid, _pe = _host(tmp_path, nrs=tmp_path / "nrs.exe")
    host.registry.transition(sid, SessionState.FAILED)

    result = host.dotnet_reactor_unpack(sid)

    assert not result.ok


def _seq_host(
    tmp_path: Path,
    states: list[SessionState],
    *,
    de4dot: Path | None = None,
    nrs: Path | None = None,
) -> _Host:
    pe = tmp_path / "app.exe"
    _write_min_pe(pe)
    session = Session(
        target=TargetKind.PE,
        binary=pe,
        locator=str(pe),
        sha256=file_sha256(pe),
        state=SessionState.READY,
    )
    settings = SimpleNamespace(de4dot=de4dot, net_reactor_slayer=nrs, artifact_root=tmp_path)
    host = _Host(settings, _SeqRegistry(session, states))  # type: ignore[arg-type]
    host._de4dot_runner = lambda *a, **k: SimpleNamespace(output_path=str(pe), to_dict=lambda: {})
    host._net_reactor_slayer_runner = lambda *a, **k: SimpleNamespace(
        output_path=str(pe), to_dict=lambda: {}
    )
    return host


def test_deobfuscate_rolls_back_when_the_session_closes_midway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "de4dot.exe"
    exe.write_bytes(b"placeholder")
    host = _seq_host(tmp_path, [SessionState.READY, SessionState.CLOSED], de4dot=exe)
    monkeypatch.setattr(service_dotnet, "inspect_dotnet", lambda *a, **k: _Report())

    result = host.dotnet_deobfuscate("sid")

    assert not result.ok


def test_reactor_rolls_back_when_the_session_closes_midway(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = tmp_path / "nrs.exe"
    exe.write_bytes(b"placeholder")
    host = _seq_host(tmp_path, [SessionState.READY, SessionState.CLOSED], nrs=exe)
    monkeypatch.setattr(service_dotnet, "inspect_dotnet", lambda *a, **k: _Report())

    result = host.dotnet_reactor_unpack("sid")

    assert not result.ok
