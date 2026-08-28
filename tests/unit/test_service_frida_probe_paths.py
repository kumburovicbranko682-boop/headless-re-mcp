"""Coverage for the pid-based Frida probe methods in ``core/service_ext``.

Separate from the device-aware mixin in ``core/service_frida`` (covered by
``test_service_frida_paths``), ``service_ext`` carries the probe helpers that
run against a live debuggee pid: ``frida_attach`` / ``frida_modules`` /
``frida_exports`` / ``frida_memory_read`` and the PE arm of
``frida_hook_template``. Because FridaClient is never available in the quality
environment and these need a debuggee pid, their success surface, the
``FridaError`` -> envelope mapping, and the ``_require_debuggee_pid`` guard were
unreached. These fake FridaClient and the dynamic-state probe to drive them.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

_AUTH_KEY = "frida_authorized"


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeFrida:
    def __init__(self, *args: object, **kwargs: object) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def attach(self, pid: int, *, allowed_pid: int) -> dict[str, Any]:
        self.calls.append(("attach", pid, allowed_pid))
        return {"pid": pid, "attached": True}

    def modules(self, pid: int, *, allowed_pid: int, limit: int = 64) -> dict[str, Any]:
        self.calls.append(("modules", pid))
        return {"modules": [{"name": "libc.so"}], "count": 1}

    def exports(
        self, pid: int, module_name: str, *, allowed_pid: int, limit: int = 64
    ) -> dict[str, Any]:
        self.calls.append(("exports", module_name))
        return {"module": module_name, "exports": [], "count": 0}

    def memory_read(self, pid: int, address: int, size: int, *, allowed_pid: int) -> dict[str, Any]:
        self.calls.append(("memory_read", address, size))
        return {"address": address, "size": size, "hex": "00" * size}

    def hook_template(self, pid: int, template: str, *, allowed_pid: int) -> dict[str, Any]:
        self.calls.append(("hook_template", template, pid))
        return {"template": template, "pid": pid}

    def hook_template_device(
        self, device_id: str | None, pid: int, template: str, *, allowed_pids: Any
    ) -> dict[str, Any]:
        self.calls.append(("hook_template_device", template, pid))
        return {"template": template, "pid": pid, "device": device_id}


class _BoomFrida:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise FridaError("permission_denied", "pid not in the authorized set")

        return _fn


class _CrashFrida:
    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("frida wrapper blew up")

        return _fn


# Each pid-based probe, with call args, so the error arms can be swept uniformly.
_PROBES: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = [
    ("frida_attach", (), {}),
    ("frida_modules", (), {}),
    ("frida_exports", ("libc.so",), {}),
    ("frida_memory_read", (0x1000, 4), {}),
    ("frida_hook_template", (), {"template": "noop"}),
]


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def _pe_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _with_debuggee(monkeypatch: Any, service: AnalysisService, pid: int = 4321) -> None:
    """Make the dynamic-state probe report a live debuggee pid."""
    monkeypatch.setattr(
        service,
        "dynamic_state",
        lambda session_id, **kwargs: Result(ok=True, data={"debuggee_pid": pid}),
    )


def _patch_frida(monkeypatch: Any, factory: Any) -> None:
    monkeypatch.setattr("headless_re_mcp.core.service_ext.FridaClient", factory)


# --------------------------------------------------------------------------- #
# _require_debuggee_pid guard                                                  #
# --------------------------------------------------------------------------- #
def test_frida_attach_without_a_debuggee_is_invalid_state(
    tmp_path: Path, monkeypatch: Any
) -> None:
    _patch_frida(monkeypatch, _FakeFrida)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        result = service.frida_attach(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# happy paths                                                                  #
# --------------------------------------------------------------------------- #
def test_frida_attach_probes_the_debuggee(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeFrida()
    _patch_frida(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        _with_debuggee(monkeypatch, service)
        result = service.frida_attach(session_id)
        assert result.ok, result.error
        assert result.data is not None and result.data["pid"] == 4321
        assert result.meta["backend"] == "frida"
        assert ("attach", 4321, 4321) in fake.calls
    finally:
        service.close_all()


def test_frida_modules_lists_for_the_debuggee(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeFrida()
    _patch_frida(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        _with_debuggee(monkeypatch, service)
        result = service.frida_modules(session_id, limit=8)
        assert result.ok, result.error
        assert result.data is not None and result.data["count"] == 1
        assert result.meta["backend"] == "frida"
    finally:
        service.close_all()


def test_frida_exports_reads_a_module(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeFrida()
    _patch_frida(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        _with_debuggee(monkeypatch, service)
        result = service.frida_exports(session_id, "libc.so")
        assert result.ok, result.error
        assert result.data is not None and result.data["module"] == "libc.so"
    finally:
        service.close_all()


def test_frida_memory_read_returns_bytes(tmp_path: Path, monkeypatch: Any) -> None:
    fake = _FakeFrida()
    _patch_frida(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        _with_debuggee(monkeypatch, service)
        result = service.frida_memory_read(session_id, 0x1000, 4)
        assert result.ok, result.error
        assert result.data is not None and result.data["size"] == 4
    finally:
        service.close_all()


def test_frida_hook_template_uses_the_debuggee_pid_without_a_device(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake = _FakeFrida()
    _patch_frida(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        _with_debuggee(monkeypatch, service)
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok, result.error
        assert result.data is not None and result.data["template"] == "noop"
        assert ("hook_template", "noop", 4321) in fake.calls
    finally:
        service.close_all()


def test_frida_attach_reports_invalid_state_for_a_nonpositive_pid(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A dynamic state that resolves but carries no live pid is still invalid."""
    _patch_frida(monkeypatch, _FakeFrida)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        monkeypatch.setattr(
            service,
            "dynamic_state",
            lambda session_id, **kwargs: Result(ok=True, data={"debuggee_pid": 0}),
        )
        result = service.frida_attach(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# frida_hook_template device branch (APK/web session with authorized pids)     #
# --------------------------------------------------------------------------- #
def test_frida_hook_template_uses_the_authorized_device_pid(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake = _FakeFrida()
    _patch_frida(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        service.registry.update_metadata(
            session_id, {_AUTH_KEY: {"device_id": "usb", "pids": [7777]}}
        )
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok, result.error
        assert result.data is not None and result.data["device"] == "usb"
        assert ("hook_template_device", "noop", 7777) in fake.calls
    finally:
        service.close_all()


def test_frida_hook_template_device_branch_rejects_a_closed_session(
    tmp_path: Path, monkeypatch: Any
) -> None:
    fake = _FakeFrida()
    _patch_frida(monkeypatch, lambda *a, **k: fake)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        service.registry.update_metadata(
            session_id, {_AUTH_KEY: {"device_id": "usb", "pids": [7777]}}
        )
        closed = service.close_session(session_id)
        assert closed.ok, closed.error
        result = service.frida_hook_template(session_id, template="noop")
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_request"
        assert fake.calls == []  # never injected into the device process
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# FridaError / unexpected-error envelope mapping (all probe methods)           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("method", "args", "kwargs"), _PROBES)
def test_frida_probes_map_a_frida_error(
    tmp_path: Path, monkeypatch: Any, method: str, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> None:
    _patch_frida(monkeypatch, _BoomFrida)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        _with_debuggee(monkeypatch, service)
        result = getattr(service, method)(session_id, *args, **kwargs)
        assert result.ok is False and result.error is not None
        assert result.error.code == "permission_denied"
    finally:
        service.close_all()


@pytest.mark.parametrize(("method", "args", "kwargs"), _PROBES)
def test_frida_probes_wrap_an_unexpected_error(
    tmp_path: Path, monkeypatch: Any, method: str, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> None:
    _patch_frida(monkeypatch, _CrashFrida)
    service = _service(tmp_path)
    try:
        session_id = _pe_session(service, tmp_path)
        _with_debuggee(monkeypatch, service)
        result = getattr(service, method)(session_id, *args, **kwargs)
        assert result.ok is False and result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()
