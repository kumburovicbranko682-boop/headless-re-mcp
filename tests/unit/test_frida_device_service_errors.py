"""Device-free error contract for the frida device service methods.

``test_frida_service_authorization`` pins the authorization model and the happy
connect/spawn/java paths through a full ``AnalysisService`` with a stub frida
device. What is left, and what this file closes, are the error-mapping branches
every device tool shares -- a ``FridaError`` or ``AdbError`` surfaced as a
structured failure carrying the session id, never a bare exception -- plus
``frida.applications``' success path and the "no pid spawned yet" guard.

All of it is decided in the service layer from session metadata and backend
replies, so a device-less VM proves it by handing the monkeypatched
``FridaClient``/``AdbBackend`` canned answers; nothing touches hardware.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_frida import _last_pid

_FRIDA = "headless_re_mcp.core.service_frida.FridaClient"


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.invalid/app", target="web")
    assert created.ok and created.data is not None, created.error
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


# --- frida.devices (no session) --------------------------------------------


def test_frida_devices_reports_available_transports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Client:
        def enumerate_devices(self) -> dict[str, object]:
            return {"devices": [{"id": "usb", "type": "usb"}], "count": 1}

    monkeypatch.setattr(_FRIDA, lambda: _Client())
    service = _service(tmp_path)
    try:
        result = service.frida_devices()
        assert result.ok and result.data is not None, result.error
        assert result.data["count"] == 1
    finally:
        service.close_all()


def test_frida_devices_maps_a_frida_error_to_its_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Client:
        def enumerate_devices(self) -> dict[str, object]:
            raise FridaError("backend_error", "frida server unreachable")

    monkeypatch.setattr(_FRIDA, lambda: _Client())
    service = _service(tmp_path)
    try:
        result = service.frida_devices()
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


def test_frida_devices_maps_an_unexpected_error_to_internal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Client:
        def enumerate_devices(self) -> dict[str, object]:
            raise RuntimeError("kaboom")

    monkeypatch.setattr(_FRIDA, lambda: _Client())
    service = _service(tmp_path)
    try:
        result = service.frida_devices()
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "internal_error"
    finally:
        service.close_all()


# --- frida.device.connect error mapping ------------------------------------


def test_frida_device_connect_maps_a_usb_resolve_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A FridaError while resolving the USB device fails with its code, no bind."""

    class _Client:
        def _resolve_device(self, device_id: str | None) -> object:
            raise FridaError("not_found", "no usb device present")

    monkeypatch.setattr(_FRIDA, lambda: _Client())
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.frida_device_connect(session_id, device_id="usb")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "not_found"
        # A failed resolve must never leave the session recorded as holding a device.
        assert "frida_authorized" not in service.registry.get(session_id).metadata
    finally:
        service.close_all()


def test_frida_device_connect_maps_a_remote_endpoint_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An AdbError on the remote path is mapped through the same tuple branch."""

    class _Client:
        def add_remote_device(self, endpoint: str) -> dict[str, str]:
            raise AdbError("backend_error", "cannot reach endpoint")

    monkeypatch.setattr(_FRIDA, lambda: _Client())
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.frida_device_connect(session_id, endpoint="10.0.0.5:27042")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
        assert "frida_authorized" not in service.registry.get(session_id).metadata
    finally:
        service.close_all()


# --- frida.server.ensure ----------------------------------------------------


class _AdbFake:
    def __init__(
        self, *, data: dict[str, object] | None = None, exc: Exception | None = None
    ) -> None:
        self._data = data
        self._exc = exc

    def ensure_frida_server(
        self, serial: str, *, server_binary: str | None = None, port: int = 27042
    ) -> dict[str, object]:
        del serial, server_binary, port
        if self._exc is not None:
            raise self._exc
        return dict(self._data or {})


def test_frida_server_ensure_reports_success(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._adb_backend = _AdbFake(data={"running": True, "port": 27042})
        result = service.frida_server_ensure(session_id, "emulator-5554")
        assert result.ok and result.data is not None, result.error
        assert result.data["running"] is True
    finally:
        service.close_all()


def test_frida_server_ensure_maps_an_adb_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._adb_backend = _AdbFake(exc=AdbError("backend_error", "adb push failed"))
        result = service.frida_server_ensure(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "backend_error"
    finally:
        service.close_all()


# --- frida.applications success + the no-pid guard --------------------------


def test_frida_applications_lists_installed_apps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a device is connected, application enumeration returns its payload."""

    class _Client:
        def _resolve_device(self, device_id: str | None) -> object:
            return SimpleNamespace(id="emulator-5554", name="Emu", type="usb")

        def applications(self, device_id: str | None, limit: int = 256) -> dict[str, object]:
            del device_id, limit
            return {"applications": [{"identifier": "com.a", "name": "A"}], "count": 1}

    monkeypatch.setattr(_FRIDA, lambda: _Client())
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        assert service.frida_device_connect(session_id, device_id="usb").ok
        result = service.frida_applications(session_id)
        assert result.ok and result.data is not None, result.error
        assert result.data["count"] == 1
    finally:
        service.close_all()


def test_last_pid_requires_a_prior_spawn() -> None:
    """The Java tools default to the last spawned pid; with none, refuse clearly."""
    with pytest.raises(FridaError) as caught:
        _last_pid({"pids": []})
    assert caught.value.code == "invalid_state"
    with pytest.raises(FridaError):
        _last_pid({})


def test_frida_java_without_a_spawn_is_invalid_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Connected but never spawned: default-pid Java enumeration is invalid_state."""

    class _Client:
        def _resolve_device(self, device_id: str | None) -> object:
            return SimpleNamespace(id="emulator-5554", name="Emu", type="usb")

    monkeypatch.setattr(_FRIDA, lambda: _Client())
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        assert service.frida_device_connect(session_id, device_id="usb").ok
        result = service.frida_java_classes(session_id)  # default pid=0, no spawn
        assert result.ok is False
        assert result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()
