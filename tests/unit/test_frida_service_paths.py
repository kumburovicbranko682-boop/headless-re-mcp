"""Success and error-mapping paths for the device-aware Frida service.

The frida.* field and closed-session suites drive the authorization guard and
the post-mutation state re-check, but the service mixin's own read bodies -- the
remote-endpoint connect branch, the applications/java_enumerate success wraps,
the FridaError/AdbError envelope mapping, the missing-authorization guard, and
the "most recently spawned pid" default -- ran in none of them. These drive a
real AnalysisService with an open session and a fake FridaClient so the whole
service layer runs without a real frida-core.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_frida
from headless_re_mcp.core.service import AnalysisService


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FridaStub:
    """A FridaClient stand-in whose methods are supplied per test."""

    def __init__(self, **methods: Any) -> None:
        for name, fn in methods.items():
            setattr(self, name, fn)


def _service_with_session(tmp_path: Path) -> tuple[AnalysisService, str]:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


def _authorize(service: AnalysisService, session_id: str, *, pids: list[int] | None = None) -> None:
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": list(pids or []), "packages": []}},
    )


def _patch_frida(monkeypatch: pytest.MonkeyPatch, stub: _FridaStub) -> None:
    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: stub)


# --- frida.devices (session-independent) ------------------------------------


def test_frida_devices_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    payload = {"devices": [{"id": "usb", "name": "Local USB", "type": "usb"}], "count": 1}
    _patch_frida(monkeypatch, _FridaStub(enumerate_devices=lambda: payload))
    service, _ = _service_with_session(tmp_path)
    try:
        result = service.frida_devices()
        assert result.ok is True, result.error
        assert result.data is not None and result.data["count"] == 1
        assert result.meta.get("backend") == "frida"
    finally:
        service.close_all()


def test_frida_devices_maps_a_frida_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _boom() -> Any:
        raise FridaError("backend_error", "frida host unreachable")

    _patch_frida(monkeypatch, _FridaStub(enumerate_devices=_boom))
    service, _ = _service_with_session(tmp_path)
    try:
        result = service.frida_devices()
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_frida_devices_maps_an_unexpected_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _boom() -> Any:
        raise RuntimeError("frida-core segfault")

    _patch_frida(monkeypatch, _FridaStub(enumerate_devices=_boom))
    service, _ = _service_with_session(tmp_path)
    try:
        result = service.frida_devices()
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


# --- frida.device.connect ----------------------------------------------------


def test_frida_device_connect_via_remote_endpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A non-empty endpoint takes the add_remote_device branch and authorizes it."""
    info = {"id": "10.0.0.5:5555", "name": "remote", "type": "remote"}
    _patch_frida(monkeypatch, _FridaStub(add_remote_device=lambda endpoint: info))
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.frida_device_connect(session_id, endpoint="10.0.0.5:5555")
        assert result.ok is True, result.error
        assert result.data is not None and result.data["device"]["id"] == "10.0.0.5:5555"
        auth = service.registry.get(session_id).metadata.get("frida_authorized")
        assert isinstance(auth, dict) and auth["device_id"] == "10.0.0.5:5555"
    finally:
        service.close_all()


def test_frida_device_connect_maps_a_frida_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _boom(endpoint: str) -> Any:
        raise FridaError("not_found", "no device at endpoint")

    _patch_frida(monkeypatch, _FridaStub(add_remote_device=_boom))
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.frida_device_connect(session_id, endpoint="10.0.0.5:5555")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


# --- frida.server.ensure -----------------------------------------------------


def test_frida_server_ensure_success(tmp_path: Path) -> None:
    """A server that comes up records the timeline row and returns ok."""

    class _AdbStub:
        def ensure_frida_server(self, *args: object, **kwargs: object) -> Any:
            return {"ensured": True, "port": 27042}

    service, session_id = _service_with_session(tmp_path)
    service._adb_backend = _AdbStub()  # type: ignore[assignment]
    try:
        result = service.frida_server_ensure(session_id, serial="emulator-5554")
        assert result.ok is True, result.error
        assert result.data is not None and result.data["ensured"] is True
    finally:
        service.close_all()


def test_frida_server_ensure_maps_an_adb_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An AdbError from ensuring the server surfaces through the envelope."""

    class _AdbStub:
        def ensure_frida_server(self, *args: object, **kwargs: object) -> Any:
            raise AdbError("backend_error", "cannot push frida-server")

    service, session_id = _service_with_session(tmp_path)
    service._adb_backend = _AdbStub()  # type: ignore[assignment]
    try:
        result = service.frida_server_ensure(session_id, serial="emulator-5554")
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


# --- frida.applications ------------------------------------------------------


def test_frida_applications_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    payload = {"applications": [{"identifier": "com.x", "name": "X"}], "count": 1}
    seen: dict[str, int] = {}

    def _apps(device_id: Any, *, offset: int = 0, limit: int = 256) -> Any:
        seen["offset"] = offset
        seen["limit"] = limit
        return payload

    _patch_frida(monkeypatch, _FridaStub(applications=_apps))
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id)
    try:
        result = service.frida_applications(session_id, offset=30, limit=15)
        assert result.ok is True, result.error
        assert result.data is not None and result.data["count"] == 1
        # The service must forward the page window to the client, not drop it.
        assert seen == {"offset": 30, "limit": 15}
    finally:
        service.close_all()


def test_frida_applications_maps_a_frida_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _boom(device_id: Any, *, offset: int = 0, limit: int = 256) -> Any:
        raise FridaError("backend_error", "enumeration failed")

    _patch_frida(monkeypatch, _FridaStub(applications=_boom))
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id)
    try:
        result = service.frida_applications(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_frida_applications_maps_an_unexpected_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _boom(device_id: Any, *, offset: int = 0, limit: int = 256) -> Any:
        raise RuntimeError("frida-core enumeration segfault")

    _patch_frida(monkeypatch, _FridaStub(applications=_boom))
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id)
    try:
        result = service.frida_applications(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_frida_applications_without_authorization_is_invalid_state(tmp_path: Path) -> None:
    """A session that never connected a device is refused, not silently degraded."""
    service, session_id = _service_with_session(tmp_path)
    try:
        result = service.frida_applications(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_state"
        assert "connect a frida device" in result.error.message
    finally:
        service.close_all()


# --- frida.spawn -------------------------------------------------------------


def test_frida_spawn_maps_a_frida_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def _boom(device_id: Any, package: str) -> Any:
        raise FridaError("backend_error", "spawn refused")

    _patch_frida(monkeypatch, _FridaStub(spawn=_boom))
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id)
    try:
        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


# --- frida.java.* (classes / methods) ---------------------------------------


def test_frida_java_classes_defaults_to_the_last_spawned_pid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With no explicit pid, the enumeration targets the most recent pid."""
    seen: dict[str, Any] = {}

    def _enumerate(device_id: Any, pid: int, **kwargs: Any) -> Any:
        seen["pid"] = pid
        return {"classes": ["Lcom/x/Main;"], "count": 1}

    _patch_frida(monkeypatch, _FridaStub(java_enumerate=_enumerate))
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id, pids=[321, 654])
    try:
        result = service.frida_java_classes(session_id)
        assert result.ok is True, result.error
        assert seen["pid"] == 654
    finally:
        service.close_all()


def test_frida_java_methods_honors_an_explicit_pid(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}

    def _enumerate(device_id: Any, pid: int, **kwargs: Any) -> Any:
        seen["pid"] = pid
        return {"methods": [], "count": 0}

    _patch_frida(monkeypatch, _FridaStub(java_enumerate=_enumerate))
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id, pids=[100])
    try:
        result = service.frida_java_methods(session_id, "com.x.Main", pid=999)
        assert result.ok is True, result.error
        assert seen["pid"] == 999
    finally:
        service.close_all()


def test_frida_java_without_any_pid_is_invalid_state(tmp_path: Path) -> None:
    """An authorized session that never spawned has no default pid to target."""
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id, pids=[])
    try:
        result = service.frida_java_classes(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_state"
        assert "call frida.spawn first" in result.error.message
    finally:
        service.close_all()


def test_frida_java_maps_an_unexpected_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _boom(device_id: Any, pid: int, **kwargs: Any) -> Any:
        raise RuntimeError("frida script host crashed")

    _patch_frida(monkeypatch, _FridaStub(java_enumerate=_boom))
    service, session_id = _service_with_session(tmp_path)
    _authorize(service, session_id, pids=[100])
    try:
        result = service.frida_java_classes(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()
