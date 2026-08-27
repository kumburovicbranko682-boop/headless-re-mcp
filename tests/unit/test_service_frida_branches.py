"""Branch coverage for the device-aware Frida service mixin.

Every device call is bounded by a per-session authorization: a session must
connect a device before it can enumerate/spawn, a pid must trace back to a
spawn this session performed, and a close arriving mid-call must not record the
dead session as owning a fresh pid. Backend FridaError/AdbError become
structured failures; unexpected exceptions are still captured. These fakes
drive those branches without a device; the live gate pins the real tool.
"""

from __future__ import annotations

import types
import zipfile
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_frida
from headless_re_mcp.core.models import SessionState
from headless_re_mcp.core.service import AnalysisService

MP = pytest.MonkeyPatch
_AUTH = "frida_authorized"


def _write_apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
    return path


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    svc._apk = _write_apk(tmp_path / "app.apk")  # type: ignore[attr-defined]
    try:
        yield svc
    finally:
        svc.close_all()


def _session(service: AnalysisService) -> str:
    created = service.create_session(str(service._apk), target="apk")  # type: ignore[attr-defined]
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _authorize(service: AnalysisService, session_id: str, **auth: Any) -> None:
    record = {"device_id": "dev1", "pids": [], "packages": []}
    record.update(auth)
    service.registry.update_metadata(session_id, {_AUTH: record})


def _force_state(service: AnalysisService, session_id: str, state: SessionState) -> None:
    service.registry._sessions[session_id].state = state


class _FridaStub:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def enumerate_devices(self) -> dict[str, Any]:
        return {"devices": [{"id": "dev1"}]}

    def add_remote_device(self, endpoint: str) -> dict[str, Any]:
        return {"id": f"remote:{endpoint}", "name": "remote"}

    def _resolve_device(self, device_id: str) -> Any:
        return types.SimpleNamespace(id="dev1", name="Pixel", type="usb")

    def applications(self, device_id: Any, *, limit: int = 256) -> dict[str, Any]:
        return {"applications": [], "device": device_id}

    def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
        return {"pid": 4321, "package": package}

    def java_enumerate(
        self,
        device_id: Any,
        target_pid: int,
        *,
        allowed_pids: Any,
        mode: str,
        class_name: Any,
        name_filter: Any,
        limit: int,
    ) -> dict[str, Any]:
        return {"mode": mode, "pid": target_pid, "items": []}


class TestDevices:
    def test_devices_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        result = service.frida_devices()
        assert result.ok is True and result.data is not None
        assert result.data["devices"] == [{"id": "dev1"}]

    def test_devices_maps_backend_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Err(_FridaStub):
            def enumerate_devices(self) -> dict[str, Any]:
                raise FridaError("capability_unavailable", "no frida")

        monkeypatch.setattr(service_frida, "FridaClient", _Err)
        result = service.frida_devices()
        assert result.ok is False and result.error is not None
        assert result.error.code == "capability_unavailable"

    def test_devices_captures_unexpected(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Boom(_FridaStub):
            def enumerate_devices(self) -> dict[str, Any]:
                raise RuntimeError("kaboom")

        monkeypatch.setattr(service_frida, "FridaClient", _Boom)
        assert service.frida_devices().ok is False


class TestConnect:
    def test_connect_via_local_device(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        result = service.frida_device_connect(sid, device_id="usb")
        assert result.ok is True and result.data is not None
        assert result.data["connected"] is True
        auth = service.registry.get(sid).metadata.get(_AUTH)
        assert auth is not None and auth["device_id"] == "dev1"

    def test_connect_via_remote_endpoint(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        result = service.frida_device_connect(sid, endpoint="10.0.0.5:27042")
        assert result.ok is True and result.data is not None
        assert result.data["device"]["id"] == "remote:10.0.0.5:27042"

    def test_connect_maps_backend_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Err(_FridaStub):
            def _resolve_device(self, device_id: str) -> Any:
                raise FridaError("not_found", "no such device")

        monkeypatch.setattr(service_frida, "FridaClient", _Err)
        sid = _session(service)
        result = service.frida_device_connect(sid, device_id="usb")
        assert result.ok is False and result.error is not None
        assert result.error.code == "not_found"

    def test_connect_refuses_a_closed_session(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        _force_state(service, sid, SessionState.CLOSED)
        result = service.frida_device_connect(sid, device_id="usb")
        assert result.ok is False


class TestServerEnsure:
    def test_server_ensure_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _FakeAdb:
            def ensure_frida_server(
                self, serial: str, *, server_binary: Any, port: int, bind_host: str
            ) -> dict[str, Any]:
                return {"serial": serial, "running": True, "port": port}

        monkeypatch.setattr(service, "_adb_backend", _FakeAdb(), raising=False)
        sid = _session(service)
        result = service.frida_server_ensure(sid, serial="emulator-5554")
        assert result.ok is True and result.data is not None
        assert result.data["running"] is True

    def test_server_ensure_maps_adb_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _FakeAdb:
            def ensure_frida_server(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise AdbError("backend_error", "push failed")

        monkeypatch.setattr(service, "_adb_backend", _FakeAdb(), raising=False)
        sid = _session(service)
        result = service.frida_server_ensure(sid, serial="emulator-5554")
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"

    def test_server_ensure_captures_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _FakeAdb:
            def ensure_frida_server(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

        monkeypatch.setattr(service, "_adb_backend", _FakeAdb(), raising=False)
        sid = _session(service)
        assert service.frida_server_ensure(sid, serial="emulator-5554").ok is False


class TestApplicationsSpawnJava:
    def test_applications_requires_a_connected_device(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)  # no _authorize: metadata lacks the auth record
        result = service.frida_applications(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"

    def test_applications_success(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        _authorize(service, sid)
        result = service.frida_applications(sid)
        assert result.ok is True and result.data is not None
        assert result.data["device"] == "dev1"

    def test_applications_captures_unexpected(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        class _Boom(_FridaStub):
            def applications(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

        monkeypatch.setattr(service_frida, "FridaClient", _Boom)
        sid = _session(service)
        _authorize(service, sid)
        assert service.frida_applications(sid).ok is False

    def test_spawn_success_records_pid(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        _authorize(service, sid)
        result = service.frida_spawn(sid, "com.example.app")
        assert result.ok is True and result.data is not None
        assert result.data["pid"] == 4321
        auth = service.registry.get(sid).metadata.get(_AUTH)
        assert auth is not None and auth["pids"][-1] == 4321
        assert "com.example.app" in auth["packages"]

    def test_spawn_maps_backend_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Err(_FridaStub):
            def spawn(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise FridaError("backend_error", "spawn failed")

        monkeypatch.setattr(service_frida, "FridaClient", _Err)
        sid = _session(service)
        _authorize(service, sid)
        result = service.frida_spawn(sid, "com.example.app")
        assert result.ok is False and result.error is not None
        assert result.error.code == "backend_error"

    def test_spawn_captures_unexpected(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Boom(_FridaStub):
            def spawn(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

        monkeypatch.setattr(service_frida, "FridaClient", _Boom)
        sid = _session(service)
        _authorize(service, sid)
        assert service.frida_spawn(sid, "com.example.app").ok is False

    def test_java_classes_success_defaults_to_last_pid(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        _authorize(service, sid, pids=[100, 200])
        result = service.frida_java_classes(sid, name_filter="Foo")
        assert result.ok is True and result.data is not None
        assert result.data["mode"] == "classes"
        assert result.data["pid"] == 200  # newest authorized pid

    def test_java_methods_success_with_explicit_pid(
        self, service: AnalysisService, monkeypatch: MP
    ) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        _authorize(service, sid, pids=[100])
        result = service.frida_java_methods(sid, class_name="com.x.Y", pid=100)
        assert result.ok is True and result.data is not None
        assert result.data["mode"] == "methods"

    def test_java_requires_a_pid(self, service: AnalysisService, monkeypatch: MP) -> None:
        monkeypatch.setattr(service_frida, "FridaClient", _FridaStub)
        sid = _session(service)
        _authorize(service, sid, pids=[])  # connected, but never spawned
        result = service.frida_java_classes(sid)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"

    def test_java_maps_backend_error(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Err(_FridaStub):
            def java_enumerate(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise FridaError("invalid_state", "pid not authorized")

        monkeypatch.setattr(service_frida, "FridaClient", _Err)
        sid = _session(service)
        _authorize(service, sid, pids=[100])
        result = service.frida_java_classes(sid, pid=100)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"

    def test_java_captures_unexpected(self, service: AnalysisService, monkeypatch: MP) -> None:
        class _Boom(_FridaStub):
            def java_enumerate(self, *a: Any, **k: Any) -> dict[str, Any]:
                raise RuntimeError("boom")

        monkeypatch.setattr(service_frida, "FridaClient", _Boom)
        sid = _session(service)
        _authorize(service, sid, pids=[100])
        assert service.frida_java_classes(sid, pid=100).ok is False
