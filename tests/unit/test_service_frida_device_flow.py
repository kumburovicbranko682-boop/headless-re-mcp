"""The Frida device mixin's happy paths and error mappings.

The existing frida suites pin the close-during-run guards on connect, ensure,
and spawn. What they never drive is the ordinary flow those guards protect:
enumerating devices, connecting by usb id and by remote endpoint, ensuring
frida-server, listing applications, and enumerating Java classes/methods for
an authorized pid -- plus the FridaError/AdbError-to-Result mapping on each,
the "connect a device first" refusal when a session has no authorization
record, and the "no spawned pid" refusal when a Java call has nothing to
target. This drives all of it with a fake FridaClient and a fake ADB backend
so no device is needed.
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

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _Device:
    def __init__(self, device_id: str) -> None:
        self.id = device_id
        self.name = "Pixel"
        self.type = "usb"


class _FakeFrida:
    """A FridaClient stand-in whose every call returns canned data."""

    def enumerate_devices(self) -> JsonObject:
        return {"devices": [{"id": "usb", "name": "Pixel", "type": "usb"}]}

    def add_remote_device(self, endpoint: str) -> JsonObject:
        return {"id": endpoint, "name": "remote", "type": "remote"}

    def _resolve_device(self, device_id: str) -> _Device:
        return _Device(device_id)

    def applications(self, device_id: Any, *, limit: int = 256) -> JsonObject:
        return {"device_id": device_id, "applications": [], "limit": limit}

    def spawn(self, device_id: Any, package: str) -> JsonObject:
        return {"package": package, "pid": 4242, "device": device_id}

    def java_enumerate(
        self,
        device_id: Any,
        target_pid: int,
        *,
        allowed_pids: Any,
        mode: str,
        class_name: str | None,
        name_filter: str | None,
        limit: int,
    ) -> JsonObject:
        return {
            "device_id": device_id,
            "pid": target_pid,
            "mode": mode,
            "class_name": class_name,
            "name_filter": name_filter,
            "allowed_pids": list(allowed_pids),
            "limit": limit,
        }


class _FakeAdb:
    def ensure_frida_server(
        self,
        serial: str,
        server_binary: str | None = None,
        port: int = 27042,
        bind_host: str = "127.0.0.1",
    ) -> JsonObject:
        return {"ensured": True, "running": True, "port": port, "serial": serial}


@pytest.fixture
def service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AnalysisService:
    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _FakeFrida())
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings)
    svc._adb_backend = _FakeAdb()  # type: ignore[assignment]
    return svc


def _open_session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _authorize(service: AnalysisService, session_id: str, **auth: Any) -> None:
    record = {"device_id": "usb", "pids": [], "packages": []}
    record.update(auth)
    service.registry.update_metadata(session_id, {"frida_authorized": record})


# --------------------------------------------------------------------------- #
# frida.devices                                                               #
# --------------------------------------------------------------------------- #
def test_devices_returns_the_enumerated_list(service: AnalysisService) -> None:
    try:
        result = service.frida_devices()
        assert result.ok and result.data is not None, result.error
        assert result.data["devices"][0]["id"] == "usb"
    finally:
        service.close_all()


def test_devices_maps_a_frida_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom:
        def enumerate_devices(self) -> JsonObject:
            raise FridaError("frida_unavailable", "frida is not installed", hint="pip install")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _Boom())
    try:
        result = service.frida_devices()
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "frida_unavailable"
        assert result.error.details["hint"] == "pip install"
    finally:
        service.close_all()


def test_devices_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Explode:
        def enumerate_devices(self) -> JsonObject:
            raise RuntimeError("segfault in libfrida")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _Explode())
    try:
        result = service.frida_devices()
        assert not result.ok
        assert result.error is not None
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# frida.device.connect: usb id and remote endpoint                            #
# --------------------------------------------------------------------------- #
def test_connect_by_usb_id_authorizes_the_session(service: AnalysisService, tmp_path: Path) -> None:
    try:
        sid = _open_session(service, tmp_path)
        result = service.frida_device_connect(sid, device_id="usb")
        assert result.ok and result.data is not None, result.error
        assert result.data["connected"] is True
        assert result.data["device"]["id"] == "usb"
        auth = service.registry.get(sid).metadata["frida_authorized"]
        assert auth == {"device_id": "usb", "pids": [], "packages": []}
    finally:
        service.close_all()


def test_connect_by_remote_endpoint_uses_the_returned_id(
    service: AnalysisService, tmp_path: Path
) -> None:
    try:
        sid = _open_session(service, tmp_path)
        result = service.frida_device_connect(sid, endpoint="10.0.0.5:27042")
        assert result.ok and result.data is not None, result.error
        assert result.data["device"]["type"] == "remote"
        auth = service.registry.get(sid).metadata["frida_authorized"]
        assert auth["device_id"] == "10.0.0.5:27042"
    finally:
        service.close_all()


def test_connect_maps_a_frida_error(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _NoDevice:
        def _resolve_device(self, device_id: str) -> Any:
            raise FridaError("device_not_found", f"no such device: {device_id}")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _NoDevice())
    try:
        sid = _open_session(service, tmp_path)
        result = service.frida_device_connect(sid, device_id="ghost")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "device_not_found"
        assert "frida_authorized" not in service.registry.get(sid).metadata
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# frida.server.ensure                                                         #
# --------------------------------------------------------------------------- #
def test_server_ensure_reports_the_backend_result(service: AnalysisService, tmp_path: Path) -> None:
    try:
        sid = _open_session(service, tmp_path)
        result = service.frida_server_ensure(sid, serial="emulator-5554", port=27043)
        assert result.ok and result.data is not None, result.error
        assert result.data["ensured"] is True
        assert result.data["port"] == 27043
    finally:
        service.close_all()


def test_server_ensure_maps_an_adb_error(service: AnalysisService, tmp_path: Path) -> None:
    class _FailingAdb:
        def ensure_frida_server(self, serial: str, **_kwargs: Any) -> JsonObject:
            raise AdbError("adb_unavailable", "adb not on PATH", serial=serial)

    service._adb_backend = _FailingAdb()  # type: ignore[assignment]
    try:
        sid = _open_session(service, tmp_path)
        result = service.frida_server_ensure(sid, serial="emulator-5554")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "adb_unavailable"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# authorization requirement and application listing                           #
# --------------------------------------------------------------------------- #
def test_applications_before_connecting_a_device_is_refused(
    service: AnalysisService, tmp_path: Path
) -> None:
    """No frida_authorized record means the session never connected a device."""
    try:
        sid = _open_session(service, tmp_path)
        result = service.frida_applications(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_state"
        assert "connect a frida device" in result.error.message
    finally:
        service.close_all()


def test_applications_lists_for_the_connected_device(
    service: AnalysisService, tmp_path: Path
) -> None:
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid)
        result = service.frida_applications(sid, limit=32)
        assert result.ok and result.data is not None, result.error
        assert result.data["device_id"] == "usb"
        assert result.data["limit"] == 32
    finally:
        service.close_all()


def test_applications_maps_a_frida_error(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom:
        def applications(self, device_id: Any, *, limit: int = 256) -> JsonObject:
            raise FridaError("device_gone", "device disconnected")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _Boom())
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid)
        result = service.frida_applications(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "device_gone"
    finally:
        service.close_all()


def test_applications_maps_an_unexpected_error(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Explode:
        def applications(self, device_id: Any, *, limit: int = 256) -> JsonObject:
            raise RuntimeError("frida host crashed")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _Explode())
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid)
        result = service.frida_applications(sid)
        assert not result.ok
        assert result.error is not None
    finally:
        service.close_all()


def test_spawn_maps_a_frida_error(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom:
        def spawn(self, device_id: Any, package: str) -> JsonObject:
            raise FridaError("spawn_failed", "package not installed")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _Boom())
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid)
        result = service.frida_spawn(sid, "com.absent.app")
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "spawn_failed"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# Java enumeration: class/method modes, pid selection, and its refusals       #
# --------------------------------------------------------------------------- #
def test_java_classes_targets_the_most_recent_pid_by_default(
    service: AnalysisService, tmp_path: Path
) -> None:
    """With pid=0 the mixin uses the last authorized pid, not the highest."""
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid, pids=[1000, 4242, 2000])
        result = service.frida_java_classes(sid, name_filter="com.app", limit=50)
        assert result.ok and result.data is not None, result.error
        assert result.data["mode"] == "classes"
        assert result.data["pid"] == 2000, "the most recently appended pid wins"
        assert result.data["name_filter"] == "com.app"
    finally:
        service.close_all()


def test_java_methods_uses_an_explicit_pid_and_class(
    service: AnalysisService, tmp_path: Path
) -> None:
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid, pids=[4242])
        result = service.frida_java_methods(sid, class_name="com.app.Main", pid=4242)
        assert result.ok and result.data is not None, result.error
        assert result.data["mode"] == "methods"
        assert result.data["class_name"] == "com.app.Main"
        assert result.data["pid"] == 4242
    finally:
        service.close_all()


def test_java_without_a_spawned_pid_is_refused(service: AnalysisService, tmp_path: Path) -> None:
    """An authorized device with no pid yet cannot pick a Java target."""
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid, pids=[])
        result = service.frida_java_classes(sid)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "invalid_state"
        assert "frida.spawn" in result.error.message
    finally:
        service.close_all()


def test_java_maps_a_frida_error(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom:
        def java_enumerate(self, *_args: Any, **_kwargs: Any) -> JsonObject:
            raise FridaError("not_java", "process has no Java VM")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _Boom())
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid, pids=[4242])
        result = service.frida_java_methods(sid, class_name="X", pid=4242)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "not_java"
    finally:
        service.close_all()


def test_java_maps_an_unexpected_error(
    service: AnalysisService, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Explode:
        def java_enumerate(self, *_args: Any, **_kwargs: Any) -> JsonObject:
            raise RuntimeError("agent injection crashed")

    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: _Explode())
    try:
        sid = _open_session(service, tmp_path)
        _authorize(service, sid, pids=[4242])
        result = service.frida_java_classes(sid)
        assert not result.ok
        assert result.error is not None
    finally:
        service.close_all()
