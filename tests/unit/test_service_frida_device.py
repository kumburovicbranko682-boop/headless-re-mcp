"""Device-facing Frida service methods: happy paths, auth, and error mapping.

The session-lifecycle guards live in ``test_frida_*_closed_session``; these
tests drive the enumerate/connect/applications/spawn/java surface with a fake
``FridaClient`` so every success branch, the per-session authorization record,
and the FridaError/AdbError -> failure mapping run without a device.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

CLIENT = "headless_re_mcp.core.service_frida.FridaClient"


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
        self.name = "pixel"
        self.type = "usb"


class _FakeFrida:
    """A cooperative FridaClient double covering the device surface."""

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def enumerate_devices(self) -> dict[str, Any]:
        return {"devices": [{"id": "usb", "name": "pixel"}], "count": 1}

    def _resolve_device(self, device_id: str) -> _Device:
        return _Device(device_id)

    def add_remote_device(self, endpoint: str) -> dict[str, Any]:
        return {"id": endpoint, "name": "remote", "type": "remote"}

    def applications(self, device_id: Any, limit: int = 256) -> dict[str, Any]:
        return {
            "applications": [{"identifier": "com.example"}],
            "device": device_id,
            "limit": limit,
        }

    def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
        return {"pid": 4242, "package": package, "device": device_id}

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
    ) -> dict[str, Any]:
        return {
            "mode": mode,
            "pid": target_pid,
            "allowed_pids": list(allowed_pids),
            "class_name": class_name,
            "name_filter": name_filter,
            "items": ["a", "b"][:limit],
        }


@pytest.fixture
def service(tmp_path: Path) -> Any:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = svc.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    svc._session_id = created.data["session"]["id"]  # type: ignore[attr-defined]
    try:
        yield svc
    finally:
        svc.close_all()


def _sid(service: Any) -> str:
    return str(service._session_id)


def _connect(service: Any, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(CLIENT, lambda *a, **k: _FakeFrida())
    session_id = _sid(service)
    result = service.frida_device_connect(session_id, device_id="usb")
    assert result.ok, result.error
    return session_id


# --- enumerate ------------------------------------------------------------


def test_frida_devices_returns_enumeration(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(CLIENT, lambda *a, **k: _FakeFrida())
    result = service.frida_devices()
    assert result.ok
    assert result.data is not None
    assert result.data["count"] == 1


def test_frida_devices_maps_frida_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeFrida):
        def enumerate_devices(self) -> dict[str, Any]:
            raise FridaError("frida_unavailable", "no frida")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_devices()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "frida_unavailable"


def test_frida_devices_maps_unexpected_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeFrida):
        def enumerate_devices(self) -> dict[str, Any]:
            raise RuntimeError("kaboom")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_devices()
    assert result.ok is False
    assert result.error is not None


# --- connect --------------------------------------------------------------


def test_connect_local_device_records_authorization(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _connect(service, monkeypatch)
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["device_id"] == "usb"
    assert auth["pids"] == []


def test_connect_remote_endpoint_uses_add_remote_device(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(CLIENT, lambda *a, **k: _FakeFrida())
    session_id = _sid(service)
    result = service.frida_device_connect(session_id, endpoint=" 10.0.0.5:27042 ")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["device"]["id"] == "10.0.0.5:27042"
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["device_id"] == "10.0.0.5:27042"


def test_connect_maps_frida_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeFrida):
        def _resolve_device(self, device_id: str) -> _Device:
            raise FridaError("device_not_found", "no such device")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_device_connect(_sid(service), device_id="usb")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "device_not_found"


# --- server ensure --------------------------------------------------------


def test_server_ensure_returns_backend_report(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Adb:
        def ensure_frida_server(
            self,
            serial: str,
            server_binary: str | None = None,
            port: int = 27042,
            bind_host: str = "127.0.0.1",
        ) -> dict[str, Any]:
            return {"ensured": True, "port": port, "serial": serial}

    service._adb_backend = _Adb()
    result = service.frida_server_ensure(_sid(service), serial="emulator-5554", port=27055)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["port"] == 27055


def test_server_ensure_maps_adb_error(service: Any) -> None:
    class _Adb:
        def ensure_frida_server(self, *a: Any, **k: Any) -> dict[str, Any]:
            raise AdbError("adb_unavailable", "adb missing")

    service._adb_backend = _Adb()
    result = service.frida_server_ensure(_sid(service), serial="emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "adb_unavailable"


# --- applications / spawn -------------------------------------------------


def test_applications_requires_a_connected_device(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(CLIENT, lambda *a, **k: _FakeFrida())
    result = service.frida_applications(_sid(service))
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_applications_lists_after_connect(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)
    result = service.frida_applications(session_id, limit=1)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["limit"] == 1


def test_applications_maps_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)

    class _Boom(_FakeFrida):
        def applications(self, device_id: Any, limit: int = 256) -> dict[str, Any]:
            raise FridaError("frida_rpc_error", "enumeration failed")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "frida_rpc_error"


def test_spawn_records_pid_and_package(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)
    result = service.frida_spawn(session_id, "com.example")
    assert result.ok, result.error
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["pids"] == [4242]
    assert auth["packages"] == ["com.example"]


def test_spawn_maps_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)

    class _Boom(_FakeFrida):
        def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
            raise FridaError("spawn_failed", "could not spawn")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_spawn(session_id, "com.example")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "spawn_failed"


# --- java enumeration -----------------------------------------------------


def test_java_classes_uses_last_spawned_pid(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)
    assert service.frida_spawn(session_id, "com.example").ok
    result = service.frida_java_classes(session_id, name_filter="Foo", limit=1)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["mode"] == "classes"
    assert result.data["pid"] == 4242
    assert result.data["name_filter"] == "Foo"


def test_java_methods_accepts_explicit_pid(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)
    result = service.frida_java_methods(session_id, class_name="com.x.Y", pid=1234)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["mode"] == "methods"
    assert result.data["pid"] == 1234
    assert result.data["class_name"] == "com.x.Y"


def test_java_without_any_pid_reports_invalid_state(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _connect(service, monkeypatch)
    result = service.frida_java_classes(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_java_maps_unexpected_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)
    assert service.frida_spawn(session_id, "com.example").ok

    class _Boom(_FakeFrida):
        def java_enumerate(self, *a: Any, **k: Any) -> dict[str, Any]:
            raise RuntimeError("bridge crashed")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_java_methods(session_id, class_name="com.x.Y")
    assert result.ok is False
    assert result.error is not None


# --- unexpected-error handlers and closed-session guard -------------------


def test_connect_maps_unexpected_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeFrida):
        def _resolve_device(self, device_id: str) -> _Device:
            raise RuntimeError("usb stack died")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_device_connect(_sid(service), device_id="usb")
    assert result.ok is False
    assert result.error is not None


def test_server_ensure_maps_unexpected_error(service: Any) -> None:
    class _Adb:
        def ensure_frida_server(self, *a: Any, **k: Any) -> dict[str, Any]:
            raise RuntimeError("push crashed")

    service._adb_backend = _Adb()
    result = service.frida_server_ensure(_sid(service), serial="emulator-5554")
    assert result.ok is False
    assert result.error is not None


def test_applications_maps_unexpected_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)

    class _Boom(_FakeFrida):
        def applications(self, device_id: Any, limit: int = 256) -> dict[str, Any]:
            raise RuntimeError("enumeration crashed")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None


def test_spawn_maps_unexpected_error(service: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = _connect(service, monkeypatch)

    class _Boom(_FakeFrida):
        def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
            raise RuntimeError("spawn crashed")

    monkeypatch.setattr(CLIENT, lambda *a, **k: _Boom())
    result = service.frida_spawn(session_id, "com.example")
    assert result.ok is False
    assert result.error is not None


def test_device_method_on_closed_session_is_refused(
    service: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _connect(service, monkeypatch)
    assert service.close_session(session_id).ok
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_request"
