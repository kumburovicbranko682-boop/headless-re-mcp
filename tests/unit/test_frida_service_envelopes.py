"""service_frida's read/enumerate wrappers and the java path, at the service layer.

The audit tests drive frida.spawn / frida.server.ensure / applications, the
closed-session tests drive the entry and leak guards, and the local
device.connect path is covered elsewhere -- but a band was still untouched
because the shared fake only had spawn/applications: frida.devices (session-less
enumeration), frida.device.connect's *remote endpoint* branch and its
FridaError mapping, the whole java path (frida.java.classes / methods -> _java ->
_last_pid), frida.applications' error mapping, and _frida_auth's "connect a
device first" refusal. A fake FridaClient with the remaining methods stands in
so the service wiring is what is pinned, without a real device or the frida
module.
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

JsonObject = dict[str, Any]


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


class _FakeFrida:
    """A FridaClient stand-in covering the device-scoped calls the service makes.

    ``raises`` maps a method name to the exception it should raise, so one fake
    drives both the success and the error path for a given entry point.
    """

    def __init__(self, *, raises: dict[str, BaseException] | None = None) -> None:
        self._raises = raises or {}

    def _maybe_fail(self, op: str) -> None:
        exc = self._raises.get(op)
        if exc is not None:
            raise exc

    def enumerate_devices(self) -> JsonObject:
        self._maybe_fail("enumerate_devices")
        return {"devices": [{"id": "usb", "type": "usb"}], "count": 1}

    def add_remote_device(self, endpoint: str) -> JsonObject:
        self._maybe_fail("add_remote_device")
        return {"id": endpoint, "name": "remote", "type": "remote"}

    def _resolve_device(self, device_id: str) -> Any:
        self._maybe_fail("_resolve_device")

        class _Device:
            id = device_id
            name = "usb"
            type = "usb"

        return _Device()

    def spawn(self, device_id: Any, package: str) -> JsonObject:
        self._maybe_fail("spawn")
        return {"package": package, "pid": 4242}

    def applications(
        self, device_id: Any, offset: int = 0, limit: int = 256
    ) -> JsonObject:
        self._maybe_fail("applications")
        return {"applications": [], "count": 0}

    def java_enumerate(
        self,
        device_id: Any,
        target_pid: int,
        *,
        allowed_pids: Any,
        mode: str,
        class_name: str | None = None,
        name_filter: str | None = None,
        limit: int = 200,
    ) -> JsonObject:
        self._maybe_fail("java_enumerate")
        return {"mode": mode, "items": [], "target_pid": target_pid}


def _session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    raises: dict[str, BaseException] | None = None,
) -> tuple[AnalysisService, str]:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient",
        lambda *a, **k: _FakeFrida(raises=raises),
    )
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return service, created.data["session"]["id"]


def _authorize(service: AnalysisService, session_id: str, *, pids: list[int]) -> None:
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": pids, "packages": ["com.example.app"]}},
    )


def _timeline(service: AnalysisService, session_id: str, name: str) -> list[JsonObject]:
    page = service.repository.list_timeline(session_id)
    return [item for item in page["events"] if item.get("event") == name]


def test_frida_devices_wraps_the_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _session(tmp_path, monkeypatch)
    try:
        result = service.frida_devices()
        assert result.ok is True, result.error
        assert result.data is not None and result.data["count"] == 1
        assert result.meta.get("backend") == "frida"
    finally:
        service.close_all()


def test_frida_devices_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _session(
        tmp_path,
        monkeypatch,
        raises={"enumerate_devices": FridaError("capability_unavailable", "no frida")},
    )
    try:
        result = service.frida_devices()
        assert result.ok is False
        assert result.error is not None and result.error.code == "capability_unavailable"
    finally:
        service.close_all()


def test_frida_devices_fails_closed_on_an_unexpected_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _ = _session(
        tmp_path, monkeypatch, raises={"enumerate_devices": RuntimeError("frida crashed")}
    )
    try:
        result = service.frida_devices()
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_frida_device_connect_via_a_remote_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The endpoint branch adds a remote device and authorizes it -- distinct
    from the local _resolve_device path the closed-session test drives."""
    service, session_id = _session(tmp_path, monkeypatch)
    try:
        result = service.frida_device_connect(session_id, endpoint="10.0.0.5:27042")
        assert result.ok is True, result.error
        assert result.data is not None
        assert result.data["device"]["id"] == "10.0.0.5:27042"
        auth = service.registry.get(session_id).metadata["frida_authorized"]
        assert auth["device_id"] == "10.0.0.5:27042"
        assert len(_timeline(service, session_id, "frida.device.connect")) == 1
    finally:
        service.close_all()


def test_frida_device_connect_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(
        tmp_path, monkeypatch, raises={"_resolve_device": FridaError("not_found", "no such device")}
    )
    try:
        result = service.frida_device_connect(session_id, device_id="usb")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
        # A failed connect must not leave an authorization behind.
        assert "frida_authorized" not in service.registry.get(session_id).metadata
    finally:
        service.close_all()


def test_frida_calls_refuse_without_a_connected_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """_frida_auth fails closed with invalid_state until a device is connected."""
    service, session_id = _session(tmp_path, monkeypatch)
    try:
        result = service.frida_applications(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_state"
    finally:
        service.close_all()


def test_frida_applications_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(
        tmp_path, monkeypatch, raises={"applications": FridaError("backend_error", "boom")}
    )
    try:
        _authorize(service, session_id, pids=[])
        result = service.frida_applications(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_frida_java_classes_and_methods_wrap_the_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(tmp_path, monkeypatch)
    try:
        _authorize(service, session_id, pids=[4242])
        classes = service.frida_java_classes(session_id, name_filter="com.example")
        assert classes.ok is True, classes.error
        assert classes.data is not None and classes.data["mode"] == "classes"
        assert classes.data["target_pid"] == 4242  # defaulted to the last spawned pid

        methods = service.frida_java_methods(session_id, class_name="Lcom/example/Foo;")
        assert methods.ok is True, methods.error
        assert methods.data is not None and methods.data["mode"] == "methods"
    finally:
        service.close_all()


def test_frida_java_requires_a_spawned_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a device connected but nothing spawned, the java tools have no target
    pid to default to and must refuse rather than guess one."""
    service, session_id = _session(tmp_path, monkeypatch)
    try:
        _authorize(service, session_id, pids=[])
        result = service.frida_java_classes(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_state"
    finally:
        service.close_all()


def test_frida_java_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(
        tmp_path, monkeypatch, raises={"java_enumerate": FridaError("backend_error", "enum failed")}
    )
    try:
        _authorize(service, session_id, pids=[4242])
        result = service.frida_java_classes(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


def test_frida_java_fails_closed_on_an_unexpected_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(
        tmp_path, monkeypatch, raises={"java_enumerate": RuntimeError("frida bridge crashed")}
    )
    try:
        _authorize(service, session_id, pids=[4242])
        result = service.frida_java_classes(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


def test_frida_applications_fails_closed_on_an_unexpected_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(
        tmp_path, monkeypatch, raises={"applications": RuntimeError("frida bridge crashed")}
    )
    try:
        _authorize(service, session_id, pids=[])
        result = service.frida_applications(session_id)
        assert result.ok is False
        assert result.error is not None and result.error.code == "internal_error"
    finally:
        service.close_all()


class _AdbBoom:
    """An adb backend whose ensure_frida_server raises, to drive the AdbError arm."""

    def ensure_frida_server(
        self,
        serial: str,
        server_binary: str | None = None,
        port: int = 27042,
        bind_host: str = "127.0.0.1",
    ) -> JsonObject:
        raise AdbError("backend_error", "adb push failed")


def test_frida_server_ensure_maps_an_adb_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, session_id = _session(tmp_path, monkeypatch)
    try:
        service._adb_backend = _AdbBoom()  # type: ignore[attr-defined]
        result = service.frida_server_ensure(session_id, "emulator-5554")
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
        # A failed ensure is still audited, with its error code.
        entries = service.audit_list(session_id)
        assert entries.ok and entries.data is not None
        rows = [e for e in entries.data["entries"] if e["action"] == "frida.server.ensure"]
        assert rows and rows[0]["ok"] == 0
        assert rows[0]["result_summary"] == {"code": "backend_error"}
    finally:
        service.close_all()
