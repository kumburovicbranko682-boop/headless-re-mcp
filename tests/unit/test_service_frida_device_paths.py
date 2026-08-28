"""Device-aware Frida service paths (FridaDeviceMixin).

test_frida_fields pins one connect-shape case; this covers the rest of the mixin:
the device enumeration errors, the remote-endpoint connect branch, frida-server
ensure, the per-session authorization gate (_frida_auth), applications/spawn, and
the Java enumeration that defaults to the most-recently-spawned pid (_last_pid).
FridaClient is constructed inline by the mixin, so it is monkeypatched at the
module boundary; frida.server.ensure uses the AnalysisService-owned AdbBackend,
so a fake subclass replaces it.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbBackend, AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_frida
from headless_re_mcp.core.service import AnalysisService


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


class _Dev:
    def __init__(self, ident: str = "ABCD", name: str = "Pixel", kind: str = "usb") -> None:
        self.id = ident
        self.name = name
        self.type = kind


class _FakeFrida:
    def __init__(self) -> None:
        self.raise_on: dict[str, BaseException] = {}
        self.spawn_pid = 4242

    def _maybe(self, op: str) -> None:
        exc = self.raise_on.get(op)
        if exc is not None:
            raise exc

    def enumerate_devices(self) -> dict[str, Any]:
        self._maybe("enumerate_devices")
        return {"devices": [{"id": "usb", "name": "Pixel", "type": "usb"}], "count": 1}

    def add_remote_device(self, endpoint: str) -> dict[str, Any]:
        self._maybe("add_remote_device")
        return {"id": endpoint, "name": "remote", "type": "remote"}

    def _resolve_device(self, device_id: str) -> _Dev:
        self._maybe("_resolve_device")
        return _Dev()

    def applications(self, device_id: Any, *, limit: int = 256) -> dict[str, Any]:
        self._maybe("applications")
        return {"applications": [], "count": 0, "total": 0, "has_more": False}

    def spawn(self, device_id: Any, package: str) -> dict[str, Any]:
        self._maybe("spawn")
        return {"pid": self.spawn_pid, "package": package, "device": device_id}

    def java_enumerate(
        self,
        device_id: Any,
        pid: int,
        *,
        allowed_pids: Any,
        mode: str,
        class_name: str | None = None,
        name_filter: str | None = None,
        limit: int = 200,
    ) -> dict[str, Any]:
        self._maybe("java_enumerate")
        return {
            "pid": pid,
            "classes": [],
            "methods": [],
            "count": 0,
            "has_more": False,
            "found": True,
        }


class _FakeAdb(AdbBackend):
    def __init__(self) -> None:
        super().__init__()
        self.exc: BaseException | None = None

    def ensure_frida_server(
        self,
        serial: str,
        *,
        server_binary: str | None = None,
        remote_path: str = "/data/local/tmp/frida-server",
        port: int = 27042,
        bind_host: str = "127.0.0.1",
    ) -> dict[str, Any]:
        if self.exc is not None:
            raise self.exc
        return {"running": True, "pushed": False, "port": port}


def _use_frida(monkeypatch: pytest.MonkeyPatch, fake: _FakeFrida) -> None:
    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: fake)


def _connect(service: AnalysisService, sid: str) -> None:
    result = service.frida_device_connect(sid, device_id="usb")
    assert result.ok, result.error


# ---------------------------------------------------------------------------
# frida.devices
# ---------------------------------------------------------------------------
def test_frida_devices_success_and_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeFrida()
    _use_frida(monkeypatch, fake)
    try:
        assert service.frida_devices().ok

        fake.raise_on["enumerate_devices"] = FridaError("capability_unavailable", "no frida")
        mapped = service.frida_devices()
        assert mapped.ok is False
        assert mapped.error is not None and mapped.error.code == "capability_unavailable"

        fake.raise_on["enumerate_devices"] = RuntimeError("frida core panicked")
        unexpected = service.frida_devices()
        assert unexpected.ok is False
        assert unexpected.error is not None and unexpected.error.code == "internal_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# frida.device.connect (remote endpoint branch + error)
# ---------------------------------------------------------------------------
def test_frida_device_connect_remote_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_frida(monkeypatch, _FakeFrida())
    try:
        sid = _web_session(service)
        result = service.frida_device_connect(sid, endpoint="10.0.0.1:27042")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["device"]["id"] == "10.0.0.1:27042"
        auth = service.registry.get(sid).metadata["frida_authorized"]
        assert auth["device_id"] == "10.0.0.1:27042"
    finally:
        service.close_all()


def test_frida_device_connect_maps_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeFrida()
    fake.raise_on["_resolve_device"] = FridaError("not_found", "no usb device")
    _use_frida(monkeypatch, fake)
    try:
        sid = _web_session(service)
        result = service.frida_device_connect(sid, device_id="usb")
        assert result.ok is False
        assert result.error is not None and result.error.code == "not_found"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# frida.server.ensure
# ---------------------------------------------------------------------------
def test_frida_server_ensure_success_and_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_frida(monkeypatch, _FakeFrida())
    adb = _FakeAdb()
    service._adb_backend = adb
    try:
        sid = _web_session(service)
        ok = service.frida_server_ensure(sid, "emulator-5554")
        assert ok.ok, ok.error
        assert ok.data is not None and ok.data["running"] is True

        adb.exc = AdbError("not_found", "device offline")
        failed = service.frida_server_ensure(sid, "emulator-5554")
        assert failed.ok is False
        assert failed.error is not None and failed.error.code == "not_found"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# _frida_auth gate + frida.applications
# ---------------------------------------------------------------------------
def test_frida_applications_requires_a_connected_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_frida(monkeypatch, _FakeFrida())
    try:
        sid = _web_session(service)  # no device connected yet
        ungated = service.frida_applications(sid)
        assert ungated.ok is False
        assert ungated.error is not None and ungated.error.code == "invalid_state"

        _connect(service, sid)
        assert service.frida_applications(sid, limit=10).ok
    finally:
        service.close_all()


def test_frida_applications_maps_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeFrida()
    _use_frida(monkeypatch, fake)
    try:
        sid = _web_session(service)
        _connect(service, sid)
        fake.raise_on["applications"] = FridaError("backend_error", "device dropped")
        result = service.frida_applications(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "backend_error"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# frida.spawn error mapping
# ---------------------------------------------------------------------------
def test_frida_spawn_maps_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    fake = _FakeFrida()
    _use_frida(monkeypatch, fake)
    try:
        sid = _web_session(service)
        _connect(service, sid)
        fake.raise_on["spawn"] = FridaError("invalid_params", "not a package id")
        result = service.frida_spawn(sid, "com.example.app")
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_params"
    finally:
        service.close_all()


# ---------------------------------------------------------------------------
# frida.java.* defaults to the most-recently-spawned pid (_last_pid)
# ---------------------------------------------------------------------------
def test_frida_java_uses_the_last_spawned_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeFrida()
    _use_frida(monkeypatch, fake)
    try:
        sid = _web_session(service)
        _connect(service, sid)
        spawned = service.frida_spawn(sid, "com.example.app")
        assert spawned.ok, spawned.error

        classes = service.frida_java_classes(sid, name_filter="", limit=10)
        assert classes.ok, classes.error
        assert classes.data is not None and classes.data["pid"] == fake.spawn_pid

        methods = service.frida_java_methods(sid, "com.example.Main", limit=10)
        assert methods.ok, methods.error
    finally:
        service.close_all()


def test_frida_java_without_a_spawned_pid_reports_invalid_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    _use_frida(monkeypatch, _FakeFrida())
    try:
        sid = _web_session(service)
        _connect(service, sid)  # auth has an empty pids list, nothing spawned
        result = service.frida_java_classes(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "invalid_state"
    finally:
        service.close_all()


def test_frida_java_maps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    fake = _FakeFrida()
    _use_frida(monkeypatch, fake)
    try:
        sid = _web_session(service)
        _connect(service, sid)
        assert service.frida_spawn(sid, "com.example.app").ok
        fake.raise_on["java_enumerate"] = FridaError("timeout", "Java.perform stalled")
        result = service.frida_java_classes(sid)
        assert result.ok is False
        assert result.error is not None and result.error.code == "timeout"
    finally:
        service.close_all()
