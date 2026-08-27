"""Authorization, delegation and error-mapping paths of the frida device mixin.

The frida client has its own suite; this file covers the service layer that
attaches device operations to a session -- the per-session authorization gate,
the remote-endpoint connect branch, the Java delegators and last-pid default,
and the ``FridaError`` / ``AdbError`` -> envelope mapping. ``FridaClient`` and
the adb backend are faked, so neither frida nor a device is touched.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_frida as service_frida
from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_AUTH_KEY = "frida_authorized"


@pytest.fixture
def service(tmp_path: Path) -> Iterator[AnalysisService]:
    svc = AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))
    try:
        yield svc
    finally:
        svc.close_all()


def _web_session(svc: AnalysisService) -> str:
    created = svc.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    return str(created.data["session"]["id"])


def _authorize(svc: AnalysisService, session_id: str, pids: list[int]) -> None:
    svc.registry.update_metadata(
        session_id, {_AUTH_KEY: {"device_id": "emulator-5554", "pids": pids, "packages": []}}
    )


def _returns(value: dict[str, Any]) -> Any:
    def _fn(_self: Any, *_a: Any, **_k: Any) -> dict[str, Any]:
        return value

    return _fn


def _raises(exc: BaseException) -> Any:
    def _fn(_self: Any, *_a: Any, **_k: Any) -> Any:
        raise exc

    return _fn


def _install_frida(monkeypatch: pytest.MonkeyPatch, **methods: Any) -> None:
    fake = type("_FakeFridaClient", (), {"__init__": lambda self, *a, **k: None, **methods})
    monkeypatch.setattr(service_frida, "FridaClient", fake)


# ---------------------------------------------------------------------------
# frida.devices (no session)


def test_frida_devices_returns_the_enumeration(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_frida(monkeypatch, enumerate_devices=_returns({"devices": []}))

    result = service.frida_devices()

    assert result.ok, result.error
    assert result.meta.get("backend") == "frida"


def test_frida_devices_maps_a_frida_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_frida(monkeypatch, enumerate_devices=_raises(FridaError("backend_error", "no frida")))

    result = service.frida_devices()

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_frida_devices_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_frida(monkeypatch, enumerate_devices=_raises(ValueError("boom")))

    result = service.frida_devices()

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# frida.device.connect


def test_device_connect_uses_the_remote_endpoint_when_given(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _install_frida(monkeypatch, add_remote_device=_returns({"id": "10.0.0.5:27042"}))

    result = service.frida_device_connect(session_id, endpoint="10.0.0.5:27042")

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["connected"] is True
    stored = service.registry.get(session_id).metadata[_AUTH_KEY]
    assert stored["device_id"] == "10.0.0.5:27042"


def test_device_connect_resolves_a_local_device(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    device = SimpleNamespace(id="emulator-5554", name="Android Emulator", type="usb")
    _install_frida(monkeypatch, _resolve_device=lambda self, dev_id: device)

    result = service.frida_device_connect(session_id, device_id="usb")

    assert result.ok, result.error
    assert result.data is not None
    assert result.data["device"]["id"] == "emulator-5554"


def test_device_connect_maps_a_frida_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _install_frida(
        monkeypatch, _resolve_device=_raises(FridaError("not_found", "no usb device"))
    )

    result = service.frida_device_connect(session_id, device_id="usb")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "not_found"


# ---------------------------------------------------------------------------
# frida.server.ensure


def test_server_ensure_maps_an_adb_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)

    class _Adb:
        def ensure_frida_server(self, *_a: Any, **_k: Any) -> dict[str, Any]:
            raise AdbError("device_offline", "device not connected")

    monkeypatch.setattr(service, "_adb_backend", _Adb(), raising=False)

    result = service.frida_server_ensure(session_id, "emulator-5554")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "device_offline"


def test_server_ensure_reports_the_backend_payload(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    seen: dict[str, Any] = {}

    class _Adb:
        def ensure_frida_server(
            self,
            serial: str,
            server_binary: str | None = None,
            port: int = 27042,
            bind_host: str = "",
        ) -> dict[str, Any]:
            seen.update(serial=serial, port=port)
            return {"running": True}

    monkeypatch.setattr(service, "_adb_backend", _Adb(), raising=False)

    result = service.frida_server_ensure(session_id, "emulator-5554", port=27043)

    assert result.ok, result.error
    assert seen == {"serial": "emulator-5554", "port": 27043}


# ---------------------------------------------------------------------------
# frida.applications and the authorization gate


def test_applications_requires_a_connected_device(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _install_frida(monkeypatch, applications=_returns({"applications": []}))

    result = service.frida_applications(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_applications_returns_the_list_once_authorized(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[])
    _install_frida(monkeypatch, applications=_returns({"applications": [{"pid": 1}]}))

    result = service.frida_applications(session_id)

    assert result.ok, result.error
    assert result.data == {"applications": [{"pid": 1}]}


def test_applications_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[])
    _install_frida(monkeypatch, applications=_raises(ValueError("boom")))

    result = service.frida_applications(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"


# ---------------------------------------------------------------------------
# frida.spawn


def test_spawn_maps_a_frida_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[])
    _install_frida(monkeypatch, spawn=_raises(FridaError("backend_error", "spawn failed")))

    result = service.frida_spawn(session_id, "com.example.app")

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "backend_error"


# ---------------------------------------------------------------------------
# frida.java.* delegators and last-pid default


def test_java_classes_defaults_to_the_last_spawned_pid(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[111, 222])
    seen: dict[str, Any] = {}

    def fake_java(self: Any, device_id: Any, target_pid: int, **kwargs: Any) -> dict[str, Any]:
        seen.update(target_pid=target_pid, mode=kwargs.get("mode"))
        return {"classes": []}

    _install_frida(monkeypatch, java_enumerate=fake_java)

    result = service.frida_java_classes(session_id)

    assert result.ok, result.error
    assert seen == {"target_pid": 222, "mode": "classes"}


def test_java_methods_uses_an_explicit_pid(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[111])
    seen: dict[str, Any] = {}

    def fake_java(self: Any, device_id: Any, target_pid: int, **kwargs: Any) -> dict[str, Any]:
        seen.update(target_pid=target_pid, mode=kwargs.get("mode"))
        return {"methods": []}

    _install_frida(monkeypatch, java_enumerate=fake_java)

    result = service.frida_java_methods(session_id, "com.example.Foo", pid=555)

    assert result.ok, result.error
    assert seen == {"target_pid": 555, "mode": "methods"}


def test_java_without_a_spawned_pid_is_refused(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[])
    _install_frida(monkeypatch, java_enumerate=_returns({"classes": []}))

    result = service.frida_java_classes(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_java_maps_a_frida_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[111])
    _install_frida(
        monkeypatch, java_enumerate=_raises(FridaError("permission_denied", "pid not authorized"))
    )

    result = service.frida_java_classes(session_id)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "permission_denied"


def test_java_maps_an_unexpected_error(
    service: AnalysisService, monkeypatch: pytest.MonkeyPatch
) -> None:
    session_id = _web_session(service)
    _authorize(service, session_id, pids=[111])
    _install_frida(monkeypatch, java_enumerate=_raises(ValueError("boom")))

    result = service.frida_java_methods(session_id, "com.example.Foo", pid=5)

    assert not result.ok
    assert result.error is not None
    assert result.error.code == "invalid_request"
