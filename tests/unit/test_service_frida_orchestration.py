"""The frida device mixin must gate on session state, auth, and error mapping.

``FridaDeviceMixin`` fronts the frida/adb device flow: it refuses an operation
on a closed session, refuses a pid-scoped call before a device is connected,
records the connect/spawn bookkeeping, and turns a ``FridaError`` / ``AdbError``
into a retryable-aware ``XdbgRpcError`` while letting anything else through. No
device or frida-server exists here, so ``FridaClient`` (and the adb backend for
``server.ensure``) are replaced with fakes -- the point is the mixin's gating
and translation, not real instrumentation.

Also pins the ``_append_recent`` recency/dedup/bound helper and ``_last_pid``
(the Java default target), which decide which process a bare Java call hits.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_frida
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_frida import _append_recent, _last_pid

JsonObject = dict[str, Any]


class _FakeFrida:
    """A frida stand-in; per-method results/errors are class-scoped per test."""

    results: dict[str, Any] = {}
    errors: dict[str, BaseException] = {}

    def _answer(self, name: str, default: Any) -> Any:
        err = _FakeFrida.errors.get(name)
        if err is not None:
            raise err
        return _FakeFrida.results.get(name, default)

    def enumerate_devices(self) -> Any:
        return self._answer("enumerate_devices", {"devices": []})

    def add_remote_device(self, endpoint: str) -> Any:
        return self._answer(
            "add_remote_device", {"id": "remote-1", "name": "R", "type": "remote"}
        )

    def _resolve_device(self, device_id: str) -> Any:
        return self._answer(
            "_resolve_device", SimpleNamespace(id="usb-1", name="Pixel", type="usb")
        )

    def applications(self, device_id: Any, limit: int = 256) -> Any:
        return self._answer("applications", {"applications": []})

    def spawn(self, device_id: Any, package: str) -> Any:
        return self._answer("spawn", {"pid": 4242})

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
    ) -> Any:
        return self._answer("java_enumerate", {mode: [], "pid": pid})


class _FakeAdb:
    def __init__(self) -> None:
        self.error: BaseException | None = None

    def ensure_frida_server(
        self, serial: str, *, server_binary: Any = None, port: int = 27042, bind_host: str = ""
    ) -> JsonObject:
        if self.error is not None:
            raise self.error
        return {"serial": serial, "port": port, "running": True}


@pytest.fixture(autouse=True)
def _reset_fake(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeFrida.results = {}
    _FakeFrida.errors = {}
    monkeypatch.setattr(service_frida, "FridaClient", _FakeFrida)


@pytest.fixture
def service(tmp_path: Path) -> Any:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    svc = AnalysisService(settings)
    try:
        yield svc
    finally:
        svc.close_all()


def _session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok, created.error
    assert created.data is not None
    return str(created.data["session"]["id"])


def _connect(service: AnalysisService, session_id: str) -> None:
    result = service.frida_device_connect(session_id)
    assert result.ok, result.error


# --------------------------------------------------------------------------
# frida_devices
# --------------------------------------------------------------------------


def test_frida_devices_returns_the_enumerated_list(service: AnalysisService) -> None:
    _FakeFrida.results["enumerate_devices"] = {"devices": [{"id": "usb-1"}]}
    result = service.frida_devices()
    assert result.ok, result.error
    assert result.data == {"devices": [{"id": "usb-1"}]}


def test_frida_devices_maps_a_frida_error(service: AnalysisService) -> None:
    _FakeFrida.errors["enumerate_devices"] = FridaError("timeout", "frida did not respond")
    result = service.frida_devices()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True


def test_frida_devices_surfaces_an_unexpected_exception(service: AnalysisService) -> None:
    _FakeFrida.errors["enumerate_devices"] = RuntimeError("frida-core exploded")
    result = service.frida_devices()
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# frida_device_connect
# --------------------------------------------------------------------------


def test_device_connect_resolves_a_usb_device(service: AnalysisService) -> None:
    session_id = _session(service)
    result = service.frida_device_connect(session_id, device_id="usb")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["connected"] is True
    assert result.data["device"]["id"] == "usb-1"


def test_device_connect_adds_a_remote_endpoint(service: AnalysisService) -> None:
    session_id = _session(service)
    _FakeFrida.results["add_remote_device"] = {
        "id": "10.0.0.5:27042",
        "name": "N",
        "type": "remote",
    }
    result = service.frida_device_connect(session_id, endpoint="10.0.0.5:27042")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["device"]["id"] == "10.0.0.5:27042"


def test_device_connect_refuses_a_closed_session(service: AnalysisService) -> None:
    session_id = _session(service)
    assert service.close_session(session_id).ok
    result = service.frida_device_connect(session_id)
    assert result.ok is False
    assert result.error is not None


def test_device_connect_maps_a_frida_error(service: AnalysisService) -> None:
    session_id = _session(service)
    _FakeFrida.errors["_resolve_device"] = FridaError("not_found", "no usb device")
    result = service.frida_device_connect(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "not_found"


# --------------------------------------------------------------------------
# frida_server_ensure
# --------------------------------------------------------------------------


def test_server_ensure_reports_the_backend_payload(service: AnalysisService) -> None:
    session_id = _session(service)
    service._adb_backend = _FakeAdb()  # type: ignore[assignment]
    result = service.frida_server_ensure(session_id, "emulator-5554", port=27050)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["port"] == 27050


def test_server_ensure_maps_an_adb_error(service: AnalysisService) -> None:
    session_id = _session(service)
    adb = _FakeAdb()
    adb.error = AdbError("timeout", "adb push timed out")
    service._adb_backend = adb  # type: ignore[assignment]
    result = service.frida_server_ensure(session_id, "emulator-5554")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "timeout"
    assert result.error.retryable is True


def test_server_ensure_surfaces_an_unexpected_exception(service: AnalysisService) -> None:
    session_id = _session(service)
    adb = _FakeAdb()
    adb.error = RuntimeError("adb binary missing")
    service._adb_backend = adb  # type: ignore[assignment]
    result = service.frida_server_ensure(session_id, "emulator-5554")
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# auth-gated operations: applications / spawn / java
# --------------------------------------------------------------------------


def test_pid_scoped_call_needs_a_connected_device(service: AnalysisService) -> None:
    session_id = _session(service)
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_applications_lists_once_connected(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    _FakeFrida.results["applications"] = {"applications": [{"name": "app"}]}
    result = service.frida_applications(session_id)
    assert result.ok, result.error
    assert result.data == {"applications": [{"name": "app"}]}


def test_applications_maps_a_frida_error(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    _FakeFrida.errors["applications"] = FridaError("backend_error", "enumeration failed")
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_applications_surfaces_an_unexpected_exception(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    _FakeFrida.errors["applications"] = RuntimeError("frida-core exploded")
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None


def test_spawn_records_the_pid_and_package(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    _FakeFrida.results["spawn"] = {"pid": 9001}
    result = service.frida_spawn(session_id, "com.example.app")
    assert result.ok, result.error
    assert result.data == {"pid": 9001}
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["pids"] == [9001]
    assert auth["packages"] == ["com.example.app"]


def test_spawn_maps_a_frida_error(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    _FakeFrida.errors["spawn"] = FridaError("invalid_params", "unknown package")
    result = service.frida_spawn(session_id, "com.nope")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_spawn_surfaces_an_unexpected_exception(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    _FakeFrida.errors["spawn"] = RuntimeError("frida-core exploded")
    result = service.frida_spawn(session_id, "com.example.app")
    assert result.ok is False
    assert result.error is not None


def test_java_classes_default_to_the_last_spawned_pid(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    service.frida_spawn(session_id, "com.example.app")
    _FakeFrida.results["java_enumerate"] = {"classes": ["a.B"], "pid": 4242}
    result = service.frida_java_classes(session_id, name_filter="a")
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["classes"] == ["a.B"]


def test_java_methods_accept_an_explicit_pid(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    _FakeFrida.results["java_enumerate"] = {"methods": ["m()"], "pid": 555}
    result = service.frida_java_methods(session_id, "a.B", pid=555)
    assert result.ok, result.error
    assert result.data is not None
    assert result.data["methods"] == ["m()"]


def test_java_without_a_spawned_pid_reports_invalid_state(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    result = service.frida_java_classes(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


def test_java_maps_a_frida_error(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    service.frida_spawn(session_id, "com.example.app")
    _FakeFrida.errors["java_enumerate"] = FridaError("backend_error", "ScriptRuntimeError")
    result = service.frida_java_classes(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_java_surfaces_an_unexpected_exception(service: AnalysisService) -> None:
    session_id = _session(service)
    _connect(service, session_id)
    service.frida_spawn(session_id, "com.example.app")
    _FakeFrida.errors["java_enumerate"] = RuntimeError("ScriptRuntimeError")
    result = service.frida_java_classes(session_id)
    assert result.ok is False
    assert result.error is not None


# --------------------------------------------------------------------------
# _append_recent / _last_pid
# --------------------------------------------------------------------------


def test_append_recent_dedupes_and_keeps_recency() -> None:
    assert _append_recent([1, 2, 3], 2) == [1, 3, 2]
    assert _append_recent(None, 7) == [7]


def test_append_recent_bounds_the_history() -> None:
    result = _append_recent(list(range(10)), 10, limit=3)
    assert result == [8, 9, 10]


def test_last_pid_returns_the_most_recent() -> None:
    assert _last_pid({"pids": [11, 22, 33]}) == 33


def test_last_pid_refuses_when_no_pid_is_recorded() -> None:
    with pytest.raises(FridaError) as exc:
        _last_pid({"pids": []})
    assert exc.value.code == "invalid_state"
