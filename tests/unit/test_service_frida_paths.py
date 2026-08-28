"""Edge-path coverage for core/service_frida.py.

Targets the success returns and typed error arms of every frida.* method plus
the module-level authorization helpers, using a fake FridaClient/AdbBackend so
no real device or frida install is needed.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core import service_frida
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_frida import _append_recent, _last_pid


def _write_minimal_pe(path: Path) -> None:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = (0x8664).to_bytes(2, "little")
    path.write_bytes(image)


def _service(tmp_path: Path) -> AnalysisService:
    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    return AnalysisService(settings)


def _session(service: AnalysisService, tmp_path: Path) -> str:
    binary = tmp_path / "sample.exe"
    _write_minimal_pe(binary)
    created = service.create_session(str(binary))
    assert created.ok and created.data is not None, created.error
    return str(created.data["session"]["id"])


def _authorize(service: AnalysisService, session_id: str, *, pids: list[int]) -> None:
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": list(pids), "packages": []}},
    )


class _FakeDevice:
    id = "emulator-5554"
    name = "Android Emulator"
    type = "usb"


class _FakeFrida:
    """A cooperative stand-in for FridaClient covering the happy paths."""

    def enumerate_devices(self) -> dict[str, Any]:
        return {"devices": [{"id": "usb", "type": "usb"}]}

    def add_remote_device(self, endpoint: str) -> dict[str, Any]:
        return {"id": endpoint, "name": "remote", "type": "remote"}

    def _resolve_device(self, device_id: str | None) -> _FakeDevice:
        return _FakeDevice()

    def applications(self, device_id: str | None, *, limit: int = 256) -> dict[str, Any]:
        return {"device": device_id, "applications": ["a.b"], "limit": limit}

    def spawn(self, device_id: str | None, package: str) -> dict[str, Any]:
        return {"device": device_id, "package": package, "pid": 4321}

    def java_enumerate(
        self,
        device_id: str | None,
        target_pid: int,
        *,
        allowed_pids: list[int],
        mode: str,
        class_name: str | None,
        name_filter: str | None,
        limit: int,
    ) -> dict[str, Any]:
        return {"mode": mode, "pid": target_pid, "classes": ["a.B"]}


class _BrokenFrida:
    def __getattr__(self, name: str) -> Any:
        def _explode(*args: Any, **kwargs: Any) -> Any:
            raise FridaError("frida_unavailable", f"{name} failed")

        return _explode


def _use(monkeypatch: pytest.MonkeyPatch, client: Any) -> None:
    monkeypatch.setattr(service_frida, "FridaClient", lambda *a, **k: client)


# --- module-level helpers ---


def test_append_recent_dedupes_and_bounds() -> None:
    assert _append_recent([1, 2, 3], 2) == [1, 3, 2]
    assert _append_recent(None, 7) == [7]
    assert _append_recent(list(range(64)), 64, limit=3) == [62, 63, 64]


def test_last_pid_returns_the_newest_and_refuses_when_empty() -> None:
    assert _last_pid({"pids": [10, 20, 30]}) == 30
    with pytest.raises(FridaError) as caught:
        _last_pid({"pids": []})
    assert caught.value.code == "invalid_state"


# --- _frida_auth ---


def test_frida_call_without_a_connected_device_is_refused(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.frida_applications(session_id)
        assert not result.ok and result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


# --- frida_devices ---


def test_frida_devices_reports_the_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _FakeFrida())
    service = _service(tmp_path)
    try:
        result = service.frida_devices()
        assert result.ok and result.data is not None, result.error
        assert result.data["devices"][0]["id"] == "usb"
    finally:
        service.close_all()


def test_frida_devices_wraps_a_frida_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _BrokenFrida())
    service = _service(tmp_path)
    try:
        result = service.frida_devices()
        assert not result.ok and result.error is not None
        assert result.error.code == "frida_unavailable"
    finally:
        service.close_all()


def test_frida_devices_wraps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom:
        def enumerate_devices(self) -> dict[str, Any]:
            raise RuntimeError("frida native crash")

    _use(monkeypatch, _Boom())
    service = _service(tmp_path)
    try:
        result = service.frida_devices()
        assert not result.ok and result.error is not None
        assert "native crash" in result.error.message
    finally:
        service.close_all()


# --- frida_device_connect ---


def test_device_connect_resolves_a_usb_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _FakeFrida())
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.frida_device_connect(session_id)
        assert result.ok and result.data is not None, result.error
        assert result.data["device"]["id"] == "emulator-5554"
    finally:
        service.close_all()


def test_device_connect_adds_a_remote_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _FakeFrida())
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.frida_device_connect(session_id, endpoint="10.0.0.5:27042")
        assert result.ok and result.data is not None, result.error
        assert result.data["device"]["id"] == "10.0.0.5:27042"
    finally:
        service.close_all()


def test_device_connect_wraps_a_frida_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _BrokenFrida())
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        result = service.frida_device_connect(session_id, endpoint="10.0.0.5:27042")
        assert not result.ok and result.error is not None
        assert result.error.code == "frida_unavailable"
    finally:
        service.close_all()


# --- frida_server_ensure ---


def test_server_ensure_uses_the_adb_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FakeAdb:
        def ensure_frida_server(
            self,
            serial: str,
            *,
            server_binary: str | None,
            port: int,
            bind_host: str,
        ) -> dict[str, Any]:
            return {"serial": serial, "port": port, "running": True}

    service = _service(tmp_path)
    monkeypatch.setattr(service, "_adb_backend", _FakeAdb(), raising=False)
    try:
        session_id = _session(service, tmp_path)
        result = service.frida_server_ensure(session_id, "emulator-5554")
        assert result.ok and result.data is not None, result.error
        assert result.data["running"] is True
    finally:
        service.close_all()


def test_server_ensure_wraps_a_backend_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from headless_re_mcp.backends.adb import AdbError

    class _FakeAdb:
        def ensure_frida_server(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise AdbError("adb_unavailable", "no adb on PATH")

    service = _service(tmp_path)
    monkeypatch.setattr(service, "_adb_backend", _FakeAdb(), raising=False)
    try:
        session_id = _session(service, tmp_path)
        result = service.frida_server_ensure(session_id, "emulator-5554")
        assert not result.ok and result.error is not None
        assert result.error.code == "adb_unavailable"
    finally:
        service.close_all()


# --- frida_applications / spawn / java ---


def test_applications_lists_and_wraps_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _FakeFrida())
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        _authorize(service, session_id, pids=[])
        ok = service.frida_applications(session_id, limit=10)
        assert ok.ok and ok.data is not None, ok.error
        assert ok.data["applications"] == ["a.b"]
    finally:
        service.close_all()

    _use(monkeypatch, _BrokenFrida())
    broken_service = _service(tmp_path)
    try:
        session_id = _session(broken_service, tmp_path)
        _authorize(broken_service, session_id, pids=[])
        bad = broken_service.frida_applications(session_id)
        assert not bad.ok and bad.error is not None
        assert bad.error.code == "frida_unavailable"
    finally:
        broken_service.close_all()


def test_spawn_records_the_pid_and_wraps_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _FakeFrida())
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        _authorize(service, session_id, pids=[])
        ok = service.frida_spawn(session_id, "a.b")
        assert ok.ok and ok.data is not None, ok.error
        assert ok.data["pid"] == 4321
        auth = service.registry.get(session_id).metadata["frida_authorized"]
        assert auth["pids"] == [4321]
        assert auth["packages"] == ["a.b"]
    finally:
        service.close_all()

    _use(monkeypatch, _BrokenFrida())
    broken_service = _service(tmp_path)
    try:
        session_id = _session(broken_service, tmp_path)
        _authorize(broken_service, session_id, pids=[])
        bad = broken_service.frida_spawn(session_id, "a.b")
        assert not bad.ok and bad.error is not None
        assert bad.error.code == "frida_unavailable"
    finally:
        broken_service.close_all()


def test_applications_and_java_wrap_unexpected_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Boom:
        def applications(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("frida native crash in applications")

        def java_enumerate(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("frida native crash in java")

    _use(monkeypatch, _Boom())
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        _authorize(service, session_id, pids=[42])

        apps = service.frida_applications(session_id)
        assert not apps.ok and apps.error is not None
        assert "native crash in applications" in apps.error.message

        java = service.frida_java_classes(session_id)
        assert not java.ok and java.error is not None
        assert "native crash in java" in java.error.message
    finally:
        service.close_all()


def test_java_enumeration_uses_the_last_pid_and_wraps_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, _FakeFrida())
    service = _service(tmp_path)
    try:
        session_id = _session(service, tmp_path)
        _authorize(service, session_id, pids=[111, 222])

        classes = service.frida_java_classes(session_id, name_filter="a")
        assert classes.ok and classes.data is not None, classes.error
        assert classes.data["pid"] == 222
        assert classes.data["mode"] == "classes"

        methods = service.frida_java_methods(session_id, "a.B", pid=999)
        assert methods.ok and methods.data is not None, methods.error
        assert methods.data["pid"] == 999
        assert methods.data["mode"] == "methods"
    finally:
        service.close_all()

    _use(monkeypatch, _BrokenFrida())
    broken_service = _service(tmp_path)
    try:
        session_id = _session(broken_service, tmp_path)
        _authorize(broken_service, session_id, pids=[111])
        bad = broken_service.frida_java_classes(session_id)
        assert not bad.ok and bad.error is not None
        assert bad.error.code == "frida_unavailable"
    finally:
        broken_service.close_all()
