"""Path coverage for the device-aware Frida service mixin (``core/service_frida``).

FridaClient and AdbBackend aren't exercised in the quality environment, so the
mixin's success surface, the FridaError/AdbError envelopes, the remote-endpoint
connect branch, and the ``_frida_auth``/``_last_pid`` guards were unreached.
These fake the two backends and drive frida.* on a web session, seeding the
per-session authorization record directly where a test needs an existing pid.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.service_frida as sf
from headless_re_mcp.backends.adb import AdbError
from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_AUTH_KEY = sf._AUTH_KEY


class _FakeFrida:
    def enumerate_devices(self) -> dict[str, Any]:
        return {"devices": ["usb"]}

    def add_remote_device(self, endpoint: str) -> dict[str, Any]:
        return {"id": endpoint, "name": "remote", "type": "remote"}

    def _resolve_device(self, device_id: str) -> Any:
        return SimpleNamespace(id=device_id, name="Local USB", type="usb")

    def applications(self, device_id: Any, *, limit: int) -> dict[str, Any]:
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


class _BoomFrida:
    """Every op raises FridaError, to drive the error envelopes uniformly."""

    def __getattr__(self, name: str) -> Any:
        def _fn(*args: Any, **kwargs: Any) -> Any:
            raise FridaError("frida_failed", "frida call failed")

        return _fn


class _CrashFrida:
    def enumerate_devices(self) -> dict[str, Any]:
        raise RuntimeError("device enumeration blew up")


class _BoomAdb:
    def ensure_frida_server(
        self, serial: str, *, server_binary: Any, port: int, bind_host: str
    ) -> dict[str, Any]:
        raise AdbError("adb_failed", "device offline")


def _service(tmp_path: Path) -> AnalysisService:
    return AnalysisService(replace(Settings.load(), artifact_root=tmp_path / "artifacts"))


def _web_session(service: AnalysisService) -> str:
    created = service.create_session("https://example.com/app", target="web")
    assert created.ok and created.data is not None
    session = created.data["session"]
    assert isinstance(session, dict)
    return str(session["id"])


def _authorize(service: AnalysisService, session_id: str, pids: tuple[int, ...] = ()) -> None:
    service.registry.update_metadata(
        session_id,
        {_AUTH_KEY: {"device_id": "usb", "pids": list(pids), "packages": ["com.example"]}},
    )


# --------------------------------------------------------------------------- #
# _last_pid / _frida_auth guards                                               #
# --------------------------------------------------------------------------- #
def test_last_pid_requires_a_spawned_process() -> None:
    with pytest.raises(FridaError) as excinfo:
        sf._last_pid({"pids": []})
    assert excinfo.value.code == "invalid_state"
    assert sf._last_pid({"pids": [10, 20]}) == 20


def test_frida_tools_refuse_a_session_without_a_connected_device(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        result = service.frida_applications(session_id)
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_state"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# frida_devices                                                                #
# --------------------------------------------------------------------------- #
def test_frida_devices_enumerates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    try:
        monkeypatch.setattr(sf, "FridaClient", _FakeFrida)
        result = service.frida_devices()
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["devices"] == ["usb"]
    finally:
        service.close_all()


def test_frida_devices_wraps_an_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        monkeypatch.setattr(sf, "FridaClient", _CrashFrida)
        result = service.frida_devices()
        assert result.ok is False and result.error is not None
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# frida_device_connect                                                         #
# --------------------------------------------------------------------------- #
def test_frida_device_connect_adds_a_remote_endpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        monkeypatch.setattr(sf, "FridaClient", _FakeFrida)
        result = service.frida_device_connect(session_id, endpoint="tcp:10.0.0.5:27042")
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["device"]["id"] == "tcp:10.0.0.5:27042"
        session = service.registry.get(session_id)
        assert session.metadata[_AUTH_KEY]["device_id"] == "tcp:10.0.0.5:27042"
    finally:
        service.close_all()


def test_frida_device_connect_maps_a_frida_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        monkeypatch.setattr(sf, "FridaClient", _BoomFrida)
        result = service.frida_device_connect(session_id, endpoint="tcp:10.0.0.5:27042")
        assert result.ok is False and result.error is not None
        assert result.error.code == "frida_failed"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# frida_server_ensure                                                          #
# --------------------------------------------------------------------------- #
def test_frida_server_ensure_maps_an_adb_error(tmp_path: Path) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        service._adb_backend = _BoomAdb()  # type: ignore[assignment]
        result = service.frida_server_ensure(session_id, serial="emulator-5554")
        assert result.ok is False and result.error is not None
        assert result.error.code == "adb_failed"
    finally:
        service.close_all()


# --------------------------------------------------------------------------- #
# frida_applications / frida_spawn / _java                                     #
# --------------------------------------------------------------------------- #
def test_frida_applications_lists_after_a_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        _authorize(service, session_id)
        monkeypatch.setattr(sf, "FridaClient", _FakeFrida)
        result = service.frida_applications(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["device"] == "usb"
    finally:
        service.close_all()


def test_frida_spawn_maps_a_frida_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        _authorize(service, session_id)
        monkeypatch.setattr(sf, "FridaClient", _BoomFrida)
        result = service.frida_spawn(session_id, "com.example.app")
        assert result.ok is False and result.error is not None
        assert result.error.code == "frida_failed"
    finally:
        service.close_all()


def test_frida_java_classes_enumerate_the_last_spawned_pid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        _authorize(service, session_id, pids=(4321,))
        monkeypatch.setattr(sf, "FridaClient", _FakeFrida)
        result = service.frida_java_classes(session_id)
        assert result.ok, result.error
        assert result.data is not None
        assert result.data["pid"] == 4321
        assert result.data["mode"] == "classes"
    finally:
        service.close_all()


def test_frida_java_methods_map_a_frida_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        _authorize(service, session_id, pids=(4321,))
        monkeypatch.setattr(sf, "FridaClient", _BoomFrida)
        result = service.frida_java_methods(session_id, "com.example.Main")
        assert result.ok is False and result.error is not None
        assert result.error.code == "frida_failed"
    finally:
        service.close_all()


def test_coerce_limit_accepts_a_numeric_string_but_refuses_garbage() -> None:
    # A numeric string and a float still work, matching the prior lenient
    # int(limit) and the sibling _coerce_pid; a value that cannot be a count is
    # a fixable invalid_params, not the internal_error incident a bare
    # TypeError/OverflowError would have produced inside java_enumerate.
    assert sf._coerce_limit("500") == 500
    assert sf._coerce_limit(5.0) == 5
    for bad in (["500"], {"limit": 1}, "not-a-number", None, float("inf")):
        with pytest.raises(FridaError) as excinfo:
            sf._coerce_limit(bad)
        assert excinfo.value.code == "invalid_params"


@pytest.mark.parametrize("bad", [[10], {"limit": 1}, None, float("inf"), "not-a-number"])
def test_frida_java_classes_refuses_a_non_int_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: object
) -> None:
    # java_enumerate is the one frida enumeration whose limit was not bounded by
    # a backend clamp, so a list/dict/None/inf reached int(limit) and raised --
    # an internal_error incident on the real backend. The service must answer
    # invalid_params, and the backend enumeration must not run.
    calls: list[int] = []

    class _RecordingFrida(_FakeFrida):
        def java_enumerate(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            calls.append(1)
            return super().java_enumerate(*args, **kwargs)

    service = _service(tmp_path)
    try:
        session_id = _web_session(service)
        _authorize(service, session_id, pids=(4321,))
        monkeypatch.setattr(sf, "FridaClient", _RecordingFrida)
        result = service.frida_java_classes(session_id, pid=4321, limit=bad)  # type: ignore[arg-type]
        assert result.ok is False and result.error is not None
        assert result.error.code == "invalid_params"
        assert calls == []
    finally:
        service.close_all()
