"""Device-aware Frida service: authorization, error mapping and pid recency.

The service methods wrap the backend client and add the per-session
authorization record that the local single-pid rule generalises to. These
exercise the branches the live Android gates cannot reach on a machine with no
device: a session that never connected, a backend error mapped to an envelope,
and the "most recently spawned pid" default the Java tools rely on.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaError
from headless_re_mcp.core.service_frida import (
    FridaDeviceMixin,
    _append_recent,
    _last_pid,
)
from headless_re_mcp.core.session import SessionRegistry


class _Repo:
    def record_backend(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def append_timeline(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


class _Service(FridaDeviceMixin):
    def __init__(self) -> None:
        self.registry = SessionRegistry()
        self.repository = _Repo()


def _service_with_session() -> tuple[_Service, str]:
    service = _Service()
    session = service.registry.create("https://example.invalid")
    return service, session.id


# ----------------------------------------------------------------------
# _append_recent and _last_pid.
# ----------------------------------------------------------------------
def test_append_recent_keeps_the_newest_last_and_dedupes() -> None:
    """The Java tools default to the newest pid, so order is load-bearing.

    A sorted set would target the highest pid, not the app the caller just
    launched. Re-spawning an already-present pid moves it to the end rather
    than duplicating it.
    """
    items = _append_recent([1, 2, 3], 2)
    assert items == [1, 3, 2]
    items = _append_recent(None, 7)
    assert items == [7]


def test_append_recent_is_bounded() -> None:
    """A session that spawns forever cannot grow its authorization list."""
    result = _append_recent(list(range(100)), 100, limit=10)
    assert len(result) == 10
    assert result[-1] == 100
    assert result[0] == 91


def test_last_pid_refuses_when_nothing_was_spawned() -> None:
    with pytest.raises(FridaError) as caught:
        _last_pid({"pids": []})
    assert caught.value.code == "invalid_state"
    assert _last_pid({"pids": [10, 20]}) == 20


# ----------------------------------------------------------------------
# Authorization gate.
# ----------------------------------------------------------------------
def test_applications_without_connect_asks_to_connect_a_device_first() -> None:
    """A session that never connected has no device; the reply says so.

    An agent that read a generic failure might retry applications forever;
    invalid_state naming frida.device.connect points it at the missing step.
    """
    service, session_id = _service_with_session()
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"
    assert "frida.device.connect" in result.error.message


def test_java_classes_without_a_spawn_reports_invalid_state() -> None:
    """Java enumeration needs a target pid; none spawned yet is invalid_state."""
    service, session_id = _service_with_session()
    service.registry.update_metadata(
        session_id, {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}}
    )
    result = service.frida_java_classes(session_id)
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_state"


# ----------------------------------------------------------------------
# Error mapping to the envelope.
# ----------------------------------------------------------------------
def test_devices_maps_a_backend_error_to_the_envelope(monkeypatch: Any) -> None:
    """A FridaError becomes a structured failure with its own code, not a raise."""

    class _Client:
        def enumerate_devices(self) -> dict[str, Any]:
            raise FridaError("backend_error", "frida-core down")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service = _Service()
    result = service.frida_devices()
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"


def test_devices_reports_an_unexpected_exception_as_a_failure(monkeypatch: Any) -> None:
    """An unexpected exception still lands as an envelope, never a traceback."""

    class _Client:
        def enumerate_devices(self) -> dict[str, Any]:
            raise RuntimeError("boom")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service = _Service()
    result = service.frida_devices()
    assert result.ok is False
    assert result.error is not None


def test_spawn_records_the_pid_and_package_on_the_session(monkeypatch: Any) -> None:
    """A successful spawn authorizes the pid so a later Java call can use it."""

    class _Client:
        def spawn(self, device_id: str | None, package: str) -> dict[str, Any]:
            return {"package": package, "pid": 4242, "device": device_id or "local"}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    service.registry.update_metadata(
        session_id, {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}}
    )
    result = service.frida_spawn(session_id, "com.example.app")
    assert result.ok is True
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["pids"] == [4242]
    assert auth["packages"] == ["com.example.app"]


def test_spawn_maps_a_backend_error_to_the_envelope(monkeypatch: Any) -> None:
    class _Client:
        def spawn(self, device_id: str | None, package: str) -> dict[str, Any]:
            raise FridaError("invalid_params", "package must be an Android package id")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    service.registry.update_metadata(
        session_id, {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}}
    )
    result = service.frida_spawn(session_id, "notapackage")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "invalid_params"


def test_device_connect_via_endpoint_uses_add_remote_device(monkeypatch: Any) -> None:
    """The endpoint form registers a remote device and records its resolved id."""

    class _Client:
        def add_remote_device(self, endpoint: str) -> dict[str, Any]:
            return {"id": "10.0.0.5:27042", "name": "remote", "type": "remote"}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    result = service.frida_device_connect(session_id, endpoint="10.0.0.5:27042")
    assert result.ok is True
    assert result.data is not None
    assert result.data["device"]["id"] == "10.0.0.5:27042"
    auth = service.registry.get(session_id).metadata["frida_authorized"]
    assert auth["device_id"] == "10.0.0.5:27042"


def test_devices_success_reports_ok_with_the_backend_payload(monkeypatch: Any) -> None:
    class _Client:
        def enumerate_devices(self) -> dict[str, Any]:
            return {"devices": [{"id": "local"}], "count": 1}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    result = _Service().frida_devices()
    assert result.ok is True
    assert result.data is not None
    assert result.data["count"] == 1


def test_device_connect_maps_a_backend_error_to_the_envelope(monkeypatch: Any) -> None:
    class _Client:
        def add_remote_device(self, endpoint: str) -> dict[str, Any]:
            raise FridaError("backend_error", "endpoint refused")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    result = service.frida_device_connect(session_id, endpoint="10.0.0.9:1")
    assert result.ok is False
    assert result.error is not None
    assert result.error.code == "backend_error"
    # A failed connect leaves no authorization behind for a later call to reuse.
    assert "frida_authorized" not in service.registry.get(session_id).metadata


def test_applications_success_after_connect(monkeypatch: Any) -> None:
    class _Client:
        def applications(self, device_id: str | None, limit: int = 256) -> dict[str, Any]:
            return {"applications": [], "count": 0, "total": 0, "has_more": False}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    service.registry.update_metadata(
        session_id, {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}}
    )
    result = service.frida_applications(session_id)
    assert result.ok is True


def test_applications_reports_an_unexpected_exception(monkeypatch: Any) -> None:
    class _Client:
        def applications(self, device_id: str | None, limit: int = 256) -> dict[str, Any]:
            raise RuntimeError("device manager crashed")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    service.registry.update_metadata(
        session_id, {"frida_authorized": {"device_id": "usb", "pids": [], "packages": []}}
    )
    result = service.frida_applications(session_id)
    assert result.ok is False
    assert result.error is not None


def test_java_reports_an_unexpected_exception(monkeypatch: Any) -> None:
    class _Client:
        def java_enumerate(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("script host died")

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    service.registry.update_metadata(
        session_id, {"frida_authorized": {"device_id": "usb", "pids": [5], "packages": []}}
    )
    result = service.frida_java_classes(session_id)
    assert result.ok is False
    assert result.error is not None


def test_java_methods_uses_the_last_spawned_pid_by_default(monkeypatch: Any) -> None:
    """With no explicit pid, the Java call targets the most recent spawn."""
    seen: dict[str, Any] = {}

    class _Client:
        def java_enumerate(self, device_id: str | None, pid: int, **kwargs: Any) -> dict[str, Any]:
            seen["pid"] = pid
            seen["mode"] = kwargs["mode"]
            return {"class_name": kwargs.get("class_name"), "found": True, "methods": []}

    monkeypatch.setattr(
        "headless_re_mcp.core.service_frida.FridaClient", lambda: _Client()
    )
    service, session_id = _service_with_session()
    service.registry.update_metadata(
        session_id,
        {"frida_authorized": {"device_id": "usb", "pids": [11, 22], "packages": []}},
    )
    result = service.frida_java_methods(session_id, class_name="Foo")
    assert result.ok is True
    assert seen["pid"] == 22
    assert seen["mode"] == "methods"
