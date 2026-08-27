"""Frida client guard paths: envelopes, device resolution, and fast-fail order.

The happy-path field shapes live in ``test_frida_fields.py``; this file drives
the error and branch arcs a real frida runtime can never exercise in CI -- the
paths that decide whether a caller gets a structured ``FridaError`` envelope or
a raw exception the service files as an ``internal_error`` incident.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _invoke,
)


# --------------------------------------------------------------------------
# A single configurable fake frida runtime. Each operation reads flags off the
# config dict so one harness can stand in for a local attach, a device attach,
# a spawn, a device lookup and a device manager without a class per scenario.
# --------------------------------------------------------------------------
class _Exports:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self._cfg = cfg

    def modules(self, cap: int) -> Any:
        return self._cfg.get("modules")

    def exports(self, name: str, cap: int) -> Any:
        return self._cfg.get("exports")

    def read(self, address: int, size: int) -> Any:
        return self._cfg.get("read")

    def classes(self, name_filter: str, cap: int) -> Any:
        return self._cfg.get("classes")

    def methods(self, class_name: str, cap: int) -> Any:
        return self._cfg.get("methods")


class _Script:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self._cfg = cfg
        self.loaded = False
        self.destroyed = False
        self.exports_sync = _Exports(cfg)

    def load(self) -> None:
        boom = self._cfg.get("load_raises")
        if boom is not None:
            raise boom
        self.loaded = True


class _Session:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self._cfg = cfg
        self.detached = False
        self.script = _Script(cfg)

    def create_script(self, source: str) -> _Script:
        assert source
        return self.script

    def detach(self) -> None:
        self.detached = True
        self.script.destroyed = True


class _Device:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self._cfg = cfg
        self.id = cfg.get("device_id", "usb")
        self.name = cfg.get("device_name", "USB Device")
        self.type = cfg.get("device_type", "usb")
        self.session = _Session(cfg)
        self.spawned: list[str] = []
        self.resumed: list[int] = []
        self.killed: list[int] = []

    def attach(self, pid: int) -> _Session:
        boom = self._cfg.get("attach_raises")
        if boom is not None:
            raise boom
        return self.session

    def enumerate_applications(self) -> Any:
        boom = self._cfg.get("apps_raises")
        if boom is not None:
            raise boom
        return self._cfg.get("applications", [])

    def spawn(self, package: str) -> int:
        boom = self._cfg.get("spawn_raises")
        if boom is not None:
            raise boom
        self.spawned.append(package)
        return int(self._cfg.get("spawn_pid", 4321))

    def resume(self, pid: int) -> None:
        boom = self._cfg.get("resume_raises")
        if boom is not None:
            raise boom
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)


class _Manager:
    def __init__(self, device: _Device, cfg: dict[str, Any]) -> None:
        self._device = device
        self._cfg = cfg
        self.added: list[str] = []

    def get_device(self, endpoint: str, timeout: float | None = None) -> _Device:
        boom = self._cfg.get("mgr_get_raises")
        if boom is not None:
            raise boom
        return self._device

    def add_remote_device(self, endpoint: str) -> _Device:
        boom = self._cfg.get("mgr_add_raises")
        if boom is not None:
            raise boom
        self.added.append(endpoint)
        return self._device


class _Frida:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self._cfg = cfg
        self.device = _Device(cfg)
        self.manager = _Manager(self.device, cfg)
        self.local_attaches: list[int] = []

    def attach(self, pid: int) -> _Session:
        self.local_attaches.append(pid)
        boom = self._cfg.get("local_attach_raises")
        if boom is not None:
            raise boom
        return self.device.session

    def get_local_device(self) -> _Device:
        return self.device

    def get_usb_device(self, **_: object) -> _Device:
        boom = self._cfg.get("usb_raises")
        if boom is not None:
            raise boom
        return self.device

    def get_device(self, device_id: str, **_: object) -> _Device:
        boom = self._cfg.get("get_device_raises")
        if boom is not None:
            raise boom
        return self.device

    def get_device_manager(self) -> _Manager:
        return self.manager

    def enumerate_devices(self) -> Any:
        boom = self._cfg.get("devices_raises")
        if boom is not None:
            raise boom
        return self._cfg.get("devices", [])


def _client(cfg: dict[str, Any] | None = None) -> tuple[FridaClient, _Frida]:
    client = FridaClient()
    fake = _Frida(cfg or {})
    client._frida = fake
    client._available = True
    return client, fake


# --------------------------------------------------------------------------
# Small helpers: signature-driven timeout passing and bound checks.
# --------------------------------------------------------------------------
def test_invoke_passes_timeout_only_when_the_callable_names_it() -> None:
    seen: dict[str, Any] = {}

    def with_timeout(x: int, timeout: float | None = None) -> int:
        seen["timeout"] = timeout
        return x

    def without_timeout(x: int) -> int:
        seen["called"] = True
        return x

    assert _invoke(with_timeout, 5, timeout=1.5) == 5
    assert seen["timeout"] == 1.5
    assert _invoke(without_timeout, 7, timeout=1.5) == 7


def test_accepts_timeout_is_false_when_a_callable_has_no_signature() -> None:
    # range() raises ValueError from inspect.signature; the helper must treat an
    # un-introspectable callable as "does not name timeout" rather than crash.
    assert _accepts_timeout(range) is False


def test_bound_timeout_rejects_a_non_positive_deadline() -> None:
    with pytest.raises(FridaError) as info:
        _bound_timeout(0)
    assert info.value.code == "invalid_params"


def test_a_fake_frida_module_marks_the_client_available() -> None:
    # Exercises the import-success arc of __init__ without the native package.
    module = types.ModuleType("frida")
    saved = sys.modules.get("frida")
    sys.modules["frida"] = module
    try:
        client = FridaClient()
        assert client.available is True
        assert client._frida is module
    finally:
        if saved is not None:
            sys.modules["frida"] = saved
        else:
            del sys.modules["frida"]


# --------------------------------------------------------------------------
# Local (PE) attach / require guards.
# --------------------------------------------------------------------------
def test_probe_attach_returns_and_detaches() -> None:
    client, fake = _client()
    payload = client.attach(4242, allowed_pid=4242)
    assert payload["attached"] is True
    assert payload["device"] == "local"
    assert fake.device.session.detached is True


def test_probe_attach_rejects_a_non_positive_pid() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.attach(0, allowed_pid=0)
    assert info.value.code == "invalid_params"


def test_probe_attach_refuses_a_pid_that_is_not_the_debuggee() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.attach(10, allowed_pid=11)
    assert info.value.code == "permission_denied"


def test_probe_attach_says_capability_unavailable_without_frida() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as info:
        client.attach(5, allowed_pid=5)
    assert info.value.code == "capability_unavailable"


def test_require_refuses_a_foreign_pid_before_touching_frida() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.modules(10, allowed_pid=11, limit=1)
    assert info.value.code == "permission_denied"


def test_require_reports_capability_unavailable_for_the_allowed_pid() -> None:
    client, _ = _client()
    client._available = False
    with pytest.raises(FridaError) as info:
        client.modules(5, allowed_pid=5, limit=1)
    assert info.value.code == "capability_unavailable"


def test_local_attach_failure_is_a_backend_error_not_a_raw_exception() -> None:
    client, _ = _client({"local_attach_raises": RuntimeError("device busy")})
    with pytest.raises(FridaError) as info:
        client.modules(5, allowed_pid=5, limit=1)
    assert info.value.code == "backend_error"
    assert "attach failed" in info.value.message


def test_local_attach_timeout_maps_to_the_timeout_code() -> None:
    client, _ = _client({"local_attach_raises": TimeoutError("frida timed out")})
    with pytest.raises(FridaError) as info:
        client.modules(5, allowed_pid=5, limit=1)
    assert info.value.code == "timeout"


# --------------------------------------------------------------------------
# modules / exports / memory_read payload shaping.
# --------------------------------------------------------------------------
def test_modules_tolerates_a_bare_list_payload() -> None:
    payload = [
        {"name": "a.dll", "base": "0x1", "size": 10, "path": "/a"},
        {"name": "b.dll", "base": "0x2", "size": 20, "path": "/b"},
    ]
    client, _ = _client({"modules": payload})
    result = client.modules(5, allowed_pid=5, limit=64)
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["has_more"] is False


def test_exports_rejects_a_blank_module_name() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.exports(5, "   ", allowed_pid=5)
    assert info.value.code == "invalid_params"


def test_exports_on_an_unexpected_payload_is_a_backend_error() -> None:
    client, _ = _client({"exports": ["not", "a", "dict"]})
    with pytest.raises(FridaError) as info:
        client.exports(5, "ntdll.dll", allowed_pid=5)
    assert info.value.code == "backend_error"


def test_exports_skips_non_dict_rows_and_keeps_the_rest() -> None:
    client, _ = _client(
        {
            "exports": {
                "found": True,
                "module": "ntdll.dll",
                "base": "0x1000",
                "exports": [
                    {"name": "NtClose", "address": "0x1", "type": "function"},
                    "junk-row",
                ],
            }
        }
    )
    result = client.exports(5, "ntdll.dll", allowed_pid=5)
    assert result["found"] is True
    assert result["count"] == 1
    assert result["exports"][0]["name"] == "NtClose"


def test_memory_read_returns_hex_bytes() -> None:
    client, _ = _client({"read": [1, 2, 255]})
    result = client.memory_read(5, 0x1000, 3, allowed_pid=5)
    assert result["encoding"] == "hex"
    assert result["data"] == "0102ff"


def test_memory_read_rejects_an_out_of_range_size() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.memory_read(5, 0x1000, 0, allowed_pid=5)
    assert info.value.code == "invalid_params"


# --------------------------------------------------------------------------
# hook_template (local): the documented backend_error envelope.
# --------------------------------------------------------------------------
def test_local_hook_unknown_template_lists_the_allowed_set() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.hook_template(5, "totally-made-up", allowed_pid=5)
    assert info.value.code == "invalid_params"
    assert "android_ssl_unpin" in info.value.details["allowed"]


def test_local_hook_script_load_failure_is_a_backend_error() -> None:
    """A template that raises on load (non-ART target) must not leak raw.

    The template docstring promises the caller a backend_error envelope; before
    the fix the local path re-raised the raw exception, which the service filed
    as an internal_error incident -- unlike the device sibling and the reads
    that already route attach failures through _attach_local.
    """
    client, fake = _client({"load_raises": RuntimeError("no ART on this process")})
    with pytest.raises(FridaError) as info:
        client.hook_template(5, "android_ssl_unpin", allowed_pid=5)
    assert info.value.code == "backend_error"
    assert "hook template failed" in info.value.message
    assert fake.device.session.detached is True


def test_local_hook_attach_failure_is_a_backend_error() -> None:
    client, _ = _client({"local_attach_raises": RuntimeError("cannot attach")})
    with pytest.raises(FridaError) as info:
        client.hook_template(5, "noop", allowed_pid=5)
    assert info.value.code == "backend_error"
    assert "attach failed" in info.value.message


def test_local_hook_bad_timeout_is_rejected_after_template_lookup() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.hook_template(5, "noop", allowed_pid=5, timeout=0)
    assert info.value.code == "invalid_params"


# --------------------------------------------------------------------------
# Device resolution branches.
# --------------------------------------------------------------------------
def test_resolve_local_device_when_id_is_none() -> None:
    client, _ = _client({"applications": []})
    result = client.applications(None, limit=5)
    assert result["count"] == 0


def test_resolve_usb_device() -> None:
    client, _ = _client({"applications": []})
    assert client.applications("usb", limit=5)["count"] == 0


def test_resolve_remote_device_reuses_a_registered_endpoint() -> None:
    client, fake = _client({"applications": []})
    client.applications("127.0.0.1:5555", limit=5)
    # The registered device was reused; add_remote_device was not called.
    assert fake.manager.added == []


def test_resolve_remote_device_adds_when_not_yet_registered() -> None:
    client, fake = _client(
        {"applications": [], "mgr_get_raises": RuntimeError("unknown endpoint")}
    )
    client.applications("10.0.0.5:27042", limit=5)
    assert fake.manager.added == ["10.0.0.5:27042"]


def test_resolve_named_device_by_id() -> None:
    client, _ = _client({"applications": []})
    assert client.applications("emulator-5554", limit=5)["count"] == 0


def test_resolve_device_failure_is_reported_not_found() -> None:
    client, _ = _client({"usb_raises": RuntimeError("no usb device")})
    with pytest.raises(FridaError) as info:
        client.applications("usb", limit=5)
    assert info.value.code == "not_found"
    assert info.value.details["device_id"] == "usb"


# --------------------------------------------------------------------------
# enumerate_devices / add_remote_device / applications envelopes.
# --------------------------------------------------------------------------
def test_enumerate_devices_failure_is_a_backend_error() -> None:
    client, _ = _client({"devices_raises": RuntimeError("frida core down")})
    with pytest.raises(FridaError) as info:
        client.enumerate_devices()
    assert info.value.code == "backend_error"


def test_add_remote_device_reuses_a_registered_endpoint() -> None:
    client, fake = _client()
    info = client.add_remote_device("127.0.0.1:5555")
    assert info["id"] == fake.device.id
    assert fake.manager.added == []


def test_add_remote_device_adds_a_new_endpoint() -> None:
    client, fake = _client({"mgr_get_raises": RuntimeError("not registered")})
    client.add_remote_device("10.0.0.9:27042")
    assert fake.manager.added == ["10.0.0.9:27042"]


def test_add_remote_device_failure_is_a_backend_error() -> None:
    client, _ = _client(
        {
            "mgr_get_raises": RuntimeError("not registered"),
            "mgr_add_raises": RuntimeError("connection refused"),
        }
    )
    with pytest.raises(FridaError) as info:
        client.add_remote_device("10.0.0.9:27042")
    assert info.value.code == "backend_error"
    assert info.value.details["endpoint"] == "10.0.0.9:27042"


def test_applications_failure_is_a_backend_error() -> None:
    client, _ = _client({"apps_raises": RuntimeError("device offline")})
    with pytest.raises(FridaError) as info:
        client.applications("usb", limit=5)
    assert info.value.code == "backend_error"


def test_applications_caps_and_reports_more() -> None:
    apps = [SimpleNamespace(identifier=f"com.app{i}", name=f"App{i}", pid=0) for i in range(5)]
    client, _ = _client({"applications": apps})
    result = client.applications("usb", limit=2)
    assert result["count"] == 2
    assert result["total"] == 5
    assert result["has_more"] is True


# --------------------------------------------------------------------------
# spawn: fast-fail order and resume/backends.
# --------------------------------------------------------------------------
def test_spawn_validates_the_package_before_resolving_a_device() -> None:
    """A malformed package must be rejected without a (slow) device lookup.

    device_id "usb" is wired to raise on resolution; a valid package would
    surface that as not_found. An invalid package returning invalid_params
    proves the regex check ran first, matching hook_template_device checking
    its template and java_enumerate authorizing its pid before resolving.
    """
    client, _ = _client({"usb_raises": RuntimeError("no usb device")})
    with pytest.raises(FridaError) as info:
        client.spawn("usb", "not-a-package")
    assert info.value.code == "invalid_params"


def test_spawn_missing_package_is_invalid_params() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.spawn("usb", "   ")
    assert info.value.code == "invalid_params"


def test_spawn_resumes_and_returns_the_pid() -> None:
    client, fake = _client({"spawn_pid": 7777})
    result = client.spawn("usb", "com.example.app")
    assert result["pid"] == 7777
    assert fake.device.spawned == ["com.example.app"]
    assert fake.device.resumed == [7777]


def test_spawn_backend_failure_is_a_backend_error() -> None:
    client, _ = _client({"spawn_raises": RuntimeError("no such package")})
    with pytest.raises(FridaError) as info:
        client.spawn("usb", "com.example.app")
    assert info.value.code == "backend_error"


def test_spawn_kills_the_process_when_resume_fails() -> None:
    client, fake = _client({"spawn_pid": 8888, "resume_raises": RuntimeError("resume broke")})
    with pytest.raises(FridaError) as info:
        client.spawn("usb", "com.example.app")
    assert info.value.code == "backend_error"
    assert fake.device.killed == [8888]


# --------------------------------------------------------------------------
# java_enumerate: mode/argument guards and failure envelopes.
# --------------------------------------------------------------------------
def test_java_methods_requires_a_class_name() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.java_enumerate("usb", 5, allowed_pids={5}, mode="methods", limit=5)
    assert info.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.java_enumerate("usb", 5, allowed_pids={5}, mode="fields", limit=5)
    assert info.value.code == "invalid_params"


def test_java_attach_failure_is_a_backend_error() -> None:
    client, _ = _client({"attach_raises": RuntimeError("attach refused")})
    with pytest.raises(FridaError) as info:
        client.java_enumerate("usb", 5, allowed_pids={5}, mode="classes", limit=5)
    assert info.value.code == "backend_error"
    assert "attach failed" in info.value.message


def test_java_script_load_failure_is_a_backend_error() -> None:
    client, fake = _client({"load_raises": RuntimeError("script broke")})
    with pytest.raises(FridaError) as info:
        client.java_enumerate("usb", 5, allowed_pids={5}, mode="classes", limit=5)
    assert info.value.code == "backend_error"
    assert "java enumeration failed" in info.value.message
    assert fake.device.session.detached is True


# --------------------------------------------------------------------------
# hook_template_device: template / attach / load envelopes.
# --------------------------------------------------------------------------
def test_device_hook_unknown_template_lists_the_allowed_set() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.hook_template_device("usb", 5, "made-up", allowed_pids={5})
    assert info.value.code == "invalid_params"
    assert "android_ssl_unpin" in info.value.details["allowed"]


def test_device_hook_attach_failure_is_a_backend_error() -> None:
    client, _ = _client({"attach_raises": RuntimeError("attach refused")})
    with pytest.raises(FridaError) as info:
        client.hook_template_device("usb", 5, "noop", allowed_pids={5})
    assert info.value.code == "backend_error"
    assert "attach failed" in info.value.message


def test_device_hook_script_load_failure_is_a_backend_error() -> None:
    client, fake = _client({"load_raises": RuntimeError("no ART")})
    with pytest.raises(FridaError) as info:
        client.hook_template_device("usb", 5, "android_ssl_unpin", allowed_pids={5})
    assert info.value.code == "backend_error"
    assert "hook template failed" in info.value.message
    assert fake.device.session.detached is True


# --------------------------------------------------------------------------
# _authorize guards for the device surface.
# --------------------------------------------------------------------------
def test_authorize_reports_capability_unavailable_without_frida() -> None:
    client, _ = _client()
    client._available = False
    with pytest.raises(FridaError) as info:
        client.java_enumerate("usb", 5, allowed_pids={5}, mode="classes", limit=5)
    assert info.value.code == "capability_unavailable"


def test_authorize_rejects_a_non_integer_pid() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.java_enumerate("usb", "5", allowed_pids={5}, mode="classes", limit=5)  # type: ignore[arg-type]
    assert info.value.code == "invalid_params"


def test_authorize_refuses_a_pid_outside_the_allowed_set() -> None:
    client, _ = _client()
    with pytest.raises(FridaError) as info:
        client.hook_template_device("usb", 99, "noop", allowed_pids={1, 2, 3})
    assert info.value.code == "permission_denied"
    assert info.value.details["pid"] == 99
