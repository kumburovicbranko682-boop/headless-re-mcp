"""Guard and error paths for the Frida backend client.

The happy-path field contracts live in ``test_frida_fields.py``. This file
covers the refusals and failure conversions the client makes before or instead
of touching a real device: capability/permission gates, invalid parameters, the
device-resolution branches, and the way native exceptions are turned into
structured :class:`FridaError` envelopes (timeouts vs backend errors) with the
probe sessions detached and spawned pids killed. None of these need a real
Frida install -- they exercise the Python-side control flow that decides what a
caller sees.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from headless_re_mcp.backends.frida import client as frida_client
from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _invoke,
)
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT


def _ready_client(frida: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def test_accepts_timeout_reads_the_signature_and_falls_back_to_false() -> None:
    """A callable whose signature cannot be introspected is treated as not
    accepting a deadline rather than crashing the probe."""

    def with_timeout(pid: int, timeout: float = 0.0) -> int:
        return pid

    def without_timeout(pid: int, **kwargs: object) -> int:
        del kwargs
        return pid

    assert _accepts_timeout(with_timeout) is True
    # **kwargs alone is not a named timeout: frida.spawn takes aux options there.
    assert _accepts_timeout(without_timeout) is False
    # A non-callable makes inspect.signature raise TypeError; that must be
    # swallowed into False, not propagated up through the probe.
    assert _accepts_timeout(3) is False


def test_invoke_only_forwards_timeout_when_the_method_names_it() -> None:
    seen: dict[str, object] = {}

    def method_with_timeout(pid: int, timeout: float = 0.0) -> str:
        seen["timeout"] = timeout
        return "ok"

    def method_without_timeout(pid: int) -> str:
        seen["called"] = True
        return "ok"

    assert _invoke(method_with_timeout, 7, timeout=1.5) == "ok"
    assert seen["timeout"] == 1.5
    assert _invoke(method_without_timeout, 7, timeout=1.5) == "ok"
    assert seen["called"] is True


def test_bound_timeout_rejects_non_positive_and_caps_at_the_workflow_max() -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(0)
    assert caught.value.code == "invalid_params"
    with pytest.raises(FridaError):
        _bound_timeout(-3)
    assert _bound_timeout(5) == 5.0
    assert _bound_timeout(MAX_WORKFLOW_TIMEOUT * 10) == MAX_WORKFLOW_TIMEOUT


def test_constructor_binds_frida_when_the_module_imports(monkeypatch: Any) -> None:
    """With a Frida module importable, the client reports available and holds a
    reference to it; the bare-environment path (no module) stays unavailable."""
    fake = types.ModuleType("frida")
    monkeypatch.setitem(sys.modules, "frida", fake)
    client = FridaClient()
    assert client.available is True
    assert client._frida is fake


# ---------------------------------------------------------------------------
# attach / _require capability + permission gates
# ---------------------------------------------------------------------------


def test_attach_refuses_when_frida_is_not_installed() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.attach(10, allowed_pid=10)
    assert caught.value.code == "capability_unavailable"


def test_attach_rejects_a_non_positive_or_non_int_pid() -> None:
    client = _ready_client(object())
    for bad in (0, -1, "10"):
        with pytest.raises(FridaError) as caught:
            client.attach(bad, allowed_pid=bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"


def test_attach_refuses_a_pid_outside_the_session_debuggee() -> None:
    client = _ready_client(object())
    with pytest.raises(FridaError) as caught:
        client.attach(11, allowed_pid=99)
    assert caught.value.code == "permission_denied"
    assert caught.value.details["pid"] == 11
    assert caught.value.details["allowed_pid"] == 99


def test_attach_probe_detaches_immediately_after_success() -> None:
    detached: list[bool] = []

    class _Session:
        def detach(self) -> None:
            detached.append(True)

    class _Frida:
        def attach(self, pid: int) -> _Session:
            return _Session()

    client = _ready_client(_Frida())
    payload = client.attach(4242, allowed_pid=4242)
    assert payload["pid"] == 4242
    assert payload["attached"] is True
    assert payload["device"] == "local"
    assert detached == [True]


def test_require_reports_capability_before_touching_a_backend() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    # pid == allowed_pid so the permission gate passes and the availability
    # gate is the one that fires.
    with pytest.raises(FridaError) as caught:
        client.modules(5, allowed_pid=5)
    assert caught.value.code == "capability_unavailable"


def test_require_permission_gate_fires_before_availability() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.modules(5, allowed_pid=9)
    assert caught.value.code == "permission_denied"


# ---------------------------------------------------------------------------
# modules / exports / memory_read payload shaping and refusals
# ---------------------------------------------------------------------------


def _local_client_with_exports(api: Any) -> FridaClient:
    script = type("_S", (), {"exports_sync": api, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()
    frida = type("_F", (), {"attach": lambda self, pid: session})()
    return _ready_client(frida)


def test_modules_reads_the_dict_shape_with_a_total_larger_than_the_page() -> None:
    """The newer enum script returns {modules, total}; total drives has_more
    even when the page is short."""

    class _Api:
        def modules(self, limit: int) -> dict[str, Any]:
            del limit
            return {
                "modules": [
                    {"name": "libc.so", "base": "0x1", "size": 4, "path": "/x"},
                ],
                "total": 42,
            }

    client = _local_client_with_exports(_Api())
    payload = client.modules(1, allowed_pid=1, limit=10)
    assert payload["count"] == 1
    assert payload["total"] == 42
    assert payload["has_more"] is True
    assert payload["modules"][0]["name"] == "libc.so"


def test_exports_requires_a_module_name() -> None:
    client = _local_client_with_exports(object())
    for bad in ("", "   "):
        with pytest.raises(FridaError) as caught:
            client.exports(1, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"


def test_exports_rejects_a_non_dict_payload_from_the_script() -> None:
    class _Api:
        def exports(self, name: str, count: int) -> list[str]:
            del name, count
            return ["not", "a", "dict"]

    client = _local_client_with_exports(_Api())
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_exports_skips_non_dict_rows_in_the_table() -> None:
    class _Api:
        def exports(self, name: str, count: int) -> dict[str, Any]:
            del count
            return {
                "found": True,
                "module": name,
                "base": "0x1",
                "exports": [
                    {"name": "a", "address": "0x2", "type": "function"},
                    "garbage-row",
                    {"name": "b", "address": "0x3", "type": "function"},
                ],
            }

    client = _local_client_with_exports(_Api())
    payload = client.exports(1, "libc.so", allowed_pid=1)
    assert payload["count"] == 2
    assert [item["name"] for item in payload["exports"]] == ["a", "b"]


def test_memory_read_bounds_the_size_and_returns_hex() -> None:
    class _Api:
        def read(self, address: int, size: int) -> list[int]:
            del address
            return [0xDE, 0xAD, 0xBE, 0xEF][:size]

    client = _local_client_with_exports(_Api())
    for bad in (0, -1, 256 * 1024 + 1, "4"):
        with pytest.raises(FridaError) as caught:
            client.memory_read(1, 0x1000, bad, allowed_pid=1)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"
    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)
    assert payload["encoding"] == "hex"
    assert payload["data"] == "deadbeef"
    assert payload["size"] == 4


# ---------------------------------------------------------------------------
# _attach_local error conversion
# ---------------------------------------------------------------------------


def test_attach_local_wraps_a_generic_failure_as_backend_error() -> None:
    class _Frida:
        def attach(self, pid: int) -> Any:
            raise RuntimeError("no such process")

    client = _ready_client(_Frida())
    with pytest.raises(FridaError) as caught:
        client._attach_local(123)
    assert caught.value.code == "backend_error"
    assert caught.value.details["pid"] == 123


def test_attach_local_reports_a_timeout_named_failure_as_timeout() -> None:
    class _Frida:
        def attach(self, pid: int) -> Any:
            raise RuntimeError("operation timed out")

    client = _ready_client(_Frida())
    with pytest.raises(FridaError) as caught:
        client._attach_local(123)
    assert caught.value.code == "timeout"


# ---------------------------------------------------------------------------
# hook_template (local)
# ---------------------------------------------------------------------------


def test_hook_template_rejects_an_unknown_template() -> None:
    client = _ready_client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "does_not_exist", allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "android_ssl_unpin" in caught.value.details["allowed"]


def test_hook_template_wraps_a_generic_attach_failure_and_reraises() -> None:
    class _Frida:
        def attach(self, pid: int, **kwargs: object) -> Any:
            del kwargs
            raise RuntimeError("boom")

    client = _ready_client(_Frida())
    with pytest.raises(RuntimeError):
        client.hook_template(1, "noop", allowed_pid=1)


def test_hook_template_maps_a_timeout_named_attach_failure_to_timeout() -> None:
    class _Frida:
        def attach(self, pid: int, **kwargs: object) -> Any:
            del kwargs
            raise RuntimeError("attach timed out")

    client = _ready_client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "timeout"


def test_hook_template_reraises_a_frida_error_from_attach_unchanged() -> None:
    class _Frida:
        def attach(self, pid: int, **kwargs: object) -> Any:
            del kwargs
            raise FridaError("permission_denied", "attach blocked by policy")

    client = _ready_client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "permission_denied"


# ---------------------------------------------------------------------------
# _resolve_device branches
# ---------------------------------------------------------------------------


class _Marker:
    def __init__(self, tag: str) -> None:
        self.tag = tag


def test_resolve_device_local_uses_get_local_device() -> None:
    class _Frida:
        def get_local_device(self) -> _Marker:
            return _Marker("local")

    client = _ready_client(_Frida())
    assert client._resolve_device(None).tag == "local"


def test_resolve_device_reuses_a_registered_remote_before_re_adding() -> None:
    class _Manager:
        def get_device(self, device_id: str, timeout: int = 1) -> _Marker:
            del timeout
            return _Marker(f"registered:{device_id}")

        def add_remote_device(self, device_id: str) -> _Marker:  # pragma: no cover
            raise AssertionError("should not re-add a registered device")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _ready_client(_Frida())
    resolved = client._resolve_device("10.0.0.2:27042")
    assert resolved.tag == "registered:10.0.0.2:27042"


def test_resolve_device_adds_a_remote_when_it_is_not_yet_registered() -> None:
    class _Manager:
        def get_device(self, device_id: str, timeout: int = 1) -> _Marker:
            del device_id, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, device_id: str) -> _Marker:
            return _Marker(f"added:{device_id}")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _ready_client(_Frida())
    resolved = client._resolve_device("10.0.0.3:27042")
    assert resolved.tag == "added:10.0.0.3:27042"


def test_resolve_device_falls_through_to_get_device_for_a_plain_id() -> None:
    class _Frida:
        def get_device(self, device_id: str, timeout: int = 5) -> _Marker:
            del timeout
            return _Marker(f"byid:{device_id}")

    client = _ready_client(_Frida())
    assert client._resolve_device("emulator-5554").tag == "byid:emulator-5554"


def test_resolve_device_maps_a_lookup_failure_to_not_found() -> None:
    class _Frida:
        def get_device(self, device_id: str, timeout: int = 5) -> Any:
            del device_id, timeout
            raise RuntimeError("device gone")

    client = _ready_client(_Frida())
    with pytest.raises(FridaError) as caught:
        client._resolve_device("emulator-5554")
    assert caught.value.code == "not_found"
    assert caught.value.details["device_id"] == "emulator-5554"


# ---------------------------------------------------------------------------
# enumerate_devices / add_remote_device / applications failures
# ---------------------------------------------------------------------------


def test_device_operations_report_capability_when_frida_is_missing() -> None:
    """``_need`` is the single gate the device-aware calls share; with no
    module installed every one of them refuses before resolving a device."""
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "capability_unavailable"


def test_enumerate_devices_wraps_a_failure_as_backend_error() -> None:
    class _Frida:
        def enumerate_devices(self) -> Any:
            raise RuntimeError("usb subsystem down")

    client = _ready_client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_wraps_a_generic_add_failure() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            del endpoint, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> Any:
            del endpoint
            raise RuntimeError("connection refused")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _ready_client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("10.0.0.9:27042")
    assert caught.value.code == "backend_error"
    assert caught.value.details["endpoint"] == "10.0.0.9:27042"


def test_applications_wraps_an_enumeration_failure() -> None:
    class _Device:
        def enumerate_applications(self) -> Any:
            raise RuntimeError("frida-server not running")

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# spawn error conversion
# ---------------------------------------------------------------------------


def test_spawn_requires_a_package() -> None:
    client = _ready_client(object())
    client._resolve_device = lambda device_id: object()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")
    assert caught.value.code == "invalid_params"


def test_spawn_wraps_a_spawn_failure_as_backend_error() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            raise RuntimeError("activity not found")

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert caught.value.details["package"] == "com.example.app"


def test_spawn_maps_a_timeout_named_spawn_failure_to_timeout() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            raise RuntimeError("spawn timed out waiting for zygote")

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"


def test_spawn_kills_the_process_when_resume_fails_and_reports_backend_error() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 7777

        def resume(self, pid: int) -> None:
            del pid
            raise RuntimeError("resume rejected")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert killed == [7777]


def test_spawn_kills_and_reports_timeout_when_resume_times_out_inline() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 8888

        def resume(self, pid: int) -> None:
            del pid
            raise RuntimeError("resume timed out")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"
    assert killed == [8888]


def test_spawn_reraises_a_frida_error_from_resume_after_killing() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 9999

        def resume(self, pid: int) -> None:
            del pid
            raise FridaError("permission_denied", "resume blocked")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "permission_denied"
    assert killed == [9999]


# ---------------------------------------------------------------------------
# java_enumerate refusals and error conversion
# ---------------------------------------------------------------------------


def _java_device(*, attach: Any = None, script: Any = None) -> Any:
    if script is None:
        script = type("_S", (), {"exports_sync": object(), "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()

    def _attach(self: Any, pid: int) -> Any:
        if attach is not None:
            return attach(pid)
        return session

    return type("_Dev", (), {"attach": _attach})()


def test_java_enumerate_methods_requires_a_class_name() -> None:
    client = _ready_client(object())
    client._resolve_device = lambda device_id: _java_device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods")
    assert caught.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    class _Api:
        def classes(self, name_filter: str, count: int) -> list[str]:
            return []

    script = type("_S", (), {"exports_sync": _Api(), "load": lambda self: None})()
    client = _ready_client(object())
    client._resolve_device = lambda device_id: _java_device(script=script)  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="dump")
    assert caught.value.code == "invalid_params"


def test_java_enumerate_wraps_an_attach_failure() -> None:
    def _raise(pid: int) -> Any:
        raise RuntimeError("attach denied")

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _java_device(attach=_raise)  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_a_timeout_named_attach_to_timeout() -> None:
    def _raise(pid: int) -> Any:
        raise RuntimeError("attach timed out")

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _java_device(attach=_raise)  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "timeout"


def _script_load_raiser(detached: list[bool], message: str) -> Any:
    class _Script:
        def load(self) -> None:
            raise RuntimeError(message)

    session = type(
        "_Sess",
        (),
        {
            "create_script": lambda self, source: _Script(),
            "detach": lambda self: detached.append(True),
        },
    )()
    return type("_Dev", (), {"attach": lambda self, pid: session})()


def test_java_enumerate_wraps_a_script_load_failure_and_detaches() -> None:
    detached: list[bool] = []
    client = _ready_client(object())
    client._resolve_device = lambda device_id: _script_load_raiser(  # type: ignore[method-assign]
        detached, "script failed to compile"
    )
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"
    # The session is detached in work()'s finally and again in the outer
    # cleanup; both are best-effort and idempotent, so at least one lands.
    assert detached and all(detached)


def test_java_enumerate_maps_a_timeout_named_script_failure_to_timeout() -> None:
    detached: list[bool] = []
    client = _ready_client(object())
    client._resolve_device = lambda device_id: _script_load_raiser(  # type: ignore[method-assign]
        detached, "script load timed out"
    )
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "timeout"
    assert detached


# ---------------------------------------------------------------------------
# hook_template_device refusals and error conversion
# ---------------------------------------------------------------------------


def test_hook_template_device_rejects_an_unknown_template() -> None:
    client = _ready_client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "nope", allowed_pids={1})
    assert caught.value.code == "invalid_params"


def test_hook_template_device_wraps_an_attach_failure() -> None:
    def _raise(pid: int) -> Any:
        raise RuntimeError("attach denied")

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _java_device(attach=_raise)  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})
    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_a_timeout_named_attach_to_timeout() -> None:
    def _raise(pid: int) -> Any:
        raise RuntimeError("attach timed out")

    client = _ready_client(object())
    client._resolve_device = lambda device_id: _java_device(attach=_raise)  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})
    assert caught.value.code == "timeout"


def test_hook_template_device_wraps_a_script_load_failure_and_detaches() -> None:
    detached: list[bool] = []
    client = _ready_client(object())
    client._resolve_device = lambda device_id: _script_load_raiser(  # type: ignore[method-assign]
        detached, "template rejected"
    )
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})
    assert caught.value.code == "backend_error"
    assert detached and all(detached)


def test_hook_template_device_maps_a_timeout_named_script_failure_to_timeout() -> None:
    detached: list[bool] = []
    client = _ready_client(object())
    client._resolve_device = lambda device_id: _script_load_raiser(  # type: ignore[method-assign]
        detached, "script load timed out"
    )
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})
    assert caught.value.code == "timeout"
    assert detached


# ---------------------------------------------------------------------------
# _authorize gates
# ---------------------------------------------------------------------------


def test_authorize_reports_capability_when_frida_is_missing() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client._authorize(1, {1})
    assert caught.value.code == "capability_unavailable"


def test_authorize_rejects_a_non_positive_pid() -> None:
    client = _ready_client(object())
    with pytest.raises(FridaError) as caught:
        client._authorize(0, {0})
    assert caught.value.code == "invalid_params"


def test_authorize_refuses_a_pid_outside_the_allow_set() -> None:
    client = _ready_client(object())
    with pytest.raises(FridaError) as caught:
        client._authorize(5, {1, 2, 3})
    assert caught.value.code == "permission_denied"
    assert caught.value.details["pid"] == 5
    assert caught.value.details["allowed_pids"] == [1, 2, 3]


def test_module_exposes_error_type() -> None:
    assert issubclass(frida_client.FridaError, RuntimeError)
