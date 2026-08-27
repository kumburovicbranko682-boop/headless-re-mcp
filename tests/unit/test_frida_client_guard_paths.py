"""Frida backend guard, error and honesty branches.

The device-aware Frida surface (Android) leans on live USB / emulator gates
that skip on a machine without a device, so its failure contract -- the paths
that turn a wedged attach, a missing module, a bad package id or an unauthorized
pid into a structured ``FridaError`` rather than an exception or a false success
-- was thin under unit coverage. These exercise those branches with mocks so the
honesty properties hold on every runtime, not only where a phone is plugged in.
"""

from __future__ import annotations

import sys
import time
from typing import Any

import pytest

from headless_re_mcp.backends.frida import client as frida_client
from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _invoke,
    _is_timeout,
    _page,
)
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT


# ----------------------------------------------------------------------
# Module-level helpers.
# ----------------------------------------------------------------------
def test_page_distinguishes_a_full_page_from_the_whole_list() -> None:
    """One extra element means "there is more"; exactly the page means "that is all"."""
    page, has_more = _page([1, 2, 3], 2)
    assert page == [1, 2]
    assert has_more is True
    page, has_more = _page([1, 2], 2)
    assert page == [1, 2]
    assert has_more is False
    # A None list is the empty list, not a crash.
    assert _page(None, 5) == ([], False)


def test_is_timeout_matches_by_type_name_or_message() -> None:
    assert _is_timeout(TimeoutError("x")) is True
    assert _is_timeout(RuntimeError("operation timed out")) is True
    assert _is_timeout(RuntimeError("unrelated")) is False


def test_accepts_timeout_names_the_param_not_merely_kwargs() -> None:
    """spawn takes ``**kwargs`` for aux options -- a deadline there is not a bound."""

    def with_timeout(pid: int, timeout: float = 1.0) -> None:  # pragma: no cover - probe
        del pid, timeout

    def only_kwargs(pid: int, **kwargs: Any) -> None:  # pragma: no cover - probe
        del pid, kwargs

    assert _accepts_timeout(with_timeout) is True
    assert _accepts_timeout(only_kwargs) is False
    # A builtin whose signature cannot be read is treated as not accepting one,
    # rather than raising while deciding whether to pass a deadline.
    assert _accepts_timeout(print) is False
    # A non-callable makes signature() raise TypeError; the same fail-safe holds.
    assert _accepts_timeout(object()) is False


def test_invoke_only_passes_timeout_when_the_callable_names_it() -> None:
    seen: dict[str, Any] = {}

    def with_timeout(pid: int, *, timeout: float = 0.0) -> str:
        seen["timeout"] = timeout
        return "ok"

    def without_timeout(pid: int) -> str:
        return "ok"

    assert _invoke(with_timeout, 1, timeout=5.0) == "ok"
    assert seen["timeout"] == 5.0
    # No timeout kwarg leaks to a callable that does not name it.
    assert _invoke(without_timeout, 1, timeout=5.0) == "ok"


def test_bound_timeout_rejects_non_positive_and_clamps_to_the_ceiling() -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(0)
    assert caught.value.code == "invalid_params"
    with pytest.raises(FridaError):
        _bound_timeout(-1)
    assert _bound_timeout(MAX_WORKFLOW_TIMEOUT * 10) == MAX_WORKFLOW_TIMEOUT
    assert _bound_timeout(1.5) == 1.5


def test_client_reports_unavailable_when_the_frida_module_will_not_import(
    monkeypatch: Any,
) -> None:
    """A checkout without the android extra must degrade, not crash on construct.

    Setting the module to None in sys.modules makes ``import frida`` raise, which
    is the same shape as the extra being absent. The client swallows it and
    reports ``available`` False so callers get ``capability_unavailable`` rather
    than an import traceback at construction.
    """
    monkeypatch.setitem(sys.modules, "frida", None)
    client = FridaClient()
    assert client.available is False
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "capability_unavailable"


# ----------------------------------------------------------------------
# Local-device attach path (PE sessions).
# ----------------------------------------------------------------------
def test_attach_refuses_before_it_ever_touches_the_target() -> None:
    """Capability, type and permission checks come before any attach call."""
    unavailable = FridaClient()
    unavailable._available = False
    unavailable._frida = None
    with pytest.raises(FridaError) as caught:
        unavailable.attach(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"

    client = FridaClient()
    client._available = True
    client._frida = object()
    for bad in (0, -3, True):
        with pytest.raises(FridaError) as caught:
            client.attach(bad, allowed_pid=bad)  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"

    with pytest.raises(FridaError) as caught:
        client.attach(11, allowed_pid=22)
    assert caught.value.code == "permission_denied"
    assert caught.value.details["allowed_pid"] == 22


def test_attach_detaches_the_probe_session_after_reporting_success() -> None:
    """attach is a probe: it must not leave an agent resident in the target."""
    detached: list[bool] = []

    class _Session:
        def detach(self) -> None:
            detached.append(True)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid, timeout=0.0: _Session()  # type: ignore[method-assign]
    payload = client.attach(7, allowed_pid=7)
    assert payload == {
        "pid": 7,
        "attached": True,
        "device": "local",
        "note": "probe attach; detached immediately",
    }
    assert detached == [True]


def test_attach_local_wraps_a_driver_failure_as_backend_error() -> None:
    class _Boom:
        def attach(self, pid: int) -> Any:
            raise RuntimeError("no such process")

    client = FridaClient()
    client._available = True
    client._frida = _Boom()
    with pytest.raises(FridaError) as caught:
        client._attach_local(999)
    assert caught.value.code == "backend_error"
    assert caught.value.details["pid"] == 999


def test_attach_local_maps_a_wedged_attach_to_timeout(monkeypatch: Any) -> None:
    monkeypatch.setattr(frida_client, "_PROBE_TIMEOUT_S", 0.2)

    class _Wedged:
        def attach(self, pid: int) -> Any:
            time.sleep(10)
            return object()

    client = FridaClient()
    client._available = True
    client._frida = _Wedged()
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client._attach_local(1, timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"


# ----------------------------------------------------------------------
# Enumeration honesty on the local path.
# ----------------------------------------------------------------------
class _DictExports:
    def modules(self, limit: int) -> dict[str, Any]:
        return {
            "modules": [
                {"name": "libc.so", "base": "0x1", "size": 10, "path": "/lib/libc.so"}
            ],
            "total": 42,
        }


def _local_client_with(exports: Any) -> FridaClient:
    script = type("_S", (), {"exports_sync": exports, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, src: script, "detach": lambda self: None},
    )()
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._attach_local = lambda pid, timeout=0.0: session  # type: ignore[method-assign]
    return client


def test_modules_reads_total_from_the_script_dict_shape() -> None:
    """The dict shape carries the real total, so has_more reflects the device."""
    client = _local_client_with(_DictExports())
    payload = client.modules(1, allowed_pid=1, limit=64)
    assert payload["count"] == 1
    assert payload["total"] == 42
    assert payload["has_more"] is True


def test_exports_requires_a_module_name() -> None:
    client = _local_client_with(object())
    for bad in ("", "   "):
        with pytest.raises(FridaError) as caught:
            client.exports(1, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"


def test_exports_rejects_a_payload_that_is_not_a_dict() -> None:
    """A bare list has no ``found`` flag; treating it as exports would lie."""

    class _BadExports:
        def exports(self, name: str, count: int) -> list[Any]:
            return []

    client = _local_client_with(_BadExports())
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_memory_read_bounds_the_size() -> None:
    client = _local_client_with(object())
    for bad in (0, -1, 256 * 1024 + 1):
        with pytest.raises(FridaError) as caught:
            client.memory_read(1, 0x1000, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"


def test_memory_read_returns_hex_encoded_bytes() -> None:
    """The happy path names an encoding and hex-encodes the bytes it read."""

    class _ReadApi:
        def read(self, address: int, size: int) -> list[int]:
            return [0xDE, 0xAD, 0xBE, 0xEF][:size]

    client = _local_client_with(_ReadApi())
    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)
    assert payload["encoding"] == "hex"
    assert payload["data"] == "deadbeef"
    assert payload["address"] == 0x1000
    assert payload["size"] == 4


def test_require_reports_unavailable_after_the_pid_check_passes() -> None:
    """pid matches, but the module is absent, so the read degrades cleanly."""
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


# ----------------------------------------------------------------------
# hook_template (local).
# ----------------------------------------------------------------------
def test_hook_template_rejects_an_unknown_name_and_lists_the_allowed_set() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "not_a_template", allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "android_ssl_unpin" in caught.value.details["allowed"]


def test_hook_template_discloses_that_the_probe_does_not_persist() -> None:
    """A hook is meant to outlive the call; a probe detach destroys it.

    The reply says so rather than implying a hook that stopped existing before
    the caller could read the result.
    """

    class _Session:
        def create_script(self, src: str) -> Any:
            return type("_S", (), {"load": lambda self: None})()

        def detach(self) -> None:
            return None

    class _Frida:
        def attach(self, pid: int) -> Any:
            return _Session()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    payload = client.hook_template(3, "noop", allowed_pid=3)
    assert payload["loaded"] is True
    assert payload["persisted"] is False
    assert "destroyed" in payload["note"]


def test_hook_template_maps_a_wedged_load_to_timeout_and_detaches() -> None:
    """A script.load that hangs must not park the worker; the probe detaches."""
    detached: list[bool] = []

    class _Script:
        def load(self) -> None:
            raise RuntimeError("operation timed out")

    class _Session:
        def create_script(self, src: str) -> _Script:
            return _Script()

        def detach(self) -> None:
            detached.append(True)

    class _Frida:
        def attach(self, pid: int) -> _Session:
            return _Session()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client.hook_template(3, "noop", allowed_pid=3)
    assert caught.value.code == "timeout"
    assert detached  # the probe detached rather than leaving the session live


# ----------------------------------------------------------------------
# Device resolution.
# ----------------------------------------------------------------------
class _Dev:
    def __init__(self, ident: str = "d", name: str = "n", kind: str = "usb") -> None:
        self.id = ident
        self.name = name
        self.type = kind


def test_resolve_device_reuses_a_registered_remote_before_re_adding() -> None:
    """A host:port already known is fetched, not re-added on every call."""

    class _Manager:
        def __init__(self) -> None:
            self.added = 0

        def get_device(self, endpoint: str, timeout: int = 1) -> _Dev:
            return _Dev(endpoint, "remote", "remote")

        def add_remote_device(self, endpoint: str) -> _Dev:  # pragma: no cover - probe
            self.added += 1
            return _Dev(endpoint)

    class _Frida:
        def __init__(self) -> None:
            self.manager = _Manager()

        def get_device_manager(self) -> _Manager:
            return self.manager

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    device = client._resolve_device("10.0.0.1:27042")
    assert device.id == "10.0.0.1:27042"
    assert client._frida.manager.added == 0


def test_resolve_device_adds_a_remote_when_not_yet_registered() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> _Dev:
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> _Dev:
            return _Dev(endpoint, "remote", "remote")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    device = client._resolve_device("10.0.0.2:27042")
    assert device.type == "remote"


def test_resolve_device_uses_get_device_for_a_plain_id() -> None:
    class _Frida:
        def get_device(self, device_id: str, timeout: int = 5) -> _Dev:
            return _Dev(device_id, "emu", "emulator")

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    device = client._resolve_device("emulator-5554")
    assert device.id == "emulator-5554"


def test_resolve_device_maps_an_unknown_device_to_not_found() -> None:
    class _Frida:
        def get_local_device(self) -> Any:
            raise RuntimeError("no local device")

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client._resolve_device("local")
    assert caught.value.code == "not_found"
    assert caught.value.details["device_id"] == "local"


def test_enumerate_devices_wraps_driver_failure_as_backend_error() -> None:
    class _Frida:
        def enumerate_devices(self) -> Any:
            raise RuntimeError("frida-core down")

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_wraps_manager_failure_as_backend_error() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            raise RuntimeError("no")

        def add_remote_device(self, endpoint: str) -> Any:
            raise RuntimeError("refused")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("1.2.3.4:1")
    assert caught.value.code == "backend_error"
    assert caught.value.details["endpoint"] == "1.2.3.4:1"


def test_applications_wraps_enumeration_failure_as_backend_error() -> None:
    class _Device:
        def enumerate_applications(self) -> Any:
            raise RuntimeError("device busy")

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"


# ----------------------------------------------------------------------
# spawn.
# ----------------------------------------------------------------------
def test_spawn_requires_a_non_empty_package() -> None:
    client = FridaClient()
    client._resolve_device = lambda device_id: _Dev()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")
    assert caught.value.code == "invalid_params"


def test_spawn_wraps_a_spawn_failure_as_backend_error() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            raise RuntimeError("package not installed")

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"


def test_spawn_kills_the_process_when_resume_fails() -> None:
    """A spawned-but-not-resumed pid must not be left running.

    resume raising a non-timeout error still kills the pid before surfacing the
    failure, so a failed launch does not leak a suspended process on the device.
    """
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            return 5150

        def resume(self, pid: int) -> None:
            raise RuntimeError("resume rejected")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert killed == [5150]


# ----------------------------------------------------------------------
# java_enumerate and hook_template_device validation.
# ----------------------------------------------------------------------
def _device_client(device: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


def test_java_methods_requires_a_class_name() -> None:
    class _Api:
        def methods(self, class_name: str, limit: int) -> dict[str, Any]:  # pragma: no cover
            return {"found": True, "methods": []}

    script = type("_S", (), {"exports_sync": _Api(), "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, src: script, "detach": lambda self: None},
    )()
    device = type("_D", (), {"attach": lambda self, pid: session})()
    client = _device_client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods")
    assert caught.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    script = type("_S", (), {"exports_sync": object(), "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, src: script, "detach": lambda self: None},
    )()
    device = type("_D", (), {"attach": lambda self, pid: session})()
    client = _device_client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="fields")
    assert caught.value.code == "invalid_params"


def test_java_enumerate_wraps_an_attach_failure_as_backend_error() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            raise RuntimeError("no gadget")

    client = _device_client(_Device())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"


def test_java_enumerate_wraps_a_generic_script_failure_and_detaches() -> None:
    """A non-timeout script failure surfaces as backend_error, session detached."""
    detached: list[bool] = []

    class _Script:
        def load(self) -> None:
            raise RuntimeError("script compile error")

    class _Session:
        def create_script(self, src: str) -> _Script:
            return _Script()

        def detach(self) -> None:
            detached.append(True)

    class _Device:
        def attach(self, pid: int) -> _Session:
            return _Session()

    client = _device_client(_Device())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"
    assert "java enumeration failed" in caught.value.message
    assert detached


def test_hook_template_device_rejects_an_unknown_template() -> None:
    client = _device_client(_Dev())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "bogus", allowed_pids={1})
    assert caught.value.code == "invalid_params"


def test_hook_template_device_wraps_an_attach_failure_as_backend_error() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            raise RuntimeError("no gadget")

    client = _device_client(_Device())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})
    assert caught.value.code == "backend_error"


def test_hook_template_device_wraps_a_generic_load_failure_and_detaches() -> None:
    detached: list[bool] = []

    class _Script:
        def load(self) -> None:
            raise RuntimeError("script rejected")

    class _Session:
        def create_script(self, src: str) -> _Script:
            return _Script()

        def detach(self) -> None:
            detached.append(True)

    class _Device:
        def attach(self, pid: int) -> _Session:
            return _Session()

    client = _device_client(_Device())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})
    assert caught.value.code == "backend_error"
    assert "hook template failed" in caught.value.message
    assert detached


# ----------------------------------------------------------------------
# _authorize.
# ----------------------------------------------------------------------
def test_authorize_checks_availability_pid_shape_and_allow_set() -> None:
    unavailable = FridaClient()
    unavailable._available = False
    unavailable._frida = None
    with pytest.raises(FridaError) as caught:
        unavailable._authorize(1, {1})
    assert caught.value.code == "capability_unavailable"

    client = FridaClient()
    client._available = True
    client._frida = object()
    for bad in (0, -1, True):
        with pytest.raises(FridaError) as caught:
            client._authorize(bad, {1})  # type: ignore[arg-type]
        assert caught.value.code == "invalid_params"

    with pytest.raises(FridaError) as caught:
        client._authorize(99, {1, 2})
    assert caught.value.code == "permission_denied"
    assert caught.value.details["allowed_pids"] == [1, 2]
