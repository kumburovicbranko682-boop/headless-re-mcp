"""Frida backend paths the field/honesty suites never reach.

These cover the local single-pid operations (attach, memory_read, the local
hook_template), device resolution for the local / remote / named branches, and
the error contracts every device-aware call funnels non-timeout failures into.
Each assertion pins a code an unattended agent branches on -- a probe that
reported ``backend_error`` where the real answer was ``not_found`` or
``permission_denied`` would send the caller down the wrong recovery path.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _invoke,
    _is_timeout,
)


# ---------------------------------------------------------------------------
# Fakes: a script whose exports_sync is supplied by the test, a session that
# hands it out and records detach, and a frida/device that hands out sessions.
# ---------------------------------------------------------------------------
class _Script:
    def __init__(self, api: object) -> None:
        self.exports_sync = api

    def load(self) -> None:
        return None


class _Session:
    def __init__(self, api: object, detaches: list[int], tag: int = 0) -> None:
        self._api = api
        self._detaches = detaches
        self._tag = tag

    def create_script(self, source: str) -> _Script:
        del source
        return _Script(self._api)

    def detach(self) -> None:
        self._detaches.append(self._tag)


class _Frida:
    """A local frida module: attach(pid) returns a session with a fixed api."""

    def __init__(self, api: object, detaches: list[int]) -> None:
        self._api = api
        self.detaches = detaches
        self.attached: list[int] = []

    def attach(self, pid: int) -> _Session:
        self.attached.append(pid)
        return _Session(self._api, self.detaches, tag=pid)


class _EnumApi:
    """Matches _ENUM_SCRIPT rpc.exports for modules/exports/read."""

    def modules(self, limit: int) -> dict[str, Any]:
        held = [
            {"name": f"m{i}", "base": "0x1", "size": i, "path": f"/lib/m{i}"}
            for i in range(min(limit, 3))
        ]
        return {"modules": held, "total": 42}

    def exports(self, name: str, count: int) -> dict[str, Any]:
        return {
            "found": True,
            "module": name,
            "base": "0x1000",
            # A stray non-dict entry must be skipped, not crash the mapping.
            "exports": [
                {"name": "a", "address": "0x1", "type": "function"},
                "not-a-dict",
                {"name": "b", "address": "0x2", "type": "variable"},
            ],
        }

    def read(self, address: int, size: int) -> list[int]:
        del address
        return list(range(size))


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------
def test_bound_timeout_rejects_non_positive() -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(0)
    assert caught.value.code == "invalid_params"
    with pytest.raises(FridaError):
        _bound_timeout(-5)


def test_accepts_timeout_only_when_named_not_for_kwargs_or_builtins() -> None:
    def names_it(x: int, timeout: float = 1.0) -> None:
        del x, timeout

    def kwargs_only(*args: object, **kwargs: object) -> None:
        del args, kwargs

    assert _accepts_timeout(names_it) is True
    assert _accepts_timeout(kwargs_only) is False
    # A callable whose signature cannot be introspected (``range`` raises
    # ValueError) must fall back to False rather than raise, so _invoke never
    # forwards a deadline frida cannot take.
    assert _accepts_timeout(range) is False


def test_invoke_forwards_timeout_only_to_methods_that_name_it() -> None:
    seen: dict[str, Any] = {}

    def names_it(value: int, timeout: float | None = None) -> int:
        seen["timeout"] = timeout
        return value

    assert _invoke(names_it, 7, timeout=3.0) == 7
    assert seen["timeout"] == 3.0

    def kwargs_only(value: int, **kwargs: object) -> int:
        seen["kwargs"] = dict(kwargs)
        return value

    assert _invoke(kwargs_only, 9, timeout=3.0) == 9
    assert seen["kwargs"] == {}


def test_is_timeout_matches_on_type_name_or_message() -> None:
    class Timeoutish(Exception):
        pass

    assert _is_timeout(Timeoutish()) is True
    assert _is_timeout(RuntimeError("the call timed out")) is True
    assert _is_timeout(RuntimeError("connection refused")) is False


# ---------------------------------------------------------------------------
# Local single-pid operations
# ---------------------------------------------------------------------------
def test_attach_rejects_when_unavailable_bad_pid_or_wrong_pid() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as unavailable:
        client.attach(1, allowed_pid=1)
    assert unavailable.value.code == "capability_unavailable"

    client._available = True
    client._frida = _Frida(_EnumApi(), [])
    with pytest.raises(FridaError) as bad_pid:
        client.attach(0, allowed_pid=0)
    assert bad_pid.value.code == "invalid_params"
    with pytest.raises(FridaError) as bool_pid:
        client.attach(True, allowed_pid=True)  # type: ignore[arg-type]
    assert bool_pid.value.code == "invalid_params"
    with pytest.raises(FridaError) as wrong:
        client.attach(2, allowed_pid=1)
    assert wrong.value.code == "permission_denied"
    assert wrong.value.details["allowed_pid"] == 1


def test_attach_probe_returns_and_detaches_immediately() -> None:
    detaches: list[int] = []
    frida = _Frida(_EnumApi(), detaches)
    client = FridaClient()
    client._available = True
    client._frida = frida
    payload = client.attach(1234, allowed_pid=1234)
    assert payload["attached"] is True
    assert payload["pid"] == 1234
    assert payload["device"] == "local"
    # The probe must not stay resident: attach() detaches in its finally.
    assert detaches == [1234]


def test_modules_reads_the_dict_shape_with_total() -> None:
    client = FridaClient()
    client._available = True
    client._frida = _Frida(_EnumApi(), [])
    payload = client.modules(1, allowed_pid=1, limit=64)
    assert payload["count"] == 3
    assert payload["total"] == 42
    assert payload["has_more"] is True
    assert payload["modules"][0]["path"] == "/lib/m0"


def test_exports_requires_module_name_and_skips_non_dict_rows() -> None:
    client = FridaClient()
    client._available = True
    client._frida = _Frida(_EnumApi(), [])
    with pytest.raises(FridaError) as caught:
        client.exports(1, "   ", allowed_pid=1)
    assert caught.value.code == "invalid_params"

    payload = client.exports(1, "libc.so", allowed_pid=1, limit=64)
    assert payload["found"] is True
    assert payload["module"] == "libc.so"
    # The "not-a-dict" row was dropped, not counted.
    assert payload["count"] == 2
    assert [e["name"] for e in payload["exports"]] == ["a", "b"]


def test_exports_rejects_a_non_dict_payload() -> None:
    class _BadApi:
        def exports(self, name: str, count: int) -> list[int]:
            del name, count
            return [1, 2, 3]

    client = FridaClient()
    client._available = True
    client._frida = _Frida(_BadApi(), [])
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_memory_read_returns_hex_and_bounds_the_size() -> None:
    client = FridaClient()
    client._available = True
    client._frida = _Frida(_EnumApi(), [])
    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)
    assert payload["encoding"] == "hex"
    assert payload["address"] == 0x1000
    assert payload["size"] == 4
    assert payload["data"] == "00010203"

    for bad in (0, 256 * 1024 + 1):
        with pytest.raises(FridaError) as caught:
            client.memory_read(1, 0x1000, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"


def test_local_hook_template_rejects_unknown_and_loads_a_known_one() -> None:
    detaches: list[int] = []
    client = FridaClient()
    client._available = True
    client._frida = _Frida(_EnumApi(), detaches)
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "does_not_exist", allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "android_ssl_unpin" in caught.value.details["allowed"]

    payload = client.hook_template(1, "noop", allowed_pid=1)
    assert payload["loaded"] is True
    assert payload["template"] == "noop"
    # A probe hook does not persist: it says so and detaches.
    assert payload["persisted"] is False
    assert detaches == [1]


def test_local_hook_template_surfaces_a_non_timeout_load_failure() -> None:
    class _BoomScript:
        def load(self) -> None:
            raise RuntimeError("script compile failed")

    class _BoomSession:
        def create_script(self, source: str) -> _BoomScript:
            del source
            return _BoomScript()

        def detach(self) -> None:
            return None

    class _BoomFrida:
        def attach(self, pid: int) -> _BoomSession:
            del pid
            return _BoomSession()

    client = FridaClient()
    client._available = True
    client._frida = _BoomFrida()
    with pytest.raises(RuntimeError):
        client.hook_template(1, "noop", allowed_pid=1)


def test_attach_local_wraps_a_non_timeout_failure_as_backend_error() -> None:
    class _RefusingFrida:
        def attach(self, pid: int) -> Any:
            del pid
            raise RuntimeError("device offline")

    client = FridaClient()
    client._available = True
    client._frida = _RefusingFrida()
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "backend_error"
    assert caught.value.details["pid"] == 1


def test_attach_local_times_out_and_detaches() -> None:
    detaches: list[int] = []

    class _HangFrida:
        def attach(self, pid: int) -> _Session:
            time.sleep(10)
            return _Session(_EnumApi(), detaches, tag=pid)

    client = FridaClient()
    client._available = True
    client._frida = _HangFrida()
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        # attach() defaults its deadline at definition time, so the bound must
        # be passed explicitly to be enforced here.
        client.attach(1, allowed_pid=1, timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"


def test_require_reports_capability_unavailable_when_module_missing() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# Device resolution
# ---------------------------------------------------------------------------
class _Dev:
    def __init__(self, ident: str) -> None:
        self.id = ident
        self.name = ident
        self.type = "usb"


def test_resolve_device_local_default() -> None:
    class _F:
        def get_local_device(self) -> _Dev:
            return _Dev("local")

    client = FridaClient()
    client._available = True
    client._frida = _F()
    for alias in (None, "", "local"):
        assert client._resolve_device(alias).id == "local"


def test_resolve_device_named_uses_get_device() -> None:
    class _F:
        def get_device(self, device_id: str, timeout: int = 5) -> _Dev:
            del timeout
            return _Dev(device_id)

    client = FridaClient()
    client._available = True
    client._frida = _F()
    assert client._resolve_device("emulator-5554").id == "emulator-5554"


def test_resolve_device_remote_prefers_registered_then_adds() -> None:
    class _Mgr:
        def __init__(self, registered: bool) -> None:
            self._registered = registered
            self.added = 0

        def get_device(self, device_id: str, timeout: int = 1) -> _Dev:
            del timeout
            if not self._registered:
                raise RuntimeError("not registered")
            return _Dev(device_id)

        def add_remote_device(self, device_id: str) -> _Dev:
            self.added += 1
            return _Dev(device_id)

    class _F:
        def __init__(self, registered: bool) -> None:
            self._mgr = _Mgr(registered)

        def get_device_manager(self) -> _Mgr:
            return self._mgr

    reused = FridaClient()
    reused._available = True
    reused._frida = _F(registered=True)
    assert reused._resolve_device("10.0.0.1:27042").id == "10.0.0.1:27042"
    assert reused._frida._mgr.added == 0

    added = FridaClient()
    added._available = True
    added._frida = _F(registered=False)
    assert added._resolve_device("10.0.0.1:27042").id == "10.0.0.1:27042"
    assert added._frida._mgr.added == 1


def test_resolve_device_maps_a_lookup_failure_to_not_found() -> None:
    class _F:
        def get_local_device(self) -> _Dev:
            raise RuntimeError("no local device")

    client = FridaClient()
    client._available = True
    client._frida = _F()
    with pytest.raises(FridaError) as caught:
        client._resolve_device(None)
    assert caught.value.code == "not_found"
    assert caught.value.details["device_id"] is None


def test_resolve_device_requires_the_module() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client._resolve_device("usb")
    assert caught.value.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# Device-aware enumeration error contracts
# ---------------------------------------------------------------------------
def test_enumerate_devices_maps_failure_to_backend_error() -> None:
    class _F:
        def enumerate_devices(self) -> list[Any]:
            raise RuntimeError("frida-server down")

    client = FridaClient()
    client._available = True
    client._frida = _F()
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_maps_failure_to_backend_error() -> None:
    class _Mgr:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            raise RuntimeError("nope")

        def add_remote_device(self, endpoint: str) -> Any:
            raise RuntimeError("connection refused")

    class _F:
        def get_device_manager(self) -> _Mgr:
            return _Mgr()

    client = FridaClient()
    client._available = True
    client._frida = _F()
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("10.0.0.1:27042")
    assert caught.value.code == "backend_error"
    assert caught.value.details["endpoint"] == "10.0.0.1:27042"


def test_applications_maps_failure_to_backend_error() -> None:
    class _Device:
        def enumerate_applications(self) -> list[Any]:
            raise RuntimeError("no apps")

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# spawn error branches
# ---------------------------------------------------------------------------
def test_spawn_requires_a_package_after_resolving_the_device() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            return 1

        def resume(self, pid: int) -> None:
            return None

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")
    assert caught.value.code == "invalid_params"


def test_spawn_maps_a_spawn_failure_to_backend_error() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            del package
            raise RuntimeError("activity not found")

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert caught.value.details["package"] == "com.example.app"


def test_spawn_kills_the_process_when_resume_fails() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 555

        def resume(self, pid: int) -> None:
            del pid
            raise RuntimeError("resume rejected")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert "resume failed" in caught.value.message
    assert killed == [555]


# ---------------------------------------------------------------------------
# java_enumerate and hook_template_device error branches
# ---------------------------------------------------------------------------
def _device_that_attach_raises(exc: Exception) -> object:
    class _Device:
        def attach(self, pid: int) -> Any:
            del pid
            raise exc

    return _Device()


def test_java_enumerate_maps_attach_failure_to_backend_error() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = (  # type: ignore[method-assign]
        lambda device_id: _device_that_attach_raises(RuntimeError("gone"))
    )
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"


def test_java_enumerate_methods_requires_class_name() -> None:
    class _Api:
        def classes(self, name_filter: str, count: int) -> list[str]:
            return []

        def methods(self, class_name: str, count: int) -> dict[str, Any]:
            return {"found": True, "methods": []}

    detaches: list[int] = []

    class _Device:
        def attach(self, pid: int) -> _Session:
            return _Session(_Api(), detaches, tag=pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods")
    assert caught.value.code == "invalid_params"
    # A bad mode is refused too.
    with pytest.raises(FridaError) as bad_mode:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="fields")
    assert bad_mode.value.code == "invalid_params"


def test_hook_template_device_rejects_unknown_and_maps_attach_failure() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = (  # type: ignore[method-assign]
        lambda device_id: _device_that_attach_raises(RuntimeError("gone"))
    )
    with pytest.raises(FridaError) as unknown:
        client.hook_template_device("usb", 1, "nope", allowed_pids={1})
    assert unknown.value.code == "invalid_params"

    with pytest.raises(FridaError) as attach_fail:
        client.hook_template_device("usb", 1, "noop", allowed_pids={1})
    assert attach_fail.value.code == "backend_error"


def test_hook_template_device_loads_a_known_template() -> None:
    detaches: list[int] = []

    class _Device:
        def attach(self, pid: int) -> _Session:
            return _Session(_EnumApi(), detaches, tag=pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    payload = client.hook_template_device(
        "usb", 7, "android_ssl_unpin", allowed_pids={7}
    )
    assert payload["loaded"] is True
    assert payload["template"] == "android_ssl_unpin"
    assert payload["device"] == "usb"
    assert payload["persisted"] is False
    assert detaches == [7]


class _TimeoutExc(Exception):
    """Named so _is_timeout treats it as a deadline hit, without a real sleep."""


def test_attach_local_maps_a_timeout_named_failure_to_timeout() -> None:
    detaches: list[int] = []

    class _F:
        def attach(self, pid: int) -> Any:
            del pid
            raise _TimeoutExc("operation timed out")

    client = FridaClient()
    client._available = True
    client._frida = _F()
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "timeout"
    assert detaches == []


def test_local_hook_template_maps_a_timeout_named_load_to_timeout() -> None:
    class _HangScript:
        def load(self) -> None:
            raise _TimeoutExc("load timed out")

    class _Sess:
        def create_script(self, source: str) -> _HangScript:
            del source
            return _HangScript()

        def detach(self) -> None:
            return None

    class _F:
        def attach(self, pid: int) -> _Sess:
            del pid
            return _Sess()

    client = FridaClient()
    client._available = True
    client._frida = _F()
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "timeout"


def test_spawn_maps_a_timeout_named_spawn_to_timeout() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            del package
            raise _TimeoutExc("spawn timed out")

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"


def test_spawn_kills_and_reraises_a_frida_error_from_resume() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 900

        def resume(self, pid: int) -> None:
            del pid
            raise FridaError("permission_denied", "resume refused")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    # The original FridaError code is preserved, and the process is not left
    # running behind a failed resume.
    assert caught.value.code == "permission_denied"
    assert killed == [900]


def test_spawn_kills_and_reports_timeout_when_resume_times_out() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 901

        def resume(self, pid: int) -> None:
            del pid
            raise _TimeoutExc("resume timed out")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = FridaClient()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"
    assert killed == [901]


def test_java_enumerate_maps_a_timeout_named_attach_to_timeout() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = (  # type: ignore[method-assign]
        lambda device_id: _device_that_attach_raises(_TimeoutExc("attach timed out"))
    )
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "timeout"


def test_java_enumerate_detaches_when_the_script_raises() -> None:
    detaches: list[int] = []

    class _Api:
        def classes(self, name_filter: str, count: int) -> list[str]:
            raise RuntimeError("enumerateLoadedClasses failed")

    class _Device:
        def attach(self, pid: int) -> _Session:
            return _Session(_Api(), detaches, tag=pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 5, allowed_pids={5}, mode="classes")
    assert caught.value.code == "backend_error"
    # The session is torn down even though the failure came from the script;
    # only this pid's session is touched (the finally and the error handler may
    # each detach it, which frida tolerates).
    assert detaches and set(detaches) == {5}


def test_hook_template_device_detaches_when_the_script_raises() -> None:
    detaches: list[int] = []

    class _BoomScript:
        def load(self) -> None:
            raise RuntimeError("compile failed")

    class _Sess:
        def __init__(self, tag: int) -> None:
            self._tag = tag

        def create_script(self, source: str) -> _BoomScript:
            del source
            return _BoomScript()

        def detach(self) -> None:
            detaches.append(self._tag)

    class _Device:
        def attach(self, pid: int) -> _Sess:
            return _Sess(pid)

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 6, "noop", allowed_pids={6})
    assert caught.value.code == "backend_error"
    assert detaches and set(detaches) == {6}


def test_authorize_reports_unavailable_and_bad_pid() -> None:
    unavailable = FridaClient()
    unavailable._available = False
    unavailable._frida = None
    with pytest.raises(FridaError) as caught:
        unavailable._authorize(1, {1})
    assert caught.value.code == "capability_unavailable"

    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as bad_pid:
        client._authorize(0, {0})
    assert bad_pid.value.code == "invalid_params"
    with pytest.raises(FridaError) as not_allowed:
        client._authorize(9, {1, 2})
    assert not_allowed.value.code == "permission_denied"
    assert not_allowed.value.details["allowed_pids"] == [1, 2]
