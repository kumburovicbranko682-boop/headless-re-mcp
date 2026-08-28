"""Guard, error and payload-shape branches of the Frida client.

The field and timeout tests around this backend cover the happy path and the
deadline backstop. What they leave unexercised are the branches that decide
whether a call is even allowed to touch a device, and the ones that translate a
raw frida failure into a structured envelope. Those are exactly the branches an
unattended agent leans on: a wrong pid must be refused rather than attached, a
wedged lookup must surface ``not_found`` rather than a bare exception, and a
partial spawn must clean up the pid it created. Each test here pins one such
branch so a regression that swallows the refusal or the cleanup fails loudly.

The frida native runtime cannot run in CI, so every device / session / script
here is a stand-in that returns or raises exactly what the real object would at
that seam; the client logic under test is Python either way.
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
    _page,
)
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT


def _client(device: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


# ---------------------------------------------------------------------------
# Module-level helpers.
# ---------------------------------------------------------------------------
def test_page_returns_everything_when_the_list_fits() -> None:
    """A short list is the whole list; has_more must read False.

    _page asks for one more than the page precisely so a full page can be told
    apart from "that is all there is". When the list is under the limit there is
    nothing left over, and the second field has to say so or a caller paginates
    past the end.
    """
    page, has_more = _page([1, 2, 3], 10)
    assert page == [1, 2, 3]
    assert has_more is False


def test_page_treats_none_as_empty() -> None:
    """A backend that answered with null instead of [] must not crash paging."""
    page, has_more = _page(None, 10)
    assert page == []
    assert has_more is False


def test_bound_timeout_rejects_a_non_positive_deadline() -> None:
    """A zero or negative timeout is a caller error, not an unbounded wait."""
    for value in (0.0, -1.0):
        with pytest.raises(FridaError) as caught:
            _bound_timeout(value)
        assert caught.value.code == "invalid_params"


def test_bound_timeout_caps_at_the_workflow_ceiling() -> None:
    """No caller can ask a probe to park a worker past the workflow ceiling."""
    assert _bound_timeout(MAX_WORKFLOW_TIMEOUT * 10) == MAX_WORKFLOW_TIMEOUT
    assert _bound_timeout(1.5) == 1.5


def test_accepts_timeout_is_false_for_an_uninspectable_callable() -> None:
    """A callable whose signature cannot be read is treated as not naming
    timeout, so _invoke never forwards a deadline frida would read as a spawn
    argument.
    """
    assert _accepts_timeout(object()) is False

    def names_timeout(a: int, timeout: float = 0.0) -> int:
        return a

    def does_not(a: int) -> int:
        return a

    assert _accepts_timeout(names_timeout) is True
    assert _accepts_timeout(does_not) is False


def test_invoke_omits_timeout_when_the_method_does_not_name_it() -> None:
    """_invoke forwards timeout only to methods that declare it.

    Frida's spawn takes ``**kwargs`` for aux options, so a stray ``timeout``
    would silently become a spawn argument. A method that names no timeout must
    be called with exactly the positional arguments it was given.
    """
    seen: dict[str, Any] = {}

    def method(value: int, **kwargs: Any) -> int:
        seen.update(kwargs)
        return value

    # method takes **kwargs but does not *name* timeout, so it must not receive it.
    assert _invoke(method, 7, timeout=5.0) == 7
    assert "timeout" not in seen

    def with_timeout(value: int, timeout: float = 0.0) -> float:
        return timeout

    assert _invoke(with_timeout, 1, timeout=3.0) == 3.0


def test_is_timeout_matches_by_type_name_or_message() -> None:
    class _Timeoutish(Exception):
        pass

    assert _is_timeout(_Timeoutish()) is True
    assert _is_timeout(RuntimeError("operation timed out")) is True
    assert _is_timeout(RuntimeError("connection refused")) is False


# ---------------------------------------------------------------------------
# Availability: frida not importable.
# ---------------------------------------------------------------------------
def test_client_without_frida_reports_unavailable(monkeypatch: Any) -> None:
    """A missing frida module must degrade to capability_unavailable, not crash.

    The import lives in __init__ so a host without the android extra still gets
    a usable client object; every entry point then answers with a structured
    envelope rather than an ImportError leaking through the tool boundary.
    """
    import builtins

    real_import = builtins.__import__

    def deny_frida(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "frida":
            raise ImportError("no frida here")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny_frida)
    client = FridaClient()
    assert client.available is False
    for call in (
        lambda: client.attach(1, allowed_pid=1),
        lambda: client.enumerate_devices(),
        lambda: client._need(),
        lambda: client._authorize(1, {1}),
    ):
        with pytest.raises(FridaError) as caught:
            call()
        assert caught.value.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# attach: the single-pid allow check.
# ---------------------------------------------------------------------------
def test_attach_refuses_a_non_positive_pid() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.attach(0, allowed_pid=0)
    assert caught.value.code == "invalid_params"


def test_attach_refuses_a_pid_that_is_not_the_debuggee() -> None:
    """attach is limited to the session debuggee; another pid is denied."""
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.attach(4242, allowed_pid=1)
    assert caught.value.code == "permission_denied"
    assert caught.value.details["pid"] == 4242
    assert caught.value.details["allowed_pid"] == 1


def test_attach_detaches_the_probe_session_on_success() -> None:
    """The probe attaches, confirms, and detaches in a finally.

    Leaving the probe session attached would keep an agent resident in the
    debuggee after a call that only meant to confirm reachability.
    """
    detached: list[bool] = []

    class _Session:
        def detach(self) -> None:
            detached.append(True)

    class _Frida:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    payload = client.attach(1, allowed_pid=1)
    assert payload["pid"] == 1
    assert payload["attached"] is True
    assert detached == [True]


# ---------------------------------------------------------------------------
# modules / exports / memory_read payload shapes.
# ---------------------------------------------------------------------------
def _script_client(exports_api: Any) -> FridaClient:
    script = type("_S", (), {"exports_sync": exports_api, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, src: script, "detach": lambda self: None},
    )()
    frida = type("_F", (), {"attach": lambda self, pid: session})()
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


def test_modules_tolerates_a_bare_list_script_shape() -> None:
    """An older enumeration script returned a bare list, not {modules,total}.

    The bare-array branch keeps that shape working: total falls back to the
    number held so has_more still answers truthfully instead of raising.
    """

    class _Api:
        def modules(self, limit: int) -> list[dict[str, Any]]:
            del limit
            return [{"name": "a", "base": "0x1", "size": 1, "path": "/a"}]

    client = _script_client(_Api())
    payload = client.modules(1, allowed_pid=1, limit=10)
    assert payload["count"] == 1
    assert payload["total"] == 1
    assert payload["has_more"] is False


def test_exports_requires_a_module_name() -> None:
    client = _script_client(object())
    for bad in ("", "   "):
        with pytest.raises(FridaError) as caught:
            client.exports(1, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"


def test_exports_rejects_a_non_dict_payload() -> None:
    """A script that answered with a bare list for exports is a backend fault.

    exports must report found / module / base, so a shape that cannot carry
    them is refused rather than silently reported as an empty, un-found table.
    """

    class _Api:
        def exports(self, name: str, limit: int) -> list[Any]:
            del name, limit
            return ["not", "a", "dict"]

    client = _script_client(_Api())
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_exports_skips_non_dict_rows() -> None:
    """A malformed row inside the exports list is dropped, not crashed on."""

    class _Api:
        def exports(self, name: str, limit: int) -> dict[str, Any]:
            del limit
            return {
                "found": True,
                "module": name,
                "base": "0x1",
                "exports": [
                    {"name": "ok", "address": "0x2", "type": "function"},
                    "garbage",
                ],
            }

    client = _script_client(_Api())
    payload = client.exports(1, "libc.so", allowed_pid=1)
    assert payload["count"] == 1
    assert payload["exports"][0]["name"] == "ok"


def test_memory_read_returns_hex_for_a_valid_size() -> None:
    """memory.read answers with hex, size and address, not raw bytes."""

    class _Api:
        def read(self, address: int, size: int) -> list[int]:
            del address
            return list(range(size))

    client = _script_client(_Api())
    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)
    assert payload["encoding"] == "hex"
    assert payload["size"] == 4
    assert payload["address"] == 0x1000
    assert payload["data"] == bytes(range(4)).hex()


def test_memory_read_rejects_an_out_of_range_size() -> None:
    client = _script_client(object())
    for bad in (0, 256 * 1024 + 1):
        with pytest.raises(FridaError) as caught:
            client.memory_read(1, 0x1000, bad, allowed_pid=1)
        assert caught.value.code == "invalid_params"


def test_memory_read_refuses_a_pid_that_is_not_the_debuggee() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.memory_read(999, 0x1000, 4, allowed_pid=1)
    assert caught.value.code == "permission_denied"


# ---------------------------------------------------------------------------
# hook_template (local device).
# ---------------------------------------------------------------------------
def test_hook_template_rejects_an_unknown_template() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "not_a_template", allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "noop" in caught.value.details["allowed"]


def test_hook_template_loads_and_detaches_the_probe() -> None:
    detached: list[bool] = []

    class _Session:
        def create_script(self, src: str) -> Any:
            return type("_S", (), {"load": lambda self: None})()

        def detach(self) -> None:
            detached.append(True)

    class _Frida:
        def attach(self, pid: int, **kwargs: Any) -> _Session:
            del pid, kwargs
            return _Session()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    payload = client.hook_template(1, "noop", allowed_pid=1)
    assert payload["loaded"] is True
    assert payload["persisted"] is False
    assert detached == [True]


def test_hook_template_wraps_a_load_failure_as_backend_error() -> None:
    """A script that raises on load is a backend fault, surfaced as an envelope
    with the probe session already detached.
    """
    detached: list[bool] = []

    class _Session:
        def create_script(self, src: str) -> Any:
            def _raise() -> None:
                raise RuntimeError("script compile failed")

            return type("_S", (), {"load": staticmethod(_raise)})()

        def detach(self) -> None:
            detached.append(True)

    class _Frida:
        def attach(self, pid: int, **kwargs: Any) -> _Session:
            del pid, kwargs
            return _Session()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(RuntimeError):
        client.hook_template(1, "noop", allowed_pid=1)
    assert detached == [True]


# ---------------------------------------------------------------------------
# _attach_local generic failure translation.
# ---------------------------------------------------------------------------
def test_attach_local_wraps_a_generic_failure_as_backend_error() -> None:
    """A frida attach that raises a non-timeout error becomes backend_error.

    The caller gets a code it can branch on plus the pid, rather than an opaque
    frida exception crossing the tool boundary.
    """

    class _Frida:
        def attach(self, pid: int, **kwargs: Any) -> Any:
            del kwargs
            raise RuntimeError(f"process {pid} vanished")

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client.attach(1, allowed_pid=1)
    assert caught.value.code == "backend_error"
    assert caught.value.details["pid"] == 1


# ---------------------------------------------------------------------------
# _resolve_device branches.
# ---------------------------------------------------------------------------
def test_resolve_device_maps_the_local_aliases() -> None:
    """None / "" / "local" all resolve the local device."""
    resolved: list[str] = []

    class _Frida:
        def get_local_device(self) -> Any:
            resolved.append("local")
            return object()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    for alias in (None, "", "local"):
        client._resolve_device(alias)
    assert resolved == ["local", "local", "local"]


def test_resolve_device_reuses_a_registered_remote_before_adding() -> None:
    """A host:port already registered is fetched, not re-added.

    Re-adding a remote on every call churns frida's device manager for what is
    meant to be a stable connection held for the life of the session.
    """
    added: list[str] = []

    class _Manager:
        def get_device(self, device_id: str, timeout: int = 0) -> Any:
            del timeout
            return type("_D", (), {"id": device_id})()

        def add_remote_device(self, device_id: str) -> Any:
            added.append(device_id)
            return object()

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    device = client._resolve_device("10.0.0.1:27042")
    assert device.id == "10.0.0.1:27042"
    assert added == []


def test_resolve_device_adds_a_remote_that_is_not_yet_registered() -> None:
    added: list[str] = []

    class _Manager:
        def get_device(self, device_id: str, timeout: int = 0) -> Any:
            del timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, device_id: str) -> Any:
            added.append(device_id)
            return type("_D", (), {"id": device_id})()

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    device = client._resolve_device("10.0.0.1:27042")
    assert device.id == "10.0.0.1:27042"
    assert added == ["10.0.0.1:27042"]


def test_resolve_device_uses_get_device_for_a_named_id() -> None:
    class _Frida:
        def get_device(self, device_id: str, timeout: int = 0) -> Any:
            del timeout
            return type("_D", (), {"id": device_id})()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    device = client._resolve_device("emulator-5554")
    assert device.id == "emulator-5554"


def test_resolve_device_reports_not_found_on_a_lookup_failure() -> None:
    """A device that never resolves is not_found, carrying the id asked for."""

    class _Frida:
        def get_device(self, device_id: str, timeout: int = 0) -> Any:
            del device_id, timeout
            raise RuntimeError("no such device")

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client._resolve_device("ghost")
    assert caught.value.code == "not_found"
    assert caught.value.details["device_id"] == "ghost"


# ---------------------------------------------------------------------------
# enumerate_devices / add_remote_device / applications failure translation.
# ---------------------------------------------------------------------------
def test_enumerate_devices_wraps_a_failure_as_backend_error() -> None:
    class _Frida:
        def enumerate_devices(self) -> Any:
            raise RuntimeError("device manager down")

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_wraps_a_failure_as_backend_error() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 0) -> Any:
            del endpoint, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> Any:
            del endpoint
            raise RuntimeError("connection refused")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = FridaClient()
    client._available = True
    client._frida = _Frida()
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("10.0.0.1:27042")
    assert caught.value.code == "backend_error"
    assert caught.value.details["endpoint"] == "10.0.0.1:27042"


def test_applications_wraps_a_failure_as_backend_error() -> None:
    class _Device:
        def enumerate_applications(self) -> Any:
            raise RuntimeError("adb offline")

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# spawn: validation and partial-spawn cleanup.
# ---------------------------------------------------------------------------
def test_spawn_requires_a_non_empty_package() -> None:
    class _Device:
        pass

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")
    assert caught.value.code == "invalid_params"


def test_spawn_wraps_a_spawn_failure_as_backend_error() -> None:
    class _Device:
        def spawn(self, package: str, **kwargs: Any) -> int:
            del package, kwargs
            raise RuntimeError("activity not found")

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert caught.value.details["package"] == "com.example.app"


def test_spawn_kills_the_process_when_resume_fails() -> None:
    """A pid spawned then failed to resume must not be left running.

    Spawn leaves the process suspended; if resume raises, the caller never got
    a usable pid, so the probe kills it rather than leaking a suspended app.
    """
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str, **kwargs: Any) -> int:
            del package, kwargs
            return 4242

        def resume(self, pid: int, **kwargs: Any) -> None:
            del kwargs
            raise RuntimeError(f"resume {pid} failed")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert killed == [4242]


# ---------------------------------------------------------------------------
# java_enumerate branches.
# ---------------------------------------------------------------------------
def test_java_enumerate_wraps_an_attach_failure_as_backend_error() -> None:
    class _Device:
        def attach(self, pid: int, **kwargs: Any) -> Any:
            del kwargs
            raise RuntimeError(f"cannot attach {pid}")

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"


def test_java_methods_requires_a_class_name() -> None:
    class _Api:
        def methods(self, class_name: str, limit: int) -> dict[str, Any]:
            del class_name, limit
            return {"found": False, "methods": []}

    script = type("_S", (), {"exports_sync": _Api(), "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, src: script, "detach": lambda self: None},
    )()
    device = type("_Dev", (), {"attach": lambda self, pid, **kw: session})()
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods", class_name=None)
    assert caught.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    script = type("_S", (), {"exports_sync": object(), "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, src: script, "detach": lambda self: None},
    )()
    device = type("_Dev", (), {"attach": lambda self, pid, **kw: session})()
    client = _client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="everything")
    assert caught.value.code == "invalid_params"


def test_java_enumerate_refuses_a_pid_outside_the_allow_set() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 99, allowed_pids={1, 2}, mode="classes")
    assert caught.value.code == "permission_denied"
    assert caught.value.details["allowed_pids"] == [1, 2]


# ---------------------------------------------------------------------------
# hook_template_device branches.
# ---------------------------------------------------------------------------
def test_hook_template_device_rejects_an_unknown_template() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "nope", allowed_pids={1})
    assert caught.value.code == "invalid_params"


def test_hook_template_device_wraps_an_attach_failure_as_backend_error() -> None:
    class _Device:
        def attach(self, pid: int, **kwargs: Any) -> Any:
            del kwargs
            raise RuntimeError(f"attach {pid} refused")

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 1, "noop", allowed_pids={1})
    assert caught.value.code == "backend_error"


def test_hook_template_device_loads_and_detaches_on_success() -> None:
    detached: list[bool] = []

    class _Session:
        def create_script(self, src: str) -> Any:
            return type("_S", (), {"load": lambda self: None})()

        def detach(self) -> None:
            detached.append(True)

    class _Device:
        def attach(self, pid: int, **kwargs: Any) -> _Session:
            del pid, kwargs
            return _Session()

    client = _client(_Device())
    payload = client.hook_template_device("usb", 1, "noop", allowed_pids={1})
    assert payload["loaded"] is True
    assert payload["device"] == "usb"
    assert detached == [True]


# ---------------------------------------------------------------------------
# _authorize.
# ---------------------------------------------------------------------------
def test_authorize_refuses_a_non_positive_pid() -> None:
    client = FridaClient()
    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as caught:
        client._authorize(0, {1})
    assert caught.value.code == "invalid_params"


class _Timeoutish(Exception):
    """Its type name contains 'timeout', so _is_timeout classifies it."""


def _attach_raises(exc: BaseException) -> Any:
    """A device whose attach raises the given exception synchronously."""

    class _Device:
        def attach(self, pid: int, **kwargs: Any) -> Any:
            del pid, kwargs
            raise exc

    return _Device()


def _load_raises(exc: BaseException) -> Any:
    """A device that attaches, but whose script load raises the exception."""

    class _Session:
        def create_script(self, src: str) -> Any:
            def _raise() -> None:
                raise exc

            return type("_S", (), {"load": staticmethod(_raise)})()

        def detach(self) -> None:
            return None

    class _Device:
        def attach(self, pid: int, **kwargs: Any) -> _Session:
            del pid, kwargs
            return _Session()

    return _Device()


def test_modules_reads_the_dict_shape_with_a_separate_total() -> None:
    """The current script answers {modules, total}; total is not len(page).

    A device with more modules than the page returns them all in total while
    holding only the page, so has_more is derived from the real count rather
    than assumed from the slice.
    """

    class _Api:
        def modules(self, limit: int) -> dict[str, Any]:
            del limit
            return {
                "modules": [{"name": "a", "base": "0x1", "size": 1, "path": "/a"}],
                "total": 42,
            }

    client = _script_client(_Api())
    payload = client.modules(1, allowed_pid=1, limit=10)
    assert payload["count"] == 1
    assert payload["total"] == 42
    assert payload["has_more"] is True


def test_require_reports_unavailable_for_the_right_pid() -> None:
    """_require checks the pid first, then availability.

    A caller that passes the authorized pid on a client whose frida module
    never imported must still get capability_unavailable, not a success.
    """
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


def test_hook_template_reraises_a_frida_error_from_the_script() -> None:
    """A FridaError raised while loading is passed through unchanged.

    The wrapper must not re-label an already-structured error as backend_error;
    the original code and message are what the caller branches on.
    """
    client = FridaClient()
    client._available = True
    client._frida = _load_raises(FridaError("invalid_params", "bad template body"))
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_hook_template_maps_a_timeout_named_error_to_timeout() -> None:
    client = FridaClient()
    client._available = True
    client._frida = _load_raises(_Timeoutish("stalled"))
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "timeout"


def test_attach_local_maps_a_timeout_named_error_to_timeout() -> None:
    """A synchronous timeout-named failure is a timeout, not a backend_error.

    Frida can raise its own timeout exceptions before the daemon deadline
    fires; those must land on the timeout code so the caller retries the same
    way it would for the outer deadline.
    """
    client = FridaClient()
    client._available = True
    client._frida = _attach_raises(_Timeoutish("attach stalled"))
    with pytest.raises(FridaError) as caught:
        client.attach(1, allowed_pid=1)
    assert caught.value.code == "timeout"


def test_spawn_maps_a_timeout_named_spawn_failure_to_timeout() -> None:
    class _Device:
        def spawn(self, package: str, **kwargs: Any) -> int:
            del package, kwargs
            raise _Timeoutish("spawn stalled")

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"


def test_spawn_reraises_a_frida_error_from_resume_after_killing() -> None:
    """A FridaError during resume is passed through, with the pid killed first.

    The spawn already created a suspended process, so the structured resume
    error must not mask the cleanup: the pid is killed, then the original error
    surfaces unchanged.
    """
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str, **kwargs: Any) -> int:
            del package, kwargs
            return 4242

        def resume(self, pid: int, **kwargs: Any) -> None:
            del pid, kwargs
            raise FridaError("permission_denied", "resume not allowed")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "permission_denied"
    assert killed == [4242]


def test_spawn_maps_a_timeout_named_resume_failure_to_timeout() -> None:
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str, **kwargs: Any) -> int:
            del package, kwargs
            return 4242

        def resume(self, pid: int, **kwargs: Any) -> None:
            del pid, kwargs
            raise _Timeoutish("resume stalled")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = _client(_Device())
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"
    assert killed == [4242]


def test_java_enumerate_maps_a_timeout_named_attach_to_timeout() -> None:
    client = _client(_attach_raises(_Timeoutish("attach stalled")))
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "timeout"


def test_java_enumerate_wraps_a_script_failure_as_backend_error() -> None:
    """A script that raises after attach is detached and reported as backend.

    The load happens after the session exists, so the outer handler must
    detach it before surfacing the error, or the probe leaks a session.
    """
    client = _client(_load_raises(RuntimeError("script blew up")))
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_a_timeout_named_script_failure_to_timeout() -> None:
    client = _client(_load_raises(_Timeoutish("script stalled")))
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "timeout"


def test_hook_template_device_maps_a_timeout_named_attach_to_timeout() -> None:
    client = _client(_attach_raises(_Timeoutish("attach stalled")))
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 1, "noop", allowed_pids={1})
    assert caught.value.code == "timeout"


def test_hook_template_device_wraps_a_script_failure_as_backend_error() -> None:
    client = _client(_load_raises(RuntimeError("script blew up")))
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 1, "noop", allowed_pids={1})
    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_a_timeout_named_script_failure_to_timeout() -> None:
    client = _client(_load_raises(_Timeoutish("script stalled")))
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 1, "noop", allowed_pids={1})
    assert caught.value.code == "timeout"


def test_hook_template_device_times_out_and_detaches(monkeypatch: Any) -> None:
    """A device hook that never loads must not park the worker.

    The device-aware hook shares the same daemon-thread deadline as the local
    one; a script load that hangs is abandoned and the session detached.
    """
    state = {"detached": False}

    class _Session:
        def create_script(self, src: str) -> Any:
            def _hang() -> None:
                time.sleep(10)

            return type("_S", (), {"load": staticmethod(_hang)})()

        def detach(self) -> None:
            state["detached"] = True

    class _Device:
        def attach(self, pid: int, **kwargs: Any) -> _Session:
            del pid, kwargs
            return _Session()

    client = _client(_Device())
    started = time.monotonic()
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 1, "noop", allowed_pids={1}, timeout=0.2)
    assert time.monotonic() - started < 2.0
    assert caught.value.code == "timeout"
    assert state["detached"] is True
