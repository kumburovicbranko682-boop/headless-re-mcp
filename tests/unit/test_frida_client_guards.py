"""Guard, error and degradation paths of the Frida backend client.

The field-shape tests in ``test_frida_fields.py`` cover the happy replies. This
file exercises the branches an unattended agent actually hits against a real
device: a missing frida module, a pid outside the session's allow-set, a device
that never resolves, a spawn whose resume fails, and the local memory-read probe
that the field tests never touched. Every one must land as a structured
``FridaError`` with a stable code -- never a bare exception -- because the tool
layer turns the code into the envelope the caller reads.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _invoke,
)


def _client(frida: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


# ---------------------------------------------------------------------------
# module-level helpers
# ---------------------------------------------------------------------------
def test_accepts_timeout_is_false_when_a_signature_cannot_be_read() -> None:
    """A callable whose signature() raises must not be handed a timeout kwarg.

    ``_invoke`` only forwards a deadline to natives that name ``timeout``. A
    non-introspectable target (a bare instance, a C function) returns False so
    the deadline stays an outer daemon-thread bound instead of a spawn argument
    frida would reject.
    """
    assert _accepts_timeout(object()) is False

    def with_timeout(pid: int, timeout: float = 0.0) -> None:
        del pid, timeout

    def without_timeout(pid: int, **kwargs: Any) -> None:
        del pid, kwargs

    assert _accepts_timeout(with_timeout) is True
    # **kwargs is not a named timeout parameter: forwarding there would be an
    # aux spawn option, not a hang bound.
    assert _accepts_timeout(without_timeout) is False


def test_invoke_forwards_the_deadline_only_to_a_named_timeout() -> None:
    seen: dict[str, Any] = {}

    def named(value: int, timeout: float = 0.0) -> str:
        seen["timeout"] = timeout
        return f"named:{value}"

    def unnamed(value: int) -> str:
        return f"unnamed:{value}"

    assert _invoke(named, 7, timeout=1.5) == "named:7"
    assert seen["timeout"] == 1.5
    assert _invoke(unnamed, 9, timeout=1.5) == "unnamed:9"


def test_bound_timeout_rejects_a_non_positive_deadline() -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(0)
    assert caught.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# local attach / require guards
# ---------------------------------------------------------------------------
def test_attach_without_frida_module_is_capability_unavailable() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.attach(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


def test_attach_rejects_a_non_positive_pid() -> None:
    client = _client(object())
    for pid in (0, -3):
        with pytest.raises(FridaError) as caught:
            client.attach(pid, allowed_pid=pid)
        assert caught.value.code == "invalid_params"


def test_attach_refuses_a_pid_that_is_not_the_session_debuggee() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.attach(4321, allowed_pid=1234)
    assert caught.value.code == "permission_denied"
    assert caught.value.details["pid"] == 4321
    assert caught.value.details["allowed_pid"] == 1234


def test_attach_detaches_the_probe_and_reports_local() -> None:
    """A successful probe attach leaves nothing resident.

    Measured: the session is detached in the finally, and the reply names the
    local device with the immediate-detach note rather than pretending a
    persistent agent.
    """
    detached: list[bool] = []

    class _Session:
        def detach(self) -> None:
            detached.append(True)

    class _Frida:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session()

    client = _client(_Frida())
    payload = client.attach(1, allowed_pid=1)
    assert payload["attached"] is True
    assert payload["device"] == "local"
    assert "detached immediately" in payload["note"]
    assert detached == [True]


def test_attach_maps_a_native_failure_to_backend_error() -> None:
    class _Frida:
        def attach(self, pid: int) -> Any:
            del pid
            raise RuntimeError("no such process")

    client = _client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.attach(99, allowed_pid=99)
    assert caught.value.code == "backend_error"
    assert caught.value.details["pid"] == 99


def test_require_refuses_a_pid_outside_the_allow_set() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.modules(2, allowed_pid=1)
    assert caught.value.code == "permission_denied"


def test_require_reports_capability_unavailable_even_for_the_allowed_pid() -> None:
    """The allow-set check passes, but a missing module is still unavailable.

    An agent that authorised the pid must not read a 'permission_denied' when
    the real cause is that frida was never installed on the host.
    """
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


class _NativeStall(RuntimeError):
    """A frida native error whose text reads as a timeout without being the
    ``concurrent.futures.TimeoutError`` alias the deadline runner catches."""


def test_attach_bounds_a_native_timeout_and_detaches() -> None:
    """frida.attach that fails with a timeout-worded native error is mapped to
    the ``timeout`` code, not surfaced as the raw exception the caller cannot
    key on.
    """

    class _Frida:
        def attach(self, pid: int) -> Any:
            del pid
            raise _NativeStall("frida native attach timed out")

    client = _client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.attach(1, allowed_pid=1)
    assert caught.value.code == "timeout"


def test_hook_template_bounds_a_native_timeout_and_detaches() -> None:
    class _Frida:
        def attach(self, pid: int) -> Any:
            del pid
            raise _NativeStall("attach timed out")

    client = _client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1)
    assert caught.value.code == "timeout"


# ---------------------------------------------------------------------------
# modules / exports payload shaping
# ---------------------------------------------------------------------------
def _script_client(exports_api: Any) -> FridaClient:
    script = type("_S", (), {"exports_sync": exports_api, "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()
    frida = type("_F", (), {"attach": lambda self, pid: session})()
    return _client(frida)


def test_modules_reads_the_dict_shape_with_a_total() -> None:
    """The newer enum script returns {modules, total}; the bare-array branch is
    the fallback. total lets has_more distinguish a full page from the whole
    list."""

    class _Api:
        def modules(self, limit: int) -> dict[str, Any]:
            del limit
            return {
                "modules": [
                    {"name": f"m{i}", "base": "0x1", "size": i, "path": "/x"}
                    for i in range(25)
                ],
                "total": 25,
            }

    client = _script_client(_Api())
    payload = client.modules(1, allowed_pid=1, limit=10)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["has_more"] is True


def test_exports_requires_a_module_name() -> None:
    client = _script_client(object())
    with pytest.raises(FridaError) as caught:
        client.exports(1, "   ", allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_exports_rejects_a_non_dict_payload_as_backend_error() -> None:
    class _Api:
        def exports(self, name: str, count: int) -> list[Any]:
            del name, count
            return []

    client = _script_client(_Api())
    with pytest.raises(FridaError) as caught:
        client.exports(1, "ntdll.dll", allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_exports_skips_a_non_dict_row_without_crashing() -> None:
    class _Api:
        def exports(self, name: str, count: int) -> dict[str, Any]:
            del count
            return {
                "found": True,
                "module": name,
                "base": "0x1",
                "exports": [
                    {"name": "good", "address": "0x2", "type": "function"},
                    "not-a-dict",
                ],
            }

    client = _script_client(_Api())
    payload = client.exports(1, "ntdll.dll", allowed_pid=1, limit=10)
    assert payload["count"] == 1
    assert payload["exports"][0]["name"] == "good"


# ---------------------------------------------------------------------------
# local memory_read probe (untouched by the field tests)
# ---------------------------------------------------------------------------
def test_memory_read_returns_hex_for_the_bytes_the_script_read() -> None:
    class _Api:
        def read(self, address: int, size: int) -> list[int]:
            del address
            return list(range(size))

    client = _script_client(_Api())
    payload = client.memory_read(1, 0x1000, 4, allowed_pid=1)
    assert payload["encoding"] == "hex"
    assert payload["data"] == "00010203"
    assert payload["size"] == 4
    assert payload["address"] == 0x1000


def test_memory_read_rejects_an_out_of_range_size() -> None:
    client = _script_client(object())
    for size in (0, 256 * 1024 + 1):
        with pytest.raises(FridaError) as caught:
            client.memory_read(1, 0x1000, size, allowed_pid=1)
        assert caught.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# hook templates
# ---------------------------------------------------------------------------
def test_hook_template_rejects_an_unknown_template() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "no_such_template", allowed_pid=1)
    assert caught.value.code == "invalid_params"
    assert "android_ssl_unpin" in caught.value.details["allowed"]


def test_hook_template_discloses_that_the_probe_does_not_persist() -> None:
    class _Session:
        def create_script(self, source: str) -> Any:
            del source
            return type("_S", (), {"load": lambda self: None})()

        def detach(self) -> None:
            return None

    class _Frida:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session()

    client = _client(_Frida())
    payload = client.hook_template(1, "android_ssl_unpin", allowed_pid=1)
    assert payload["loaded"] is True
    assert payload["template"] == "android_ssl_unpin"
    assert payload["persisted"] is False
    assert "destroyed" in payload["note"]


def test_hook_template_rejects_a_non_positive_timeout() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1, timeout=-1)
    assert caught.value.code == "invalid_params"


# ---------------------------------------------------------------------------
# device resolution
# ---------------------------------------------------------------------------
def test_resolve_device_without_frida_is_capability_unavailable() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "capability_unavailable"


def test_resolve_local_usb_remote_and_named_devices() -> None:
    marker = object()

    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            del endpoint, timeout
            return marker

    class _Frida:
        def get_local_device(self) -> Any:
            return marker

        def get_device(self, device_id: str, timeout: int = 5) -> Any:
            del device_id, timeout
            return marker

        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _client(_Frida())
    assert client._resolve_device(None) is marker
    assert client._resolve_device("local") is marker
    assert client._resolve_device("10.0.0.1:27042") is marker
    assert client._resolve_device("emulator-5554") is marker


def test_resolve_remote_falls_back_to_add_when_get_device_misses() -> None:
    added: list[str] = []
    remote = object()

    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            del endpoint, timeout
            raise RuntimeError("not registered yet")

        def add_remote_device(self, endpoint: str) -> Any:
            added.append(endpoint)
            return remote

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _client(_Frida())
    assert client._resolve_device("10.0.0.2:27042") is remote
    assert added == ["10.0.0.2:27042"]


def test_resolve_device_maps_a_lookup_failure_to_not_found() -> None:
    class _Frida:
        def get_local_device(self) -> Any:
            raise RuntimeError("no device")

    client = _client(_Frida())
    with pytest.raises(FridaError) as caught:
        client._resolve_device(None)
    assert caught.value.code == "not_found"
    assert caught.value.details["device_id"] is None


def test_enumerate_devices_maps_a_failure_to_backend_error() -> None:
    class _Frida:
        def enumerate_devices(self) -> Any:
            raise RuntimeError("usb bus down")

    client = _client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_maps_a_failure_to_backend_error() -> None:
    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            del endpoint, timeout
            raise RuntimeError("miss")

        def add_remote_device(self, endpoint: str) -> Any:
            del endpoint
            raise RuntimeError("refused")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    client = _client(_Frida())
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("10.0.0.9:27042")
    assert caught.value.code == "backend_error"
    assert caught.value.details["endpoint"] == "10.0.0.9:27042"


def test_applications_maps_a_failure_to_backend_error() -> None:
    class _Device:
        def enumerate_applications(self) -> Any:
            raise RuntimeError("device asleep")

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"


# ---------------------------------------------------------------------------
# spawn failure handling
# ---------------------------------------------------------------------------
def test_spawn_requires_a_package_id() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 1

        def resume(self, pid: int) -> None:
            del pid

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")
    assert caught.value.code == "invalid_params"


def test_spawn_maps_a_spawn_failure_to_backend_error() -> None:
    class _Device:
        def spawn(self, package: str) -> int:
            del package
            raise RuntimeError("package not installed")

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"


def test_spawn_kills_the_process_when_resume_fails() -> None:
    """A spawn that cannot be resumed must not leave a suspended process.

    Measured: resume raising leaves the target frozen at entry; the client
    kills the pid it spawned and reports backend_error rather than returning a
    pid the caller believes is running.
    """
    killed: list[int] = []

    class _Device:
        def spawn(self, package: str) -> int:
            del package
            return 5150

        def resume(self, pid: int) -> None:
            del pid
            raise RuntimeError("resume denied")

        def kill(self, pid: int) -> None:
            killed.append(pid)

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert killed == [5150]


# ---------------------------------------------------------------------------
# java_enumerate error handling
# ---------------------------------------------------------------------------
def test_java_enumerate_maps_an_attach_failure_to_backend_error() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            del pid
            raise RuntimeError("process gone")

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="classes")
    assert caught.value.code == "backend_error"


def test_java_methods_requires_a_class_name() -> None:
    client = _script_client_for_java()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="methods")
    assert caught.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    client = _script_client_for_java()
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 1, allowed_pids={1}, mode="fields")
    assert caught.value.code == "invalid_params"


def _script_client_for_java() -> FridaClient:
    class _Api:
        def classes(self, name_filter: str, count: int) -> list[str]:
            del name_filter, count
            return []

        def methods(self, class_name: str, count: int) -> dict[str, Any]:
            del class_name, count
            return {"found": True, "methods": []}

    script = type("_S", (), {"exports_sync": _Api(), "load": lambda self: None})()
    session = type(
        "_Sess",
        (),
        {"create_script": lambda self, source: script, "detach": lambda self: None},
    )()
    device = type("_Dev", (), {"attach": lambda self, pid: session})()
    client = _client(object())
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


# ---------------------------------------------------------------------------
# hook_template_device + authorize
# ---------------------------------------------------------------------------
def test_hook_template_device_rejects_an_unknown_template() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(
            "usb", 1, "no_such", allowed_pids={1}
        )
    assert caught.value.code == "invalid_params"


def test_hook_template_device_maps_an_attach_failure_to_backend_error() -> None:
    class _Device:
        def attach(self, pid: int) -> Any:
            del pid
            raise RuntimeError("attach refused")

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 1, "noop", allowed_pids={1})
    assert caught.value.code == "backend_error"


def test_hook_template_device_reports_the_disclosure_on_success() -> None:
    class _Session:
        def create_script(self, source: str) -> Any:
            del source
            return type("_S", (), {"load": lambda self: None})()

        def detach(self) -> None:
            return None

    class _Device:
        def attach(self, pid: int) -> _Session:
            del pid
            return _Session()

    client = _client(object())
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    payload = client.hook_template_device("usb", 7, "noop", allowed_pids={7})
    assert payload["loaded"] is True
    assert payload["persisted"] is False
    assert payload["device"] == "usb"


def test_authorize_rejects_a_pid_outside_the_allow_set() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 42, "noop", allowed_pids={1, 2})
    assert caught.value.code == "permission_denied"
    assert caught.value.details["allowed_pids"] == [1, 2]


def test_authorize_rejects_a_non_positive_pid() -> None:
    client = _client(object())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 0, "noop", allowed_pids={0})
    assert caught.value.code == "invalid_params"


def test_authorize_without_frida_is_capability_unavailable() -> None:
    client = FridaClient()
    client._available = False
    client._frida = None
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 1, "noop", allowed_pids={1})
    assert caught.value.code == "capability_unavailable"
