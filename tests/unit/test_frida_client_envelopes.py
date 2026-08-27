"""Every FridaClient path must turn a raw frida failure into a FridaError.

The local script-phase wrapping and the argument validators are pinned by the
other frida test modules; what is exercised here is the rest of the surface the
service trusts to never leak a bare native exception:

* the local ``attach`` / ``modules`` / ``exports`` / ``memory_read`` guards and
  their success shapes,
* the device-resolution ladder (local / usb / remote ``host:port`` / by-id) and
  its ``not_found`` envelope,
* ``enumerate_devices`` / ``add_remote_device`` / ``applications`` / ``spawn`` /
  ``java_enumerate`` / ``hook_template_device`` mapping every adbutils-style
  broad exception to a stable code, with a ``timeout``-named stall kept on the
  retryable ``timeout`` code its siblings use.

These only run through the live frida backend, so they are driven with injected
fakes -- no frida-server, no device.

Note on the timeout fakes: ``_run_deadline`` runs work on a daemon thread and
catches ``concurrent.futures.TimeoutError`` which, on 3.11+, *is* the builtin
``TimeoutError``. A builtin ``TimeoutError`` raised inside work would therefore
be swallowed by the deadline itself. To exercise a method's *own* timeout
mapping we raise a distinctly-named exception (``_NamedTimeout``) that
``_is_timeout`` still recognises by name but the deadline does not intercept.
"""

from __future__ import annotations

import builtins
import time
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _frida_backend_errors,
    _invoke,
    _kill_spawned,
    _run_deadline,
)


class _NamedTimeout(Exception):
    """A non-FutureTimeout exception whose name marks it as a timeout."""


# --------------------------------------------------------------------------
# Fakes
# --------------------------------------------------------------------------


class _Exports:
    def __init__(self, **payloads: Any) -> None:
        self._payloads = payloads

    def modules(self, cap: int) -> Any:
        return self._payloads.get("modules")

    def exports(self, name: str, cap: int) -> Any:
        return self._payloads.get("exports")

    def read(self, address: int, size: int) -> Any:
        return self._payloads.get("read", [])

    def classes(self, name_filter: str, cap: int) -> Any:
        return self._payloads.get("classes", [])

    def methods(self, class_name: str, cap: int) -> Any:
        return self._payloads.get("methods")


class _Script:
    def __init__(self, exports: _Exports, load_exc: BaseException | None = None) -> None:
        self._exports = exports
        self._load_exc = load_exc
        self.loaded = False
        self.destroyed = False

    def load(self) -> None:
        if self._load_exc is not None:
            raise self._load_exc
        self.loaded = True

    @property
    def exports_sync(self) -> _Exports:
        return self._exports


class _Session:
    def __init__(
        self, exports: _Exports | None = None, load_exc: BaseException | None = None
    ) -> None:
        self.script = _Script(exports or _Exports(), load_exc)
        self.detached = False

    def create_script(self, source: str) -> _Script:
        assert source
        return self.script

    def detach(self) -> None:
        self.detached = True
        self.script.destroyed = True


class _LocalFrida:
    def __init__(
        self, session: _Session | None = None, attach_exc: BaseException | None = None
    ) -> None:
        self._session = session or _Session()
        self._attach_exc = attach_exc

    def attach(self, pid: int, timeout: float | None = None) -> _Session:
        if self._attach_exc is not None:
            raise self._attach_exc
        return self._session


class _Device:
    def __init__(self, **kw: Any) -> None:
        self._kw = kw
        self.killed: list[int] = []

    def attach(self, pid: int, timeout: float | None = None) -> _Session:
        exc = self._kw.get("attach_exc")
        if exc is not None:
            raise exc
        return self._kw.get("session") or _Session()

    def spawn(self, package: str, timeout: float | None = None) -> int:
        exc = self._kw.get("spawn_exc")
        if exc is not None:
            raise exc
        return int(self._kw.get("spawn_pid", 4242))

    def resume(self, pid: int, timeout: float | None = None) -> None:
        exc = self._kw.get("resume_exc")
        if exc is not None:
            raise exc

    def kill(self, pid: int) -> None:
        self.killed.append(pid)

    def enumerate_applications(self) -> Any:
        exc = self._kw.get("apps_exc")
        if exc is not None:
            raise exc
        return self._kw.get("apps", [])


def _local_client(frida: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


def _device_client(device: _Device) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: device  # type: ignore[method-assign]
    return client


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------


def test_accepts_timeout_is_false_when_the_signature_cannot_be_read() -> None:
    assert _accepts_timeout(range) is False


def test_invoke_passes_a_timeout_only_when_the_callable_names_it() -> None:
    def with_timeout(x: int, timeout: float | None = None) -> Any:
        return timeout

    def without_timeout(x: int) -> str:
        return "no-timeout"

    assert _invoke(with_timeout, 1, timeout=3.0) == 3.0
    assert _invoke(without_timeout, 1, timeout=3.0) == "no-timeout"


def test_backend_errors_passes_a_fridaerror_through() -> None:
    with pytest.raises(FridaError) as caught, _frida_backend_errors("x"):
        raise FridaError("invalid_params", "already structured")
    assert caught.value.code == "invalid_params"


def test_backend_errors_maps_a_timeout_named_exception() -> None:
    with pytest.raises(FridaError) as caught, _frida_backend_errors("read"):
        raise _NamedTimeout("stalled")
    assert caught.value.code == "timeout"


def test_backend_errors_maps_any_other_exception_to_backend_error() -> None:
    with pytest.raises(FridaError) as caught, _frida_backend_errors("read"):
        raise RuntimeError("boom")
    assert caught.value.code == "backend_error"


def test_bound_timeout_rejects_a_non_positive_value() -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(0)
    assert caught.value.code == "invalid_params"


def test_bound_timeout_rejects_nan() -> None:
    with pytest.raises(FridaError) as caught:
        _bound_timeout(float("nan"))
    assert caught.value.code == "invalid_params"


def test_kill_spawned_drains_every_pid() -> None:
    device = _Device()
    _kill_spawned(device, [1, 2])
    assert set(device.killed) == {1, 2}


def test_run_deadline_times_out_without_an_on_timeout_callback() -> None:
    with pytest.raises(FridaError) as caught:
        _run_deadline(lambda: time.sleep(2), timeout=0.01)
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# __init__ / availability guards
# --------------------------------------------------------------------------


def test_missing_frida_at_import_degrades_to_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "frida":
            raise ImportError("no frida here")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    assert FridaClient().available is False


# --------------------------------------------------------------------------
# attach (local)
# --------------------------------------------------------------------------


def test_attach_refuses_when_frida_is_absent() -> None:
    client = FridaClient()
    client._available = False
    with pytest.raises(FridaError) as caught:
        client.attach(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


def test_attach_refuses_a_non_positive_pid() -> None:
    client = _local_client(_LocalFrida())
    with pytest.raises(FridaError) as caught:
        client.attach(0, allowed_pid=0)
    assert caught.value.code == "invalid_params"


def test_attach_refuses_a_pid_outside_the_session() -> None:
    client = _local_client(_LocalFrida())
    with pytest.raises(FridaError) as caught:
        client.attach(2, allowed_pid=1)
    assert caught.value.code == "permission_denied"


def test_attach_probe_succeeds_and_detaches_immediately() -> None:
    session = _Session()
    client = _local_client(_LocalFrida(session=session))
    payload = client.attach(4242, allowed_pid=4242)
    assert payload == {
        "pid": 4242,
        "attached": True,
        "device": "local",
        "note": "probe attach; detached immediately",
    }
    assert session.detached is True


# --------------------------------------------------------------------------
# _attach_local failure envelope
# --------------------------------------------------------------------------


def test_attach_local_passes_a_fridaerror_through() -> None:
    client = _local_client(_LocalFrida(attach_exc=FridaError("permission_denied", "denied")))
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "permission_denied"


def test_attach_local_maps_a_timeout() -> None:
    client = _local_client(_LocalFrida(attach_exc=_NamedTimeout("attach stalled")))
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "timeout"


def test_attach_local_maps_any_other_failure_to_backend_error() -> None:
    client = _local_client(_LocalFrida(attach_exc=RuntimeError("no such process")))
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_require_reports_capability_unavailable_when_pid_is_allowed() -> None:
    client = FridaClient()
    client._available = False
    with pytest.raises(FridaError) as caught:
        client.modules(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"


# --------------------------------------------------------------------------
# modules / exports / memory_read (local)
# --------------------------------------------------------------------------


def test_modules_reads_the_dict_payload_shape() -> None:
    exports = _Exports(
        modules={
            "modules": [
                {"name": "libc.so", "base": "0x1000", "size": 4096, "path": "/lib/libc.so"},
                "not-a-dict",
            ],
            "total": 5,
        }
    )
    client = _local_client(_LocalFrida(session=_Session(exports)))
    payload = client.modules(4242, allowed_pid=4242, limit=10)
    assert payload["count"] == 1
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_modules_reads_a_bare_array_payload() -> None:
    exports = _Exports(
        modules=[{"name": "a", "base": "0x1", "size": 1, "path": "/a"}]
    )
    client = _local_client(_LocalFrida(session=_Session(exports)))
    payload = client.modules(4242, allowed_pid=4242)
    assert payload["total"] == 1
    assert payload["has_more"] is False


def test_exports_requires_a_module_name() -> None:
    client = _local_client(_LocalFrida())
    with pytest.raises(FridaError) as caught:
        client.exports(1, "   ", allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_exports_rejects_a_non_dict_payload() -> None:
    client = _local_client(_LocalFrida(session=_Session(_Exports(exports=["oops"]))))
    with pytest.raises(FridaError) as caught:
        client.exports(1, "libc.so", allowed_pid=1)
    assert caught.value.code == "backend_error"


def test_exports_skips_non_dict_entries() -> None:
    exports = _Exports(
        exports={
            "found": True,
            "module": "libc.so",
            "base": "0x1000",
            "exports": ["not-a-dict", {"name": "open", "address": "0x2000", "type": "function"}],
        }
    )
    client = _local_client(_LocalFrida(session=_Session(exports)))
    payload = client.exports(1, "libc.so", allowed_pid=1)
    assert payload["count"] == 1
    assert payload["exports"][0]["name"] == "open"


def test_memory_read_refuses_a_negative_address() -> None:
    client = _local_client(_LocalFrida())
    with pytest.raises(FridaError) as caught:
        client.memory_read(1, -1, 16, allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_memory_read_refuses_a_bad_size() -> None:
    client = _local_client(_LocalFrida())
    with pytest.raises(FridaError) as caught:
        client.memory_read(1, 0x1000, 0, allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_memory_read_returns_hex_on_success() -> None:
    client = _local_client(_LocalFrida(session=_Session(_Exports(read=[0xDE, 0xAD]))))
    payload = client.memory_read(1, 0x1000, 2, allowed_pid=1)
    assert payload["encoding"] == "hex"
    assert payload["data"] == "dead"


def test_hook_template_rejects_an_unknown_template() -> None:
    client = _local_client(_LocalFrida())
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "not-a-template", allowed_pid=1)
    assert caught.value.code == "invalid_params"


def test_hook_template_maps_a_named_timeout_on_load() -> None:
    session = _Session(load_exc=_NamedTimeout("load stalled"))
    client = _local_client(_LocalFrida(session=session))
    with pytest.raises(FridaError) as caught:
        client.hook_template(1, "noop", allowed_pid=1, timeout=5.0)
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# _resolve_device ladder
# --------------------------------------------------------------------------


class _Mgr:
    def __init__(
        self,
        *,
        get: Any = None,
        get_exc: BaseException | None = None,
        add: Any = None,
        add_exc: BaseException | None = None,
    ) -> None:
        self._get = get
        self._get_exc = get_exc
        self._add = add
        self._add_exc = add_exc

    def get_device(self, device_id: str, timeout: float | None = None) -> Any:
        if self._get_exc is not None:
            raise self._get_exc
        return self._get

    def add_remote_device(self, device_id: str) -> Any:
        if self._add_exc is not None:
            raise self._add_exc
        return self._add


class _ResolveFrida:
    def __init__(self, **kw: Any) -> None:
        self._kw = kw

    def get_local_device(self) -> Any:
        exc = self._kw.get("local_exc")
        if exc is not None:
            raise exc
        return self._kw.get("local")

    def get_usb_device(self, timeout: float | None = None) -> Any:
        return self._kw.get("usb")

    def get_device(self, device_id: str, timeout: float | None = None) -> Any:
        return self._kw.get("by_id")

    def get_device_manager(self) -> Any:
        return self._kw.get("mgr")


def test_resolve_device_local() -> None:
    dev = object()
    client = _local_client(_ResolveFrida(local=dev))
    assert client._resolve_device(None) is dev


def test_resolve_device_usb() -> None:
    dev = object()
    client = _local_client(_ResolveFrida(usb=dev))
    assert client._resolve_device("usb") is dev


def test_resolve_device_remote_reuses_a_registered_device() -> None:
    dev = object()
    client = _local_client(_ResolveFrida(mgr=_Mgr(get=dev)))
    assert client._resolve_device("10.0.0.2:5555") is dev


def test_resolve_device_remote_adds_when_not_registered() -> None:
    added = object()
    mgr = _Mgr(get_exc=RuntimeError("not registered"), add=added)
    client = _local_client(_ResolveFrida(mgr=mgr))
    assert client._resolve_device("10.0.0.2:5555") is added


def test_resolve_device_by_id() -> None:
    dev = object()
    client = _local_client(_ResolveFrida(by_id=dev))
    assert client._resolve_device("emulator-5554") is dev


def test_resolve_device_maps_a_failure_to_not_found() -> None:
    client = _local_client(_ResolveFrida(local_exc=RuntimeError("no local device")))
    with pytest.raises(FridaError) as caught:
        client._resolve_device(None)
    assert caught.value.code == "not_found"


def test_resolve_device_passes_a_fridaerror_through() -> None:
    client = _local_client(_ResolveFrida(local_exc=FridaError("permission_denied", "denied")))
    with pytest.raises(FridaError) as caught:
        client._resolve_device(None)
    assert caught.value.code == "permission_denied"


# --------------------------------------------------------------------------
# enumerate_devices / add_remote_device
# --------------------------------------------------------------------------


def test_enumerate_devices_shapes_rows() -> None:
    frida = SimpleNamespace(
        enumerate_devices=lambda: [
            SimpleNamespace(id="local", name="Local System", type="local")
        ]
    )
    payload = _local_client(frida).enumerate_devices()
    assert payload == {
        "devices": [{"id": "local", "name": "Local System", "type": "local"}],
        "count": 1,
    }


def test_enumerate_devices_maps_a_failure() -> None:
    def boom() -> Any:
        raise RuntimeError("frida server down")

    frida = SimpleNamespace(enumerate_devices=boom)
    with pytest.raises(FridaError) as caught:
        _local_client(frida).enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_reuses_a_registered_device() -> None:
    dev = SimpleNamespace(id="10.0.0.2:5555", name="Remote", type="remote")
    frida = SimpleNamespace(get_device_manager=lambda: _Mgr(get=dev))
    payload = _local_client(frida).add_remote_device("10.0.0.2:5555")
    assert payload["id"] == "10.0.0.2:5555"


def test_add_remote_device_adds_when_not_registered() -> None:
    dev = SimpleNamespace(id="10.0.0.2:5555", name="Remote", type="remote")
    mgr = _Mgr(get_exc=RuntimeError("unknown"), add=dev)
    frida = SimpleNamespace(get_device_manager=lambda: mgr)
    payload = _local_client(frida).add_remote_device("10.0.0.2:5555")
    assert payload["type"] == "remote"


def test_add_remote_device_maps_a_failure() -> None:
    mgr = _Mgr(get_exc=RuntimeError("unknown"), add_exc=RuntimeError("cannot add"))
    frida = SimpleNamespace(get_device_manager=lambda: mgr)
    with pytest.raises(FridaError) as caught:
        _local_client(frida).add_remote_device("10.0.0.2:5555")
    assert caught.value.code == "backend_error"


def test_add_remote_device_passes_a_fridaerror_through() -> None:
    mgr = _Mgr(get_exc=RuntimeError("unknown"), add_exc=FridaError("permission_denied", "no"))
    frida = SimpleNamespace(get_device_manager=lambda: mgr)
    with pytest.raises(FridaError) as caught:
        _local_client(frida).add_remote_device("10.0.0.2:5555")
    assert caught.value.code == "permission_denied"


# --------------------------------------------------------------------------
# applications
# --------------------------------------------------------------------------


def test_applications_shapes_and_caps() -> None:
    apps = [SimpleNamespace(identifier=f"com.app{i}", name=f"App{i}", pid=i) for i in range(3)]
    client = _device_client(_Device(apps=apps))
    payload = client.applications("usb", limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 3
    assert payload["has_more"] is True


def test_applications_maps_a_failure() -> None:
    client = _device_client(_Device(apps_exc=RuntimeError("enumerate failed")))
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# spawn
# --------------------------------------------------------------------------


def test_spawn_returns_the_pid_on_success() -> None:
    client = _device_client(_Device(spawn_pid=777))
    payload = client.spawn("usb", "com.example.app")
    assert payload["pid"] == 777
    assert payload["package"] == "com.example.app"


def test_spawn_maps_a_spawn_timeout() -> None:
    client = _device_client(_Device(spawn_exc=_NamedTimeout("spawn stalled")))
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"


def test_spawn_maps_a_spawn_failure() -> None:
    client = _device_client(_Device(spawn_exc=RuntimeError("no such package")))
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"


def test_spawn_kills_the_process_and_passes_a_resume_fridaerror_through() -> None:
    device = _Device(spawn_pid=555, resume_exc=FridaError("permission_denied", "no resume"))
    client = _device_client(device)
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "permission_denied"
    assert device.killed == [555]


def test_spawn_kills_the_process_on_a_resume_timeout() -> None:
    device = _Device(spawn_pid=555, resume_exc=_NamedTimeout("resume stalled"))
    client = _device_client(device)
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"
    assert device.killed == [555]


def test_spawn_kills_the_process_on_a_resume_failure() -> None:
    device = _Device(spawn_pid=555, resume_exc=RuntimeError("resume refused"))
    client = _device_client(device)
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert device.killed == [555]


# --------------------------------------------------------------------------
# java_enumerate
# --------------------------------------------------------------------------


def test_java_enumerate_classes_pages_the_result() -> None:
    session = _Session(_Exports(classes=["a.A", "b.B", "c.C"]))
    client = _device_client(_Device(session=session))
    payload = client.java_enumerate(
        "usb", 4242, allowed_pids=[4242], mode="classes", limit=2
    )
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_java_enumerate_methods_reads_the_dict_shape() -> None:
    session = _Session(_Exports(methods={"found": True, "methods": ["m1", "m2"]}))
    client = _device_client(_Device(session=session))
    payload = client.java_enumerate(
        "usb", 4242, allowed_pids=[4242], mode="methods", class_name="com.X", limit=10
    )
    assert payload["found"] is True
    assert payload["methods"] == ["m1", "m2"]


def test_java_enumerate_methods_reads_a_bare_array() -> None:
    session = _Session(_Exports(methods=["m1"]))
    client = _device_client(_Device(session=session))
    payload = client.java_enumerate(
        "usb", 4242, allowed_pids=[4242], mode="methods", class_name="com.X"
    )
    assert payload["found"] is True
    assert payload["methods"] == ["m1"]


def test_java_enumerate_maps_an_attach_timeout() -> None:
    client = _device_client(_Device(attach_exc=_NamedTimeout("attach stalled")))
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids=[4242], mode="classes")
    assert caught.value.code == "timeout"


def test_java_enumerate_maps_an_attach_failure() -> None:
    client = _device_client(_Device(attach_exc=RuntimeError("cannot attach")))
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids=[4242], mode="classes")
    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_a_script_load_failure() -> None:
    session = _Session(load_exc=RuntimeError("Java is not defined"))
    client = _device_client(_Device(session=session))
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids=[4242], mode="classes")
    assert caught.value.code == "backend_error"


def test_java_enumerate_maps_a_named_timeout_on_load() -> None:
    session = _Session(load_exc=_NamedTimeout("load stalled"))
    client = _device_client(_Device(session=session))
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4242, allowed_pids=[4242], mode="classes")
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# hook_template_device
# --------------------------------------------------------------------------


def test_hook_template_device_maps_an_attach_timeout() -> None:
    client = _device_client(_Device(attach_exc=_NamedTimeout("attach stalled")))
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids=[4242])
    assert caught.value.code == "timeout"


def test_hook_template_device_maps_an_attach_failure() -> None:
    client = _device_client(_Device(attach_exc=RuntimeError("cannot attach")))
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids=[4242])
    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_a_script_load_failure() -> None:
    session = _Session(load_exc=RuntimeError("Java is not defined"))
    client = _device_client(_Device(session=session))
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "android_ssl_unpin", allowed_pids=[4242])
    assert caught.value.code == "backend_error"


def test_hook_template_device_maps_a_named_timeout_on_load() -> None:
    session = _Session(load_exc=_NamedTimeout("load stalled"))
    client = _device_client(_Device(session=session))
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids=[4242])
    assert caught.value.code == "timeout"


# --------------------------------------------------------------------------
# _authorize guards
# --------------------------------------------------------------------------


def test_authorize_reports_capability_unavailable() -> None:
    client = FridaClient()
    client._available = False
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4242, "noop", allowed_pids=[4242])
    assert caught.value.code == "capability_unavailable"


def test_authorize_refuses_a_non_positive_pid() -> None:
    client = _device_client(_Device())
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 0, "noop", allowed_pids=[0])
    assert caught.value.code == "invalid_params"
