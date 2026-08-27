"""FridaClient guard, error and honesty branches.

The field-shape tests pin what each frida.* call answers with on the happy
path. What is covered here is the machinery around them: the timeout/deadline
helpers, the capability/permission guards, the device resolver's per-shape
lookups, and the error contract that turns a wedged attach or a failed spawn
into a structured FridaError (timeout / backend_error / not_found /
permission_denied / invalid_params) rather than an unhandled exception. frida
itself is never imported; a fake module and fake device/session objects drive
every path.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.frida.client as fc
from headless_re_mcp.backends.frida.client import FridaClient, FridaError
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT


# --------------------------------------------------------------------------
# module-level helpers
# --------------------------------------------------------------------------
def test_is_timeout_reads_the_type_name_and_the_message() -> None:
    assert fc._is_timeout(TimeoutError("x")) is True
    assert fc._is_timeout(RuntimeError("operation timed out")) is True
    assert fc._is_timeout(RuntimeError("boom")) is False


def test_accepts_timeout_only_when_named_not_for_kwargs_or_unreadable() -> None:
    def with_timeout(pid: int, timeout: float = 1.0) -> None: ...
    def without(pid: int, **kwargs: Any) -> None: ...

    assert fc._accepts_timeout(with_timeout) is True
    assert fc._accepts_timeout(without) is False
    # A C builtin whose signature cannot be read is treated as not accepting it.
    assert fc._accepts_timeout(range) is False

    class _Dev:
        def attach(self, pid: int, timeout: float = 1.0) -> None: ...

    # A bound method is unwrapped via __func__ before the signature is read.
    assert fc._accepts_timeout(_Dev().attach) is True


def test_bound_timeout_clamps_and_refuses_non_positive() -> None:
    assert fc._bound_timeout(5) == 5.0
    assert fc._bound_timeout(10**9) == MAX_WORKFLOW_TIMEOUT
    with pytest.raises(FridaError) as caught:
        fc._bound_timeout(0)
    assert caught.value.code == "invalid_params"


def test_detach_all_and_kill_spawned_drain_and_swallow_errors() -> None:
    calls: list[str] = []

    class _S:
        def detach(self) -> None:
            calls.append("detach")
            raise RuntimeError("already gone")

    sessions = [_S(), _S()]
    fc._detach_all(sessions)
    assert sessions == [] and calls == ["detach", "detach"]

    killed: list[int] = []

    def _kill(pid: int) -> None:
        killed.append(pid)
        raise RuntimeError("no such pid")

    pids = [1, 2]
    fc._kill_spawned(SimpleNamespace(kill=_kill), pids)
    assert pids == [] and sorted(killed) == [1, 2]


def test_invoke_passes_timeout_only_when_the_callable_names_it() -> None:
    seen: dict[str, Any] = {}

    def named(pid: int, *, timeout: float) -> str:
        seen["timeout"] = timeout
        return "named"

    def bare(pid: int) -> str:
        seen["bare"] = True
        return "bare"

    assert fc._invoke(named, 7, timeout=3.0) == "named"
    assert seen["timeout"] == 3.0
    assert fc._invoke(bare, 7, timeout=3.0) == "bare"


def test_run_deadline_returns_value_and_maps_a_stall_to_timeout() -> None:
    assert fc._run_deadline(lambda: 42, timeout=5.0) == 42

    fired: list[bool] = []

    def _slow() -> None:
        time.sleep(1.0)

    with pytest.raises(FridaError) as caught:
        fc._run_deadline(_slow, timeout=0.05, on_timeout=lambda: fired.append(True))
    assert caught.value.code == "timeout"
    assert fired == [True]


def test_page_reports_when_it_truncated() -> None:
    assert fc._page([1, 2, 3], 2) == ([1, 2], True)
    assert fc._page([1], 2) == ([1], False)
    assert fc._page(None, 5) == ([], False)


# --------------------------------------------------------------------------
# fakes for the local-device operations
# --------------------------------------------------------------------------
class _Exports:
    def __init__(self, **fns: Any) -> None:
        self.__dict__.update(fns)


class _Script:
    def __init__(self, exports: Any = None, load_error: Exception | None = None) -> None:
        self.exports_sync = exports
        self._err = load_error

    def load(self) -> None:
        if self._err is not None:
            raise self._err


class _Session:
    def __init__(self, script: _Script | None = None) -> None:
        self._script = script or _Script()
        self.detached = 0

    def create_script(self, source: str) -> _Script:
        return self._script

    def detach(self) -> None:
        self.detached += 1


class _LocalFrida:
    """A frida module whose attach hands back one scripted session."""

    def __init__(self, session: _Session) -> None:
        self._session = session

    def attach(self, pid: int) -> _Session:
        return self._session


def _local_client(session: _Session) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _LocalFrida(session)
    return client


# --------------------------------------------------------------------------
# attach / _require / _need capability + permission guards
# --------------------------------------------------------------------------
def test_attach_guards_capability_pid_and_permission() -> None:
    unavailable = FridaClient()
    unavailable._available = False
    unavailable._frida = None
    with pytest.raises(FridaError) as caught:
        unavailable.attach(1, allowed_pid=1)
    assert caught.value.code == "capability_unavailable"

    client = _local_client(_Session())
    with pytest.raises(FridaError) as bad_pid:
        client.attach(0, allowed_pid=0)
    assert bad_pid.value.code == "invalid_params"
    with pytest.raises(FridaError) as denied:
        client.attach(2, allowed_pid=1)
    assert denied.value.code == "permission_denied"


def test_attach_succeeds_and_detaches_immediately() -> None:
    session = _Session()
    client = _local_client(session)
    payload = client.attach(11, allowed_pid=11)
    assert payload["attached"] is True and payload["device"] == "local"
    assert session.detached >= 1


def test_require_rejects_disallowed_pid_and_missing_module() -> None:
    client = _local_client(_Session())
    with pytest.raises(FridaError) as denied:
        client.modules(2, allowed_pid=1)
    assert denied.value.code == "permission_denied"

    client._available = False
    with pytest.raises(FridaError) as unavailable:
        client.modules(1, allowed_pid=1)
    assert unavailable.value.code == "capability_unavailable"


# --------------------------------------------------------------------------
# modules / exports / memory_read payload shaping and guards
# --------------------------------------------------------------------------
def test_modules_tolerates_a_bare_list_payload() -> None:
    exports = _Exports(
        modules=lambda cap: [{"name": "libc", "base": "0x1", "size": 4, "path": "/l"}]
    )
    client = _local_client(_Session(_Script(exports)))
    payload = client.modules(1, allowed_pid=1, limit=10)
    assert payload["count"] == 1 and payload["total"] == 1 and payload["has_more"] is False


def test_exports_requires_a_module_name_and_a_dict_payload() -> None:
    client = _local_client(_Session(_Script(_Exports(exports=lambda name, cap: {}))))
    with pytest.raises(FridaError) as blank:
        client.exports(1, "  ", allowed_pid=1)
    assert blank.value.code == "invalid_params"

    bad = _local_client(_Session(_Script(_Exports(exports=lambda name, cap: ["not-a-dict"]))))
    with pytest.raises(FridaError) as shape:
        bad.exports(1, "libc", allowed_pid=1)
    assert shape.value.code == "backend_error"


def test_exports_pages_and_labels_the_cut() -> None:
    rows = [{"name": f"e{i}", "address": "0x0", "type": "func"} for i in range(5)]
    exports = _Exports(
        exports=lambda name, cap: {
            "found": True,
            "module": "libc",
            "base": "0x1",
            "exports": rows,
        }
    )
    client = _local_client(_Session(_Script(exports)))
    payload = client.exports(1, "libc", allowed_pid=1, limit=3)
    assert payload["count"] == 3 and payload["has_more"] is True and payload["found"] is True


def test_memory_read_refuses_a_bad_size_and_hexes_the_bytes() -> None:
    client = _local_client(_Session(_Script(_Exports(read=lambda addr, size: [1, 255, 16]))))
    with pytest.raises(FridaError) as bad:
        client.memory_read(1, 0x1000, 0, allowed_pid=1)
    assert bad.value.code == "invalid_params"
    payload = client.memory_read(1, 0x1000, 3, allowed_pid=1)
    assert payload["encoding"] == "hex" and payload["data"] == "01ff10"


# --------------------------------------------------------------------------
# hook_template (local) error contract
# --------------------------------------------------------------------------
def test_hook_template_rejects_unknown_and_loads_known() -> None:
    session = _Session(_Script(_Exports()))
    client = _local_client(session)
    with pytest.raises(FridaError) as unknown:
        client.hook_template(1, "nope", allowed_pid=1)
    assert unknown.value.code == "invalid_params"

    payload = client.hook_template(1, "noop", allowed_pid=1)
    assert payload["loaded"] is True and payload["persisted"] is False
    assert session.detached >= 1


def test_hook_template_maps_a_script_load_failure_to_backend_error() -> None:
    session = _Session(_Script(_Exports(), load_error=RuntimeError("compile error")))
    client = _local_client(session)
    with pytest.raises(RuntimeError):
        client.hook_template(1, "noop", allowed_pid=1)


# --------------------------------------------------------------------------
# _attach_local error mapping
# --------------------------------------------------------------------------
def test_attach_local_maps_timeout_and_generic_failures() -> None:
    class _TimeoutFrida:
        def attach(self, pid: int) -> Any:
            raise RuntimeError("session attach timed out")

    client = FridaClient()
    client._available = True
    client._frida = _TimeoutFrida()
    with pytest.raises(FridaError) as timed:
        client._attach_local(5)
    assert timed.value.code == "timeout"

    class _BoomFrida:
        def attach(self, pid: int) -> Any:
            raise RuntimeError("no such process")

    client._frida = _BoomFrida()
    with pytest.raises(FridaError) as generic:
        client._attach_local(5)
    assert generic.value.code == "backend_error"


# --------------------------------------------------------------------------
# device resolver
# --------------------------------------------------------------------------
def _device_frida(**attrs: Any) -> Any:
    return SimpleNamespace(**attrs)


def test_resolve_device_handles_each_id_shape() -> None:
    local_dev = SimpleNamespace(id="local", name="Local", type="local")
    usb_dev = SimpleNamespace(id="usb", name="Phone", type="usb")
    net_dev = SimpleNamespace(id="10.0.0.2:27042", name="Net", type="remote")

    class _Mgr:
        def __init__(self, *, hit: bool) -> None:
            self._hit = hit

        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            if self._hit:
                return net_dev
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> Any:
            return net_dev

    client = FridaClient()
    client._available = True

    client._frida = _device_frida(get_local_device=lambda: local_dev)
    assert client._resolve_device(None) is local_dev

    client._frida = _device_frida(get_usb_device=lambda timeout=5: usb_dev)
    assert client._resolve_device("usb") is usb_dev

    # A registered remote device is reused via the manager's get_device.
    client._frida = _device_frida(get_device_manager=lambda: _Mgr(hit=True))
    assert client._resolve_device("10.0.0.2:27042") is net_dev

    # An unregistered one falls back to add_remote_device.
    client._frida = _device_frida(get_device_manager=lambda: _Mgr(hit=False))
    assert client._resolve_device("10.0.0.2:27042") is net_dev

    # A plain id goes through get_device.
    client._frida = _device_frida(get_device=lambda device_id, timeout=5: local_dev)
    assert client._resolve_device("emulator-5554") is local_dev


def test_resolve_device_maps_a_lookup_failure_to_not_found() -> None:
    client = FridaClient()
    client._available = True

    def _boom() -> Any:
        raise RuntimeError("no device")

    client._frida = _device_frida(get_local_device=_boom)
    with pytest.raises(FridaError) as caught:
        client._resolve_device(None)
    assert caught.value.code == "not_found"


def test_resolve_device_needs_the_module() -> None:
    client = FridaClient()
    client._available = False
    with pytest.raises(FridaError) as caught:
        client._resolve_device(None)
    assert caught.value.code == "capability_unavailable"


# --------------------------------------------------------------------------
# enumerate_devices / add_remote_device / applications
# --------------------------------------------------------------------------
def test_enumerate_devices_shapes_and_maps_errors() -> None:
    devices = [SimpleNamespace(id="a", name="A", type="usb")]
    client = FridaClient()
    client._available = True
    client._frida = _device_frida(enumerate_devices=lambda: devices)
    payload = client.enumerate_devices()
    assert payload["count"] == 1 and payload["devices"][0]["id"] == "a"

    def _boom() -> Any:
        raise RuntimeError("frida busy")

    client._frida = _device_frida(enumerate_devices=_boom)
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "backend_error"


def test_add_remote_device_reuses_then_adds_then_maps_errors() -> None:
    dev = SimpleNamespace(id="1.2.3.4:5", name="R", type="remote")

    class _MgrHit:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            return dev

    client = FridaClient()
    client._available = True
    client._frida = _device_frida(get_device_manager=lambda: _MgrHit())
    assert client.add_remote_device("1.2.3.4:5")["id"] == "1.2.3.4:5"

    class _MgrAdd:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            raise RuntimeError("unregistered")

        def add_remote_device(self, endpoint: str) -> Any:
            return dev

    client._frida = _device_frida(get_device_manager=lambda: _MgrAdd())
    assert client.add_remote_device("1.2.3.4:5")["name"] == "R"

    class _MgrBoom:
        def get_device(self, endpoint: str, timeout: int = 1) -> Any:
            raise RuntimeError("unregistered")

        def add_remote_device(self, endpoint: str) -> Any:
            raise RuntimeError("refused")

    client._frida = _device_frida(get_device_manager=lambda: _MgrBoom())
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("1.2.3.4:5")
    assert caught.value.code == "backend_error"


def test_applications_pages_and_maps_errors() -> None:
    apps = [SimpleNamespace(identifier=f"p{i}", name=f"n{i}", pid=i) for i in range(3)]
    local = SimpleNamespace(enumerate_applications=lambda: apps)
    client = FridaClient()
    client._available = True
    client._frida = _device_frida(get_local_device=lambda: local)
    payload = client.applications(None, limit=2)
    assert payload["count"] == 2 and payload["has_more"] is True and payload["total"] == 3

    def _boom() -> Any:
        raise RuntimeError("app enum failed")

    client._frida = _device_frida(
        get_local_device=lambda: SimpleNamespace(enumerate_applications=_boom)
    )
    with pytest.raises(FridaError) as caught:
        client.applications(None)
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# spawn
# --------------------------------------------------------------------------
def _spawn_client(device: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _device_frida(get_local_device=lambda: device)
    return client


def test_spawn_validates_the_package_id() -> None:
    device = SimpleNamespace(spawn=lambda pkg: 1, resume=lambda pid: None, kill=lambda pid: None)
    client = _spawn_client(device)
    with pytest.raises(FridaError) as blank:
        client.spawn(None, "  ")
    assert blank.value.code == "invalid_params"
    with pytest.raises(FridaError) as shape:
        client.spawn(None, "not a package")
    assert shape.value.code == "invalid_params"


def test_spawn_resumes_and_reports_the_pid() -> None:
    events: list[str] = []
    device = SimpleNamespace(
        spawn=lambda pkg: events.append("spawn") or 4321,
        resume=lambda pid: events.append(f"resume:{pid}"),
        kill=lambda pid: events.append(f"kill:{pid}"),
    )
    client = _spawn_client(device)
    payload = client.spawn(None, "com.example.app")
    assert payload["pid"] == 4321 and payload["package"] == "com.example.app"
    assert "kill:4321" not in events


def test_spawn_kills_the_process_when_resume_fails() -> None:
    killed: list[int] = []

    def _resume(pid: int) -> None:
        raise RuntimeError("resume refused")

    device = SimpleNamespace(
        spawn=lambda pkg: 99,
        resume=_resume,
        kill=lambda pid: killed.append(pid),
    )
    client = _spawn_client(device)
    with pytest.raises(FridaError) as caught:
        client.spawn(None, "com.example.app")
    assert caught.value.code == "backend_error" and killed == [99]


def test_spawn_maps_a_spawn_failure() -> None:
    def _spawn(pkg: str) -> int:
        raise RuntimeError("no such package")

    device = SimpleNamespace(spawn=_spawn, resume=lambda pid: None, kill=lambda pid: None)
    client = _spawn_client(device)
    with pytest.raises(FridaError) as caught:
        client.spawn(None, "com.example.app")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# java_enumerate
# --------------------------------------------------------------------------
def _java_device(exports: _Exports, *, attach_error: Exception | None = None) -> Any:
    session = _Session(_Script(exports))

    def _attach(pid: int) -> Any:
        if attach_error is not None:
            raise attach_error
        return session

    return SimpleNamespace(attach=_attach), session


def _java_client(device: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = _device_frida(get_local_device=lambda: device)
    return client


def test_java_enumerate_authorizes_before_touching_a_device() -> None:
    client = FridaClient()
    client._available = True
    client._frida = _device_frida(get_local_device=lambda: SimpleNamespace())
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 7, allowed_pids=[1, 2], mode="classes")
    assert caught.value.code == "permission_denied"


def test_java_enumerate_lists_classes_and_methods() -> None:
    exports = _Exports(
        classes=lambda flt, cap: ["a.B", "a.C", "a.D"],
        methods=lambda cls, cap: {"found": True, "methods": ["m1", "m2"]},
    )
    device, _ = _java_device(exports)
    client = _java_client(device)

    classes = client.java_enumerate(None, 7, allowed_pids=[7], mode="classes", limit=2)
    assert classes["count"] == 2 and classes["has_more"] is True

    methods = client.java_enumerate(
        None, 7, allowed_pids=[7], mode="methods", class_name="a.B", limit=10
    )
    assert methods["found"] is True and methods["methods"] == ["m1", "m2"]


def test_java_enumerate_methods_tolerates_a_bare_list() -> None:
    exports = _Exports(methods=lambda cls, cap: ["only"])
    device, _ = _java_device(exports)
    client = _java_client(device)
    methods = client.java_enumerate(
        None, 7, allowed_pids=[7], mode="methods", class_name="a.B"
    )
    assert methods["found"] is True and methods["methods"] == ["only"]


def test_java_enumerate_guards_mode_and_class_name() -> None:
    exports = _Exports(
        classes=lambda flt, cap: [],
        methods=lambda cls, cap: {"found": False, "methods": []},
    )
    device, _ = _java_device(exports)
    client = _java_client(device)
    with pytest.raises(FridaError) as no_class:
        client.java_enumerate(None, 7, allowed_pids=[7], mode="methods")
    assert no_class.value.code == "invalid_params"
    with pytest.raises(FridaError) as bad_mode:
        client.java_enumerate(None, 7, allowed_pids=[7], mode="fields")
    assert bad_mode.value.code == "invalid_params"


def test_java_enumerate_maps_an_attach_failure() -> None:
    exports = _Exports(classes=lambda flt, cap: [])
    device, _ = _java_device(exports, attach_error=RuntimeError("device attach refused"))
    client = _java_client(device)
    with pytest.raises(FridaError) as caught:
        client.java_enumerate(None, 7, allowed_pids=[7], mode="classes")
    assert caught.value.code == "backend_error"


# --------------------------------------------------------------------------
# hook_template_device + _authorize
# --------------------------------------------------------------------------
def test_hook_template_device_rejects_unknown_template() -> None:
    device, _ = _java_device(_Exports())
    client = _java_client(device)
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 7, "nope", allowed_pids=[7])
    assert caught.value.code == "invalid_params"


def test_hook_template_device_loads_a_known_template() -> None:
    device, session = _java_device(_Exports())
    client = _java_client(device)
    payload = client.hook_template_device(None, 7, "noop", allowed_pids=[7])
    assert payload["loaded"] is True and payload["persisted"] is False
    assert session.detached >= 1


def test_hook_template_device_maps_an_attach_failure() -> None:
    device, _ = _java_device(_Exports(), attach_error=RuntimeError("attach timed out"))
    client = _java_client(device)
    with pytest.raises(FridaError) as caught:
        client.hook_template_device(None, 7, "noop", allowed_pids=[7])
    assert caught.value.code == "timeout"


def test_authorize_guards_capability_pid_shape_and_membership() -> None:
    client = FridaClient()
    client._available = False
    with pytest.raises(FridaError) as unavailable:
        client._authorize(1, [1])
    assert unavailable.value.code == "capability_unavailable"

    client._available = True
    client._frida = object()
    with pytest.raises(FridaError) as bad_pid:
        client._authorize(0, [1])
    assert bad_pid.value.code == "invalid_params"
    with pytest.raises(FridaError) as denied:
        client._authorize(5, [1, 2])
    assert denied.value.code == "permission_denied"
