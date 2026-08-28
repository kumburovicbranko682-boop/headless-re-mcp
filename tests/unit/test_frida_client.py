"""Device-free guards and device selection of FridaClient.

test_frida_client_helpers.py pins the module-level primitives; the service
authorization tests drive the service layer. What is left uncovered on the
client are the guards that run before any device I/O -- the capability gate, the
pid authorization that is the frida line's core security boundary, and each
method's parameter validation -- plus the _resolve_device routing that picks a
local, usb, or remote device. All of it raises (or chooses) before frida ever
touches a process, so it is exercised here with availability forced or a fake
frida module injected, never a real device or agent.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.backends.frida.client as frida_client
from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client(*, available: bool = True, frida: Any = "real") -> FridaClient:
    client = FridaClient()
    client._available = available
    if not available:
        client._frida = None
    elif frida != "real":
        client._frida = frida
    return client


def test_available_reflects_the_frida_import() -> None:
    assert _client().available is True
    assert _client(available=False).available is False


# --- attach guards --------------------------------------------------------


def test_attach_degrades_without_the_frida_module() -> None:
    client = _client(available=False)
    with pytest.raises(FridaError) as caught:
        client.attach(10, allowed_pid=10)
    assert caught.value.code == "capability_unavailable"


def test_attach_rejects_a_non_positive_pid() -> None:
    client = _client()
    with pytest.raises(FridaError) as caught:
        client.attach(0, allowed_pid=0)
    assert caught.value.code == "invalid_params"


def test_attach_refuses_a_pid_outside_the_session_debuggee() -> None:
    client = _client()
    with pytest.raises(FridaError) as caught:
        client.attach(1234, allowed_pid=999)
    assert caught.value.code == "permission_denied"
    assert caught.value.details["allowed_pid"] == 999


# --- method parameter guards (after _require, before any attach) ----------


def test_exports_requires_a_module_name() -> None:
    client = _client()
    with pytest.raises(FridaError) as caught:
        client.exports(10, "   ", allowed_pid=10)
    assert caught.value.code == "invalid_params"


def test_memory_read_bounds_the_size() -> None:
    client = _client()
    with pytest.raises(FridaError) as too_small:
        client.memory_read(10, 0x1000, 0, allowed_pid=10)
    assert too_small.value.code == "invalid_params"
    with pytest.raises(FridaError) as too_big:
        client.memory_read(10, 0x1000, 256 * 1024 + 1, allowed_pid=10)
    assert too_big.value.code == "invalid_params"


def test_hook_template_rejects_an_unknown_template() -> None:
    client = _client()
    with pytest.raises(FridaError) as caught:
        client.hook_template(10, "no_such_template", allowed_pid=10)
    assert caught.value.code == "invalid_params"
    assert "android_ssl_unpin" in caught.value.details["allowed"]


# --- _require / _need / _authorize ---------------------------------------


def test_require_gates_permission_before_capability() -> None:
    # Wrong pid is refused as permission_denied even when frida is present.
    client = _client()
    with pytest.raises(FridaError) as denied:
        client._require(5, 9)
    assert denied.value.code == "permission_denied"
    # Right pid but no frida module: capability_unavailable.
    absent = _client(available=False)
    with pytest.raises(FridaError) as unavailable:
        absent._require(5, 5)
    assert unavailable.value.code == "capability_unavailable"


def test_need_raises_without_the_frida_module() -> None:
    client = _client(available=False)
    with pytest.raises(FridaError) as caught:
        client._need()
    assert caught.value.code == "capability_unavailable"


def test_authorize_checks_capability_then_pid_then_membership() -> None:
    absent = _client(available=False)
    with pytest.raises(FridaError) as unavailable:
        absent._authorize(10, [10])
    assert unavailable.value.code == "capability_unavailable"

    client = _client()
    with pytest.raises(FridaError) as bad_pid:
        client._authorize(-1, [10])
    assert bad_pid.value.code == "invalid_params"

    with pytest.raises(FridaError) as denied:
        client._authorize(7, [10, 20])
    assert denied.value.code == "permission_denied"
    assert denied.value.details["allowed_pids"] == [10, 20]


def test_authorize_admits_a_pid_in_the_allow_set() -> None:
    client = _client()
    # No raise: the authorized pid passes the boundary.
    client._authorize(20, [10, 20])


# --- _resolve_device routing (fake frida module) --------------------------


class _FakeDevice:
    def __init__(self, id: str = "local", name: str = "Local", type: str = "local") -> None:
        self.id = id
        self.name = name
        self.type = type


class _FakeManager:
    def __init__(self, *, get: Any = None, add: Any = None) -> None:
        self._get = get
        self._add = add
        self.added: list[str] = []

    def get_device(self, device_id: str, timeout: int = 0) -> Any:
        del timeout
        if isinstance(self._get, BaseException):
            raise self._get
        return self._get

    def add_remote_device(self, endpoint: str) -> Any:
        self.added.append(endpoint)
        if isinstance(self._add, BaseException):
            raise self._add
        return self._add


class _FakeFrida:
    def __init__(self, **attrs: Any) -> None:
        self._attrs = attrs
        self.calls: list[str] = []

    def get_local_device(self) -> Any:
        self.calls.append("local")
        return self._attrs.get("local", _FakeDevice())

    def get_usb_device(self, timeout: int = 0) -> Any:
        del timeout
        self.calls.append("usb")
        value = self._attrs.get("usb")
        if isinstance(value, BaseException):
            raise value
        return value or _FakeDevice("usb", "USB", "usb")

    def get_device(self, device_id: str, timeout: int = 0) -> Any:
        del timeout
        self.calls.append(f"named:{device_id}")
        value = self._attrs.get("named")
        if isinstance(value, BaseException):
            raise value
        return value or _FakeDevice(device_id, device_id, "remote")

    def get_device_manager(self) -> Any:
        return self._attrs["manager"]


def test_resolve_device_maps_the_local_aliases() -> None:
    fake = _FakeFrida()
    client = _client(frida=fake)
    for alias in (None, "", "local"):
        device = client._resolve_device(alias)
        assert device.type == "local"
    assert fake.calls == ["local", "local", "local"]


def test_resolve_device_uses_the_usb_transport() -> None:
    fake = _FakeFrida()
    client = _client(frida=fake)
    assert client._resolve_device("usb").type == "usb"


def test_resolve_device_reuses_a_registered_remote_before_adding() -> None:
    registered = _FakeDevice("10.0.0.1:27042", "remote", "remote")
    manager = _FakeManager(get=registered)
    fake = _FakeFrida(manager=manager)
    client = _client(frida=fake)
    device = client._resolve_device("10.0.0.1:27042")
    assert device is registered
    assert manager.added == []  # get_device succeeded, so nothing was re-added


def test_resolve_device_adds_a_remote_when_not_yet_registered() -> None:
    added = _FakeDevice("10.0.0.1:27042", "remote", "remote")
    manager = _FakeManager(get=RuntimeError("not registered"), add=added)
    fake = _FakeFrida(manager=manager)
    client = _client(frida=fake)
    device = client._resolve_device("10.0.0.1:27042")
    assert device is added
    assert manager.added == ["10.0.0.1:27042"]


def test_resolve_device_maps_a_lookup_failure_to_not_found() -> None:
    fake = _FakeFrida(named=RuntimeError("no such device"))
    client = _client(frida=fake)
    with pytest.raises(FridaError) as caught:
        client._resolve_device("emulator-5554")
    assert caught.value.code == "not_found"
    assert caught.value.details["device_id"] == "emulator-5554"


def test_resolve_device_degrades_without_frida() -> None:
    client = _client(available=False)
    with pytest.raises(FridaError) as caught:
        client._resolve_device("usb")
    assert caught.value.code == "capability_unavailable"


# --- enumerate_devices / applications / add_remote_device -----------------


def test_enumerate_devices_shapes_and_counts() -> None:
    fake = _FakeFrida()
    fake.enumerate_devices = lambda: [  # type: ignore[attr-defined]
        _FakeDevice("local", "Local", "local"),
        _FakeDevice("usb", "USB", "usb"),
    ]
    client = _client(frida=fake)
    data = client.enumerate_devices()
    assert data["count"] == 2
    assert {d["type"] for d in data["devices"]} == {"local", "usb"}


def test_enumerate_devices_maps_failure_to_backend_error() -> None:
    fake = _FakeFrida()

    def _boom() -> Any:
        raise RuntimeError("manager down")

    fake.enumerate_devices = _boom  # type: ignore[attr-defined]
    client = _client(frida=fake)
    with pytest.raises(FridaError) as caught:
        client.enumerate_devices()
    assert caught.value.code == "backend_error"


def test_applications_pages_and_flags_more() -> None:
    class _App:
        def __init__(self, identifier: str, name: str, pid: int) -> None:
            self.identifier = identifier
            self.name = name
            self.pid = pid

    apps = [_App(f"com.app{i}", f"App{i}", i) for i in range(5)]

    class _Dev:
        def enumerate_applications(self) -> list[Any]:
            return apps

    fake = _FakeFrida(local=_Dev())
    client = _client(frida=fake)
    data = client.applications("local", limit=2)
    assert data["count"] == 2
    assert data["total"] == 5
    assert data["has_more"] is True


def test_applications_maps_failure_to_backend_error() -> None:
    class _Dev:
        def enumerate_applications(self) -> list[Any]:
            raise RuntimeError("no server")

    fake = _FakeFrida(local=_Dev())
    client = _client(frida=fake)
    with pytest.raises(FridaError) as caught:
        client.applications("local")
    assert caught.value.code == "backend_error"


def test_add_remote_device_reuses_then_adds() -> None:
    existing = _FakeDevice("h:1", "h", "remote")
    manager = _FakeManager(get=existing)
    fake = _FakeFrida(manager=manager)
    client = _client(frida=fake)
    data = client.add_remote_device("h:1")
    assert data["id"] == "h:1"

    manager2 = _FakeManager(get=RuntimeError("miss"), add=_FakeDevice("h:2", "h", "remote"))
    fake2 = _FakeFrida(manager=manager2)
    client2 = _client(frida=fake2)
    data2 = client2.add_remote_device("h:2")
    assert data2["id"] == "h:2"
    assert manager2.added == ["h:2"]


def test_add_remote_device_maps_total_failure_to_backend_error() -> None:
    # Both the reuse lookup and the add fail: the endpoint is reported, not a crash.
    manager = _FakeManager(get=RuntimeError("miss"), add=RuntimeError("cannot add"))
    fake = _FakeFrida(manager=manager)
    client = _client(frida=fake)
    with pytest.raises(FridaError) as caught:
        client.add_remote_device("h:3")
    assert caught.value.code == "backend_error"
    assert caught.value.details["endpoint"] == "h:3"


# --- attach-and-run bodies (fake session/script/device) ------------------
#
# The guard tests above stop before any attach. These drive the method bodies
# that attach, load a script, read its exports, and detach in a finally -- with
# frida replaced by fakes so no process is ever touched. That covers the shaping
# of each result, the disclosure that a probe hook does not persist, and the
# error/rollback branches (attach failure, script failure, timeout) that a live
# gate can only reach with a real device.


class _FakeScript:
    def __init__(self, exports: Any = None, *, load_error: BaseException | None = None) -> None:
        self._exports = exports
        self._load_error = load_error
        self.loaded = False

    @property
    def exports_sync(self) -> Any:
        return self._exports

    def load(self) -> None:
        if self._load_error is not None:
            raise self._load_error
        self.loaded = True


class _FakeSession:
    def __init__(self, script: _FakeScript | None = None) -> None:
        self._script = script if script is not None else _FakeScript()
        self.detached = 0

    def create_script(self, source: str) -> _FakeScript:
        del source
        return self._script

    def detach(self) -> None:
        self.detached += 1


def _raiser(exc: BaseException) -> Any:
    def _boom(*args: Any, **kwargs: Any) -> Any:
        del args, kwargs
        raise exc

    return _boom


def _local_frida(attach_result: Any) -> _FakeFrida:
    """A fake frida whose attach returns a session (or raises when given one)."""
    fake = _FakeFrida()

    def _attach(pid: int, timeout: float | None = None) -> Any:
        del pid, timeout
        if isinstance(attach_result, BaseException):
            raise attach_result
        return attach_result

    fake.attach = _attach  # type: ignore[attr-defined]
    return fake


class _FakeSpawnDevice:
    def __init__(
        self,
        *,
        spawn_result: int = 4321,
        spawn_error: BaseException | None = None,
        resume_error: BaseException | None = None,
    ) -> None:
        self._spawn_result = spawn_result
        self._spawn_error = spawn_error
        self._resume_error = resume_error
        self.resumed: list[int] = []
        self.killed: list[int] = []

    def spawn(self, package: str, timeout: float | None = None) -> int:
        del package, timeout
        if self._spawn_error is not None:
            raise self._spawn_error
        return self._spawn_result

    def resume(self, pid: int, timeout: float | None = None) -> None:
        del timeout
        if self._resume_error is not None:
            raise self._resume_error
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)


class _FakeAttachDevice:
    def __init__(self, session_or_exc: Any) -> None:
        self._value = session_or_exc

    def attach(self, pid: int, timeout: float | None = None) -> Any:
        del pid, timeout
        if isinstance(self._value, BaseException):
            raise self._value
        return self._value


# --- __init__ degradation -------------------------------------------------


def test_construction_degrades_when_frida_cannot_be_imported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "frida", None)
    client = FridaClient()
    assert client.available is False
    assert client._frida is None


# --- attach / modules / exports / memory_read (local) --------------------


def test_attach_returns_probe_disclosure_and_detaches() -> None:
    session = _FakeSession()
    client = _client(frida=_local_frida(session))
    data = client.attach(4321, allowed_pid=4321)
    assert data["attached"] is True
    assert data["device"] == "local"
    assert session.detached == 1


def test_attach_maps_a_backend_failure() -> None:
    client = _client(frida=_local_frida(RuntimeError("no ptrace")))
    with pytest.raises(FridaError) as caught:
        client.attach(4321, allowed_pid=4321)
    assert caught.value.code == "backend_error"
    assert "attach failed" in caught.value.message


def test_attach_maps_a_timeout_named_failure_to_timeout() -> None:
    client = _client(frida=_local_frida(RuntimeError("operation timed out")))
    with pytest.raises(FridaError) as caught:
        client.attach(4321, allowed_pid=4321)
    assert caught.value.code == "timeout"


def test_modules_shapes_and_flags_more_from_a_dict_payload() -> None:
    exports = SimpleNamespace(
        modules=lambda cap: {
            "modules": [{"name": "libc.so", "base": "0x1000", "size": 4096, "path": "/l"}],
            "total": 5,
        }
    )
    session = _FakeSession(_FakeScript(exports))
    client = _client(frida=_local_frida(session))
    data = client.modules(4321, allowed_pid=4321, limit=10)
    assert data["count"] == 1
    assert data["total"] == 5
    assert data["has_more"] is True
    assert data["modules"][0]["name"] == "libc.so"
    assert session.detached == 1


def test_exports_pages_and_skips_non_dict_items() -> None:
    exports = SimpleNamespace(
        exports=lambda name, cap: {
            "found": True,
            "module": "libc.so",
            "base": "0x1000",
            "exports": [
                {"name": "open", "address": "0x2000", "type": "function"},
                "not-a-dict",  # must be skipped, not shaped
            ],
        }
    )
    session = _FakeSession(_FakeScript(exports))
    client = _client(frida=_local_frida(session))
    data = client.exports(4321, "libc.so", allowed_pid=4321, limit=64)
    assert data["found"] is True
    assert data["count"] == 1
    assert data["exports"][0]["name"] == "open"


def test_exports_rejects_a_non_dict_payload() -> None:
    exports = SimpleNamespace(exports=lambda name, cap: ["not", "a", "dict"])
    session = _FakeSession(_FakeScript(exports))
    client = _client(frida=_local_frida(session))
    with pytest.raises(FridaError) as caught:
        client.exports(4321, "libc.so", allowed_pid=4321)
    assert caught.value.code == "backend_error"


def test_memory_read_returns_hex_encoded_bytes() -> None:
    exports = SimpleNamespace(read=lambda addr, size: [0xDE, 0xAD, 0xBE, 0xEF])
    session = _FakeSession(_FakeScript(exports))
    client = _client(frida=_local_frida(session))
    data = client.memory_read(4321, 0x1000, 4, allowed_pid=4321)
    assert data["encoding"] == "hex"
    assert data["data"] == "deadbeef"
    assert session.detached == 1


# --- hook_template (local): happy and error mapping ----------------------


def test_hook_template_loads_and_discloses_non_persistence() -> None:
    session = _FakeSession(_FakeScript(exports=None))
    client = _client(frida=_local_frida(session))
    data = client.hook_template(4321, "noop", allowed_pid=4321)
    assert data["loaded"] is True
    assert data["persisted"] is False
    assert session.detached == 1


def test_hook_template_reraises_a_frida_error_unchanged() -> None:
    client = _client(frida=_local_frida(FridaError("permission_denied", "blocked")))
    with pytest.raises(FridaError) as caught:
        client.hook_template(4321, "noop", allowed_pid=4321)
    assert caught.value.code == "permission_denied"


def test_hook_template_maps_a_timeout_named_failure() -> None:
    client = _client(frida=_local_frida(RuntimeError("attach timed out")))
    with pytest.raises(FridaError) as caught:
        client.hook_template(4321, "noop", allowed_pid=4321)
    assert caught.value.code == "timeout"


def test_hook_template_propagates_an_unexpected_error_unwrapped() -> None:
    # A non-timeout, non-FridaError escapes as-is; the service envelope maps it.
    client = _client(frida=_local_frida(RuntimeError("segfault in agent")))
    with pytest.raises(RuntimeError, match="segfault in agent"):
        client.hook_template(4321, "noop", allowed_pid=4321)


# --- _resolve_device: FridaError passthrough ------------------------------


def test_resolve_device_reraises_a_frida_error_from_the_transport() -> None:
    # A FridaError raised inside the try (e.g. a capability gate) must not be
    # relabelled not_found the way an arbitrary device error is.
    fake = _FakeFrida(usb=FridaError("capability_unavailable", "boom"))
    client = _client(frida=fake)
    with pytest.raises(FridaError) as caught:
        client._resolve_device("usb")
    assert caught.value.code == "capability_unavailable"


# --- spawn (device): package guard, happy, and rollback ------------------


def test_spawn_requires_a_package() -> None:
    client = _client()
    client._resolve_device = lambda device_id: _FakeSpawnDevice()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "   ")
    assert caught.value.code == "invalid_params"


def test_spawn_launches_resumes_and_returns_the_pid() -> None:
    dev = _FakeSpawnDevice(spawn_result=4321)
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    data = client.spawn("usb", "com.example.app")
    assert data["pid"] == 4321
    assert data["package"] == "com.example.app"
    assert dev.resumed == [4321]


def test_spawn_maps_a_spawn_failure_to_backend_error() -> None:
    dev = _FakeSpawnDevice(spawn_error=RuntimeError("no such package"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "backend_error"
    assert "spawn failed" in caught.value.message


def test_spawn_maps_a_spawn_timeout() -> None:
    dev = _FakeSpawnDevice(spawn_error=RuntimeError("spawn timed out"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"


def test_spawn_kills_the_process_when_resume_is_denied() -> None:
    dev = _FakeSpawnDevice(spawn_result=4321, resume_error=FridaError("permission_denied", "no"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "permission_denied"
    assert dev.killed == [4321]


def test_spawn_kills_the_process_on_a_resume_timeout() -> None:
    dev = _FakeSpawnDevice(spawn_result=4321, resume_error=RuntimeError("resume timed out"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == "timeout"
    assert dev.killed == [4321]


@pytest.mark.parametrize(
    ("message", "code"),
    [("unexpected boom", "backend_error"), ("deadline timed out", "timeout")],
)
def test_spawn_maps_an_unexpected_deadline_error(
    monkeypatch: pytest.MonkeyPatch, message: str, code: str
) -> None:
    # The defensive outer catch: if the bounded runner itself fails in a way
    # work() did not convert, spawn still maps it (and would kill any spawned
    # pid). Forced by making the runner raise directly.
    monkeypatch.setattr(frida_client, "_run_deadline", _raiser(RuntimeError(message)))
    client = _client()
    client._resolve_device = lambda device_id: _FakeSpawnDevice()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.spawn("usb", "com.example.app")
    assert caught.value.code == code


# --- java_enumerate (device): modes, guards, and errors ------------------


def test_java_enumerate_classes_pages_and_flags_more() -> None:
    exports = SimpleNamespace(
        classes=lambda flt, lim: ["a.A", "a.B", "a.C"], methods=lambda c, lim: []
    )
    dev = _FakeAttachDevice(_FakeSession(_FakeScript(exports)))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    data = client.java_enumerate(
        "usb", 4321, allowed_pids=[4321], mode="classes", name_filter="a", limit=2
    )
    assert data["count"] == 2
    assert data["has_more"] is True


def test_java_enumerate_methods_requires_a_class_name() -> None:
    exports = SimpleNamespace(classes=lambda flt, lim: [], methods=lambda c, lim: [])
    dev = _FakeAttachDevice(_FakeSession(_FakeScript(exports)))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4321, allowed_pids=[4321], mode="methods", class_name=None)
    assert caught.value.code == "invalid_params"


def test_java_enumerate_methods_returns_a_page() -> None:
    exports = SimpleNamespace(classes=lambda flt, lim: [], methods=lambda c, lim: ["m1()", "m2()"])
    dev = _FakeAttachDevice(_FakeSession(_FakeScript(exports)))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    data = client.java_enumerate(
        "usb", 4321, allowed_pids=[4321], mode="methods", class_name="com.X", limit=100
    )
    assert data["class_name"] == "com.X"
    assert data["count"] == 2
    assert data["has_more"] is False


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    exports = SimpleNamespace(classes=lambda flt, lim: [], methods=lambda c, lim: [])
    dev = _FakeAttachDevice(_FakeSession(_FakeScript(exports)))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4321, allowed_pids=[4321], mode="bogus")
    assert caught.value.code == "invalid_params"


def test_java_enumerate_maps_an_attach_failure() -> None:
    dev = _FakeAttachDevice(RuntimeError("attach denied"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4321, allowed_pids=[4321], mode="classes")
    assert caught.value.code == "backend_error"
    assert "attach failed" in caught.value.message


def test_java_enumerate_maps_an_attach_timeout() -> None:
    dev = _FakeAttachDevice(RuntimeError("attach timed out"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4321, allowed_pids=[4321], mode="classes")
    assert caught.value.code == "timeout"


def test_java_enumerate_maps_a_script_timeout() -> None:
    session = _FakeSession(_FakeScript(load_error=RuntimeError("script load timed out")))
    dev = _FakeAttachDevice(session)
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4321, allowed_pids=[4321], mode="classes")
    assert caught.value.code == "timeout"


def test_java_enumerate_maps_a_script_failure_to_backend_error() -> None:
    session = _FakeSession(_FakeScript(load_error=RuntimeError("script boom")))
    dev = _FakeAttachDevice(session)
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.java_enumerate("usb", 4321, allowed_pids=[4321], mode="classes")
    assert caught.value.code == "backend_error"
    assert "java enumeration failed" in caught.value.message
    # Detached in work()'s finally and again in the rollback sweep; both are safe.
    assert session.detached >= 1


# --- hook_template_device: happy and error mapping -----------------------


def test_hook_template_device_loads_and_detaches() -> None:
    session = _FakeSession(_FakeScript(exports=None))
    dev = _FakeAttachDevice(session)
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    data = client.hook_template_device("usb", 4321, "noop", allowed_pids=[4321])
    assert data["loaded"] is True
    assert data["persisted"] is False
    assert session.detached == 1


def test_hook_template_device_rejects_an_unknown_template() -> None:
    client = _client()
    client._resolve_device = lambda device_id: _FakeAttachDevice(_FakeSession())  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4321, "no_such", allowed_pids=[4321])
    assert caught.value.code == "invalid_params"


def test_hook_template_device_maps_an_attach_failure() -> None:
    dev = _FakeAttachDevice(RuntimeError("attach denied"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4321, "noop", allowed_pids=[4321])
    assert caught.value.code == "backend_error"
    assert "attach failed" in caught.value.message


def test_hook_template_device_maps_an_attach_timeout() -> None:
    dev = _FakeAttachDevice(RuntimeError("attach timed out"))
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4321, "noop", allowed_pids=[4321])
    assert caught.value.code == "timeout"


def test_hook_template_device_maps_a_script_failure() -> None:
    session = _FakeSession(_FakeScript(load_error=RuntimeError("script boom")))
    dev = _FakeAttachDevice(session)
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4321, "noop", allowed_pids=[4321])
    assert caught.value.code == "backend_error"
    assert "hook template failed" in caught.value.message
    assert session.detached >= 1


def test_hook_template_device_maps_a_script_timeout() -> None:
    session = _FakeSession(_FakeScript(load_error=RuntimeError("script load timed out")))
    dev = _FakeAttachDevice(session)
    client = _client()
    client._resolve_device = lambda device_id: dev  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.hook_template_device("usb", 4321, "noop", allowed_pids=[4321])
    assert caught.value.code == "timeout"
