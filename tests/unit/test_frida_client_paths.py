"""Runtime arms of the Frida client, driven by an injected fake module.

The frida Python module is optional and not installed in CI, so the existing
suite pins only the static script content and the closed-session envelopes.
Everything that runs against a live frida -- attach/detach bookkeeping, the
signature-aware ``_invoke`` deadline shim, ``_run_deadline`` timeout handling,
device resolution, and the enumerate/spawn/hook operations plus their error
translation -- goes unrun. These inject a fake ``_frida`` module and fake
devices/sessions/scripts so those arms execute without a frida runtime.
"""

from __future__ import annotations

import sys
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import (
    _ENUM_SCRIPT,
    FridaClient,
    FridaError,
    _accepts_timeout,
    _bound_timeout,
    _detach_all,
    _invoke,
    _is_timeout,
    _kill_spawned,
    _page,
    _run_deadline,
)
from headless_re_mcp.core.limits import MAX_WORKFLOW_TIMEOUT

# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _FakeExports:
    def __init__(self, **values: Any) -> None:
        self._values = values

    def _pick(self, key: str, *call_args: Any) -> Any:
        value = self._values.get(key)
        if isinstance(value, Exception):
            raise value
        if callable(value):
            return value(*call_args)
        return value

    def modules(self, limit: int) -> Any:
        return self._pick("modules", limit)

    def exports(self, name: str, limit: int) -> Any:
        return self._pick("exports", name, limit)

    def read(self, address: int, size: int) -> Any:
        return self._pick("read", address, size)

    def classes(self, name_filter: str, limit: int) -> Any:
        return self._pick("classes", name_filter, limit)

    def methods(self, class_name: str, limit: int) -> Any:
        return self._pick("methods", class_name, limit)


class _FakeScript:
    def __init__(self, exports: _FakeExports | None, load_error: Exception | None) -> None:
        self.exports_sync = exports if exports is not None else _FakeExports()
        self._load_error = load_error
        self.loaded = False

    def load(self) -> None:
        if self._load_error is not None:
            raise self._load_error
        self.loaded = True


class _FakeSession:
    def __init__(
        self, exports: _FakeExports | None = None, *, load_error: Exception | None = None
    ) -> None:
        self._exports = exports
        self._load_error = load_error
        self.detached = False
        self.source: str | None = None

    def create_script(self, source: str) -> _FakeScript:
        self.source = source
        return _FakeScript(self._exports, self._load_error)

    def detach(self) -> None:
        self.detached = True


class _FakeDevice:
    def __init__(
        self,
        *,
        session: _FakeSession | None = None,
        attach_error: Exception | None = None,
        spawn_pid: int | None = None,
        spawn_error: Exception | None = None,
        resume_error: Exception | None = None,
        apps: Any = None,
    ) -> None:
        self._session = session
        self._attach_error = attach_error
        self._spawn_pid = spawn_pid
        self._spawn_error = spawn_error
        self._resume_error = resume_error
        self._apps = apps
        self.killed: list[int] = []
        self.resumed: list[int] = []

    def attach(self, pid: int, timeout: float | None = None) -> _FakeSession:
        del timeout
        if self._attach_error is not None:
            raise self._attach_error
        assert self._session is not None
        return self._session

    def spawn(self, package: str, timeout: float | None = None) -> int:
        del package, timeout
        if self._spawn_error is not None:
            raise self._spawn_error
        assert self._spawn_pid is not None
        return self._spawn_pid

    def resume(self, pid: int, timeout: float | None = None) -> None:
        del timeout
        if self._resume_error is not None:
            raise self._resume_error
        self.resumed.append(pid)

    def kill(self, pid: int) -> None:
        self.killed.append(pid)

    def enumerate_applications(self) -> Any:
        if isinstance(self._apps, Exception):
            raise self._apps
        return self._apps or []


class _FakeManager:
    def __init__(
        self,
        *,
        device: _FakeDevice | None = None,
        get_error: Exception | None = None,
        add_device: _FakeDevice | None = None,
        add_error: Exception | None = None,
    ) -> None:
        self._device = device
        self._get_error = get_error
        self._add_device = add_device
        self._add_error = add_error

    def get_device(self, device_id: str, timeout: float | None = None) -> _FakeDevice:
        del device_id, timeout
        if self._get_error is not None:
            raise self._get_error
        assert self._device is not None
        return self._device

    def add_remote_device(self, endpoint: str) -> _FakeDevice:
        del endpoint
        if self._add_error is not None:
            raise self._add_error
        assert self._add_device is not None
        return self._add_device


class _FakeFrida:
    def __init__(
        self,
        *,
        session: _FakeSession | None = None,
        attach_error: Exception | None = None,
        device: _FakeDevice | None = None,
        manager: _FakeManager | None = None,
        devices: Any = None,
    ) -> None:
        self._session = session
        self._attach_error = attach_error
        self._device = device
        self._manager = manager
        self._devices = devices

    def attach(self, pid: int, timeout: float | None = None) -> _FakeSession:
        del pid, timeout
        if self._attach_error is not None:
            raise self._attach_error
        assert self._session is not None
        return self._session

    def get_local_device(self) -> _FakeDevice:
        assert self._device is not None
        return self._device

    def get_usb_device(self, timeout: float | None = None) -> _FakeDevice:
        del timeout
        assert self._device is not None
        return self._device

    def get_device(self, device_id: str, timeout: float | None = None) -> _FakeDevice:
        del device_id, timeout
        assert self._device is not None
        return self._device

    def get_device_manager(self) -> _FakeManager:
        assert self._manager is not None
        return self._manager

    def enumerate_devices(self) -> Any:
        if isinstance(self._devices, Exception):
            raise self._devices
        return self._devices or []


def _client_with(frida: _FakeFrida) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


def test_accepts_timeout_names_timeout_only() -> None:
    def explicit(pid: int, timeout: float | None = None) -> None: ...
    def varkw(pid: int, **kwargs: Any) -> None: ...

    assert _accepts_timeout(explicit) is True
    # **kwargs is for spawn aux options, not a deadline -- must not count.
    assert _accepts_timeout(varkw) is False
    assert _accepts_timeout(object()) is False


def test_bound_timeout_rejects_non_positive_and_caps() -> None:
    with pytest.raises(FridaError) as exc:
        _bound_timeout(0)
    assert exc.value.code == "invalid_params"
    assert _bound_timeout(5.0) == 5.0
    assert _bound_timeout(10_000.0) == MAX_WORKFLOW_TIMEOUT


def test_is_timeout_reads_name_and_message() -> None:
    assert _is_timeout(TimeoutError("x")) is True
    assert _is_timeout(RuntimeError("it timed out")) is True
    assert _is_timeout(RuntimeError("offline")) is False


def test_page_flags_truncation() -> None:
    assert _page([1, 2, 3], 2) == ([1, 2], True)
    assert _page([1, 2], 5) == ([1, 2], False)
    assert _page(None, 5) == ([], False)


def test_detach_all_and_kill_spawned_drain_their_lists() -> None:
    sessions = [_FakeSession(), _FakeSession()]
    handles = list(sessions)
    _detach_all(handles)
    assert handles == []
    assert all(session.detached for session in sessions)

    device = _FakeDevice()
    pids = [1, 2, 3]
    _kill_spawned(device, pids)
    assert pids == []
    assert sorted(device.killed) == [1, 2, 3]


def test_invoke_passes_timeout_only_when_named() -> None:
    def named(value: int, timeout: float | None = None) -> tuple[int, float | None]:
        return value, timeout

    assert _invoke(named, 7, timeout=3.0) == (7, 3.0)

    def bare(value: int) -> int:
        return value

    assert _invoke(bare, 7, timeout=3.0) == 7


def test_run_deadline_returns_the_result_and_bounds_a_hang() -> None:
    assert _run_deadline(lambda: 42, timeout=1.0) == 42

    started = threading.Event()
    release = threading.Event()
    fired: list[str] = []

    def blocks() -> int:
        started.set()
        release.wait(2.0)
        return 0

    with pytest.raises(FridaError) as exc:
        _run_deadline(blocks, timeout=0.05, on_timeout=lambda: fired.append("stopped"))
    assert exc.value.code == "timeout"
    assert fired == ["stopped"]
    release.set()


def test_run_deadline_bounds_a_hang_without_an_on_timeout() -> None:
    release = threading.Event()
    with pytest.raises(FridaError) as exc:
        _run_deadline(lambda: release.wait(2.0), timeout=0.05)
    assert exc.value.code == "timeout"
    release.set()


# --------------------------------------------------------------------------- #
# _require / _authorize / _need guards
# --------------------------------------------------------------------------- #


def test_require_rejects_a_foreign_pid_and_missing_module() -> None:
    frida = _FakeFrida(session=_FakeSession())
    client = _client_with(frida)
    with pytest.raises(FridaError) as exc:
        client.modules(99, allowed_pid=1)
    assert exc.value.code == "permission_denied"

    client._available = False
    with pytest.raises(FridaError) as exc:
        client.modules(1, allowed_pid=1)
    assert exc.value.code == "capability_unavailable"


def test_authorize_checks_module_pid_and_allow_set() -> None:
    frida = _FakeFrida(device=_FakeDevice(session=_FakeSession()))
    client = _client_with(frida)
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", -1, allowed_pids=[1], mode="classes")
    assert exc.value.code == "invalid_params"

    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 42, allowed_pids=[1, 2], mode="classes")
    assert exc.value.code == "permission_denied"

    client._available = False
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 1, allowed_pids=[1], mode="classes")
    assert exc.value.code == "capability_unavailable"


def test_need_reports_capability_unavailable() -> None:
    client = FridaClient()
    client._available = False
    with pytest.raises(FridaError) as exc:
        client.enumerate_devices()
    assert exc.value.code == "capability_unavailable"


def test_available_property_reflects_the_flag() -> None:
    client = FridaClient()
    client._available = True
    assert client.available is True
    client._available = False
    assert client.available is False


def test_available_is_false_when_the_frida_import_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the lazy ``import frida`` in ``__init__`` to fail so the
    # module-absent degradation arm runs whether or not frida is installed. In
    # CI frida is genuinely absent; the android extra (a supported config)
    # ships it, so forcing the import keeps this branch covered there too.
    monkeypatch.setitem(sys.modules, "frida", None)
    client = FridaClient()
    assert client.available is False
    assert client._frida is None


# --------------------------------------------------------------------------- #
# attach / modules / exports / memory_read
# --------------------------------------------------------------------------- #


def test_attach_validates_and_reports_a_probe_attach() -> None:
    unavailable = FridaClient()
    unavailable._available = False
    with pytest.raises(FridaError) as exc:
        unavailable.attach(1, allowed_pid=1)
    assert exc.value.code == "capability_unavailable"

    session = _FakeSession()
    client = _client_with(_FakeFrida(session=session))
    with pytest.raises(FridaError) as exc:
        client.attach(0, allowed_pid=0)
    assert exc.value.code == "invalid_params"

    with pytest.raises(FridaError) as exc:
        client.attach(5, allowed_pid=9)
    assert exc.value.code == "permission_denied"

    payload = client.attach(7, allowed_pid=7)
    assert payload["attached"] is True
    assert payload["device"] == "local"
    assert session.detached is True  # detached in the finally


def test_modules_shapes_a_dict_payload_and_flags_more() -> None:
    exports = _FakeExports(
        modules={
            "modules": [
                {"name": "a.so", "base": "0x1", "size": 10, "path": "/a.so"},
                {"name": "b.so", "base": "0x2", "size": 20, "path": "/b.so"},
                "not-a-dict",
            ],
            "total": 9,
        }
    )
    client = _client_with(_FakeFrida(session=_FakeSession(exports)))
    payload = client.modules(3, allowed_pid=3, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 9
    assert payload["has_more"] is True
    assert payload["modules"][0]["name"] == "a.so"


def test_modules_tolerates_a_bare_list_payload() -> None:
    exports = _FakeExports(
        modules=[{"name": "only.so", "base": "0x1", "size": 4, "path": "/only.so"}]
    )
    client = _client_with(_FakeFrida(session=_FakeSession(exports)))
    payload = client.modules(3, allowed_pid=3)
    assert payload["total"] == 1
    assert payload["has_more"] is False


def test_exports_requires_a_module_name() -> None:
    client = _client_with(_FakeFrida(session=_FakeSession(_FakeExports())))
    with pytest.raises(FridaError) as exc:
        client.exports(3, "  ", allowed_pid=3)
    assert exc.value.code == "invalid_params"


def test_exports_rejects_a_non_dict_payload() -> None:
    exports = _FakeExports(exports=["not", "a", "dict"])
    client = _client_with(_FakeFrida(session=_FakeSession(exports)))
    with pytest.raises(FridaError) as exc:
        client.exports(3, "libc.so", allowed_pid=3)
    assert exc.value.code == "backend_error"


def test_exports_pages_and_skips_non_dict_entries() -> None:
    exports = _FakeExports(
        exports={
            "found": True,
            "module": "libc.so",
            "base": "0x1000",
            "exports": [
                {"name": "open", "address": "0x1", "type": "function"},
                "junk",
                {"name": "close", "address": "0x2", "type": "function"},
            ],
        }
    )
    client = _client_with(_FakeFrida(session=_FakeSession(exports)))
    payload = client.exports(3, "libc.so", allowed_pid=3, limit=10)
    assert payload["found"] is True
    assert payload["module"] == "libc.so"
    assert [item["name"] for item in payload["exports"]] == ["open", "close"]


def test_memory_read_validates_size_and_returns_hex() -> None:
    exports = _FakeExports(read=[0xDE, 0xAD, 0xBE, 0xEF])
    client = _client_with(_FakeFrida(session=_FakeSession(exports)))
    with pytest.raises(FridaError) as exc:
        client.memory_read(3, 0x1000, 0, allowed_pid=3)
    assert exc.value.code == "invalid_params"

    payload = client.memory_read(3, 0x1000, 4, allowed_pid=3)
    assert payload["encoding"] == "hex"
    assert payload["data"] == "deadbeef"


def test_attach_local_maps_timeout_and_backend_errors() -> None:
    # A message-based timeout (not the builtin TimeoutError, which is the same
    # object concurrent.futures raises for the outer deadline) exercises the
    # method's own _is_timeout arm rather than _run_deadline's deadline path.
    timeout_client = _client_with(_FakeFrida(attach_error=RuntimeError("attach timed out")))
    with pytest.raises(FridaError) as exc:
        timeout_client.modules(3, allowed_pid=3)
    assert exc.value.code == "timeout"

    broken_client = _client_with(_FakeFrida(attach_error=RuntimeError("no such process")))
    with pytest.raises(FridaError) as exc:
        broken_client.modules(3, allowed_pid=3)
    assert exc.value.code == "backend_error"


def test_attach_local_passes_a_frida_error_through() -> None:
    original = FridaError("permission_denied", "sandboxed")
    client = _client_with(_FakeFrida(attach_error=original))
    with pytest.raises(FridaError) as exc:
        client.modules(3, allowed_pid=3)
    assert exc.value.code == "permission_denied"


# --------------------------------------------------------------------------- #
# hook_template (local)
# --------------------------------------------------------------------------- #


def test_hook_template_rejects_an_unknown_template() -> None:
    client = _client_with(_FakeFrida(session=_FakeSession()))
    with pytest.raises(FridaError) as exc:
        client.hook_template(3, "does-not-exist", allowed_pid=3)
    assert exc.value.code == "invalid_params"


def test_hook_template_loads_and_discloses_non_persistence() -> None:
    session = _FakeSession()
    client = _client_with(_FakeFrida(session=session))
    payload = client.hook_template(3, "noop", allowed_pid=3)
    assert payload["loaded"] is True
    assert payload["persisted"] is False
    assert session.detached is True


def test_hook_template_maps_a_timeout_from_attach() -> None:
    client = _client_with(_FakeFrida(attach_error=RuntimeError("attach timed out")))
    with pytest.raises(FridaError) as exc:
        client.hook_template(3, "noop", allowed_pid=3)
    assert exc.value.code == "timeout"


def test_hook_template_passes_a_frida_error_through() -> None:
    session = _FakeSession(load_error=FridaError("backend_error", "script rejected"))
    client = _client_with(_FakeFrida(session=session))
    with pytest.raises(FridaError) as exc:
        client.hook_template(3, "noop", allowed_pid=3)
    assert exc.value.code == "backend_error"


def test_hook_template_reraises_a_non_timeout_exception() -> None:
    client = _client_with(_FakeFrida(attach_error=RuntimeError("weird frida state")))
    with pytest.raises(RuntimeError):
        client.hook_template(3, "noop", allowed_pid=3)


# --------------------------------------------------------------------------- #
# device resolution
# --------------------------------------------------------------------------- #


def test_resolve_device_handles_local_usb_and_default() -> None:
    device = _FakeDevice(session=_FakeSession())
    client = _client_with(_FakeFrida(device=device))
    assert client._resolve_device(None) is device
    assert client._resolve_device("usb") is device
    assert client._resolve_device("emulator-5554") is device


def test_resolve_device_reuses_a_registered_remote_device() -> None:
    device = _FakeDevice(session=_FakeSession())
    manager = _FakeManager(device=device)
    client = _client_with(_FakeFrida(manager=manager))
    assert client._resolve_device("10.0.0.2:27042") is device


def test_resolve_device_adds_a_remote_device_when_lookup_misses() -> None:
    added = _FakeDevice(session=_FakeSession())
    manager = _FakeManager(get_error=RuntimeError("not registered"), add_device=added)
    client = _client_with(_FakeFrida(manager=manager))
    assert client._resolve_device("10.0.0.2:27042") is added


def test_resolve_device_maps_a_failure_to_not_found() -> None:
    class _BoomFrida(_FakeFrida):
        def get_local_device(self) -> Any:
            raise RuntimeError("frida-server unreachable")

    client = _client_with(_BoomFrida())
    with pytest.raises(FridaError) as exc:
        client._resolve_device(None)
    assert exc.value.code == "not_found"


def test_resolve_device_passes_a_frida_error_through() -> None:
    class _FridaErrFrida(_FakeFrida):
        def get_local_device(self) -> Any:
            raise FridaError("capability_unavailable", "no local device")

    client = _client_with(_FridaErrFrida())
    with pytest.raises(FridaError) as exc:
        client._resolve_device(None)
    assert exc.value.code == "capability_unavailable"


# --------------------------------------------------------------------------- #
# enumerate_devices / add_remote_device / applications
# --------------------------------------------------------------------------- #


def test_enumerate_devices_shapes_and_maps_failure() -> None:
    devices = [
        SimpleNamespace(id="local", name="Local System", type="local"),
        SimpleNamespace(id="usb", name="Phone", type="usb"),
    ]
    client = _client_with(_FakeFrida(devices=devices))
    payload = client.enumerate_devices()
    assert payload["count"] == 2
    assert payload["devices"][1]["name"] == "Phone"

    broken = _client_with(_FakeFrida(devices=RuntimeError("manager gone")))
    with pytest.raises(FridaError) as exc:
        broken.enumerate_devices()
    assert exc.value.code == "backend_error"


def test_add_remote_device_reuses_then_adds_then_reports() -> None:
    existing = _FakeDevice(session=_FakeSession())
    existing_ns = SimpleNamespace(id="10.0.0.2:27042", name="remote", type="remote")

    class _Existing(_FakeManager):
        def get_device(self, endpoint: str, timeout: float | None = None) -> Any:
            del endpoint, timeout
            return existing_ns

    client = _client_with(_FakeFrida(manager=_Existing()))
    payload = client.add_remote_device("10.0.0.2:27042")
    assert payload["id"] == "10.0.0.2:27042"
    assert existing is not None  # keeps the fixture referenced


def test_add_remote_device_falls_back_to_add_when_lookup_misses() -> None:
    added = SimpleNamespace(id="10.0.0.3:27042", name="fresh", type="remote")
    manager = _FakeManager(get_error=RuntimeError("miss"), add_device=added)  # type: ignore[arg-type]
    client = _client_with(_FakeFrida(manager=manager))
    payload = client.add_remote_device("10.0.0.3:27042")
    assert payload["name"] == "fresh"


def test_add_remote_device_maps_a_failure_to_backend_error() -> None:
    manager = _FakeManager(
        get_error=RuntimeError("miss"), add_error=RuntimeError("refused connection")
    )
    client = _client_with(_FakeFrida(manager=manager))
    with pytest.raises(FridaError) as exc:
        client.add_remote_device("10.0.0.9:27042")
    assert exc.value.code == "backend_error"


def test_add_remote_device_passes_a_frida_error_through() -> None:
    manager = _FakeManager(
        get_error=RuntimeError("miss"),
        add_error=FridaError("capability_unavailable", "device manager gone"),
    )
    client = _client_with(_FakeFrida(manager=manager))
    with pytest.raises(FridaError) as exc:
        client.add_remote_device("10.0.0.9:27042")
    assert exc.value.code == "capability_unavailable"


def test_applications_shapes_pages_and_maps_failure() -> None:
    apps = [
        SimpleNamespace(identifier="com.a", name="A", pid=100),
        SimpleNamespace(identifier="com.b", name="B", pid=0),
        SimpleNamespace(identifier="com.c", name="C", pid=300),
    ]
    device = _FakeDevice(session=_FakeSession(), apps=apps)
    client = _client_with(_FakeFrida(device=device))
    payload = client.applications("local", limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 3
    assert payload["has_more"] is True

    broken_device = _FakeDevice(session=_FakeSession(), apps=RuntimeError("enum failed"))
    broken = _client_with(_FakeFrida(device=broken_device))
    with pytest.raises(FridaError) as exc:
        broken.applications("local")
    assert exc.value.code == "backend_error"


# --------------------------------------------------------------------------- #
# spawn
# --------------------------------------------------------------------------- #


def test_spawn_requires_a_valid_android_package() -> None:
    device = _FakeDevice(session=_FakeSession(), spawn_pid=4321)
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.spawn("local", "   ")
    assert exc.value.code == "invalid_params"

    with pytest.raises(FridaError) as exc:
        client.spawn("local", "not a package")
    assert exc.value.code == "invalid_params"


def test_spawn_resumes_and_reports_the_pid() -> None:
    device = _FakeDevice(session=_FakeSession(), spawn_pid=4321)
    client = _client_with(_FakeFrida(device=device))
    payload = client.spawn("local", "com.example.app")
    assert payload["pid"] == 4321
    assert device.resumed == [4321]


def test_spawn_maps_a_spawn_failure_and_a_timeout() -> None:
    timeout_device = _FakeDevice(session=_FakeSession(), spawn_error=TimeoutError("slow usb"))
    client = _client_with(_FakeFrida(device=timeout_device))
    with pytest.raises(FridaError) as exc:
        client.spawn("local", "com.example.app")
    assert exc.value.code == "timeout"

    broken_device = _FakeDevice(session=_FakeSession(), spawn_error=RuntimeError("no such pkg"))
    client = _client_with(_FakeFrida(device=broken_device))
    with pytest.raises(FridaError) as exc:
        client.spawn("local", "com.example.app")
    assert exc.value.code == "backend_error"


def test_spawn_kills_the_process_when_resume_fails() -> None:
    device = _FakeDevice(
        session=_FakeSession(), spawn_pid=4321, resume_error=RuntimeError("resume broke")
    )
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.spawn("local", "com.example.app")
    assert exc.value.code == "backend_error"
    assert device.killed == [4321]


def test_spawn_kills_and_reports_timeout_when_resume_times_out() -> None:
    device = _FakeDevice(
        session=_FakeSession(), spawn_pid=4321, resume_error=TimeoutError("resume hung")
    )
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.spawn("local", "com.example.app")
    assert exc.value.code == "timeout"
    assert device.killed == [4321]


def test_spawn_kills_and_passes_a_frida_error_from_resume() -> None:
    device = _FakeDevice(
        session=_FakeSession(),
        spawn_pid=4321,
        resume_error=FridaError("permission_denied", "cannot resume"),
    )
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.spawn("local", "com.example.app")
    assert exc.value.code == "permission_denied"
    assert device.killed == [4321]


# --------------------------------------------------------------------------- #
# java_enumerate
# --------------------------------------------------------------------------- #


def test_java_enumerate_classes_pages() -> None:
    exports = _FakeExports(classes=["com.a.X", "com.a.Y", "com.a.Z"])
    device = _FakeDevice(session=_FakeSession(exports))
    client = _client_with(_FakeFrida(device=device))
    payload = client.java_enumerate("local", 3, allowed_pids=[3], mode="classes", limit=2)
    assert payload["count"] == 2
    assert payload["has_more"] is True


def test_java_enumerate_methods_dict_and_bare_forms() -> None:
    dict_exports = _FakeExports(methods={"found": True, "methods": ["m1", "m2"]})
    device = _FakeDevice(session=_FakeSession(dict_exports))
    client = _client_with(_FakeFrida(device=device))
    payload = client.java_enumerate(
        "local", 3, allowed_pids=[3], mode="methods", class_name="com.a.X"
    )
    assert payload["found"] is True
    assert payload["methods"] == ["m1", "m2"]

    bare_exports = _FakeExports(methods=["only"])
    device = _FakeDevice(session=_FakeSession(bare_exports))
    client = _client_with(_FakeFrida(device=device))
    payload = client.java_enumerate(
        "local", 3, allowed_pids=[3], mode="methods", class_name="com.a.X"
    )
    assert payload["found"] is True
    assert payload["methods"] == ["only"]


def test_java_enumerate_methods_requires_a_class_name() -> None:
    device = _FakeDevice(session=_FakeSession(_FakeExports()))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 3, allowed_pids=[3], mode="methods")
    assert exc.value.code == "invalid_params"


def test_java_enumerate_rejects_an_unknown_mode() -> None:
    device = _FakeDevice(session=_FakeSession(_FakeExports()))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 3, allowed_pids=[3], mode="bogus")
    assert exc.value.code == "invalid_params"


def test_java_enumerate_maps_an_attach_failure() -> None:
    device = _FakeDevice(attach_error=RuntimeError("attach refused"))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 3, allowed_pids=[3], mode="classes")
    assert exc.value.code == "backend_error"


def test_java_enumerate_maps_an_attach_timeout() -> None:
    device = _FakeDevice(attach_error=RuntimeError("attach timed out"))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 3, allowed_pids=[3], mode="classes")
    assert exc.value.code == "timeout"


def test_java_enumerate_wraps_an_unexpected_script_failure() -> None:
    exports = _FakeExports(classes=RuntimeError("script blew up"))
    device = _FakeDevice(session=_FakeSession(exports))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 3, allowed_pids=[3], mode="classes")
    assert exc.value.code == "backend_error"


def test_java_enumerate_wraps_a_script_timeout() -> None:
    exports = _FakeExports(classes=RuntimeError("enumeration timed out"))
    device = _FakeDevice(session=_FakeSession(exports))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.java_enumerate("local", 3, allowed_pids=[3], mode="classes")
    assert exc.value.code == "timeout"


# --------------------------------------------------------------------------- #
# hook_template_device
# --------------------------------------------------------------------------- #


def test_hook_template_device_rejects_an_unknown_template() -> None:
    device = _FakeDevice(session=_FakeSession())
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.hook_template_device("local", 3, "nope", allowed_pids=[3])
    assert exc.value.code == "invalid_params"


def test_hook_template_device_loads_and_discloses() -> None:
    session = _FakeSession()
    device = _FakeDevice(session=session)
    client = _client_with(_FakeFrida(device=device))
    payload = client.hook_template_device("emulator-5554", 3, "noop", allowed_pids=[3])
    assert payload["loaded"] is True
    assert payload["persisted"] is False
    assert payload["device"] == "emulator-5554"
    assert session.detached is True


def test_hook_template_device_maps_an_attach_timeout() -> None:
    device = _FakeDevice(attach_error=TimeoutError("attach hung"))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.hook_template_device("local", 3, "noop", allowed_pids=[3])
    assert exc.value.code == "timeout"


def test_hook_template_device_maps_an_attach_backend_error() -> None:
    device = _FakeDevice(attach_error=RuntimeError("attach refused"))
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.hook_template_device("local", 3, "noop", allowed_pids=[3])
    assert exc.value.code == "backend_error"


def test_hook_template_device_wraps_an_unexpected_load_failure() -> None:
    session = _FakeSession(load_error=RuntimeError("script rejected"))
    device = _FakeDevice(session=session)
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.hook_template_device("local", 3, "noop", allowed_pids=[3])
    assert exc.value.code == "backend_error"


def test_hook_template_device_wraps_a_load_timeout() -> None:
    session = _FakeSession(load_error=RuntimeError("load timed out"))
    device = _FakeDevice(session=session)
    client = _client_with(_FakeFrida(device=device))
    with pytest.raises(FridaError) as exc:
        client.hook_template_device("local", 3, "noop", allowed_pids=[3])
    assert exc.value.code == "timeout"


def test_enum_script_is_the_source_the_session_receives() -> None:
    # The read path is pinned statically elsewhere; confirm the client actually
    # feeds that script to the session it creates.
    session = _FakeSession(_FakeExports(modules={"modules": [], "total": 0}))
    client = _client_with(_FakeFrida(session=session))
    client.modules(3, allowed_pid=3)
    assert session.source == _ENUM_SCRIPT
