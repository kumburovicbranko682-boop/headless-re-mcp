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

from typing import Any

import pytest

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
