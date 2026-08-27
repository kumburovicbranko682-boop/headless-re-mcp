"""_resolve_device is the one door every device-aware frida op goes through.

applications / spawn / java_enumerate / hook_template_device all resolve a
device before their own deadline starts, so the dispatch here -- which frida
lookup a given device_id maps to, and how a failed lookup is reported -- decides
the behaviour of the whole device surface. Two properties matter beyond "it
returns a device":

* a ``host:port`` id reuses an already-registered remote device instead of
  re-adding it on every call. add_remote_device churns frida's device manager
  for what is meant to be one stable connection held for the life of the
  session; the reuse path is only taken when the registered-device lookup
  succeeds, and add is the fallback when it does not.
* a lookup that cannot find the device is a ``not_found`` naming the id, not a
  raw frida exception that the service layer would mint an incident for.

These run with an injected fake frida module -- no USB, no emulator -- exactly
where the dispatch lives.
"""

from __future__ import annotations

from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


class _Device:
    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.id = tag
        self.name = tag
        self.type = "remote"


class _DeviceManager:
    """A frida device manager whose get_device either hits or misses."""

    def __init__(self, *, registered: bool) -> None:
        self._registered = registered
        self.calls: list[tuple[str, str]] = []

    def get_device(self, device_id: str, timeout: float | None = None) -> _Device:
        del timeout
        self.calls.append(("get_device", device_id))
        if not self._registered:
            raise RuntimeError("device is not registered")
        return _Device("reused")

    def add_remote_device(self, device_id: str) -> _Device:
        self.calls.append(("add_remote_device", device_id))
        return _Device("added")


class _FakeFrida:
    def __init__(self, *, registered: bool = True, fail_local: bool = False) -> None:
        self.calls: list[Any] = []
        self._mgr = _DeviceManager(registered=registered)
        self._fail_local = fail_local

    def get_local_device(self) -> _Device:
        self.calls.append("get_local_device")
        if self._fail_local:
            raise RuntimeError("no local device")
        return _Device("local")

    def get_usb_device(self, timeout: float | None = None) -> _Device:
        self.calls.append(("get_usb_device", timeout))
        return _Device("usb")

    def get_device(self, device_id: str, timeout: float | None = None) -> _Device:
        self.calls.append(("get_device", device_id, timeout))
        return _Device("generic")

    def get_device_manager(self) -> _DeviceManager:
        self.calls.append("get_device_manager")
        return self._mgr


def _client(frida: _FakeFrida) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


@pytest.mark.parametrize("device_id", [None, "", "local"])
def test_the_local_aliases_all_resolve_the_local_device(device_id: str | None) -> None:
    """None, empty, and the literal 'local' are the same request: the host."""
    frida = _FakeFrida()
    device = _client(frida)._resolve_device(device_id)
    assert device.tag == "local"
    assert frida.calls == ["get_local_device"]


def test_usb_resolves_the_usb_device_with_a_bounded_lookup() -> None:
    """'usb' maps to get_usb_device, carrying the short 5s lookup bound."""
    frida = _FakeFrida()
    device = _client(frida)._resolve_device("usb")
    assert device.tag == "usb"
    assert frida.calls == [("get_usb_device", 5)]


def test_a_plain_device_id_resolves_by_get_device() -> None:
    """A serial with no colon (an emulator/adb id) goes through get_device."""
    frida = _FakeFrida()
    device = _client(frida)._resolve_device("emulator-5554")
    assert device.tag == "generic"
    # A plain id never touches the device manager: no reuse/add churn.
    assert frida.calls == [("get_device", "emulator-5554", 5)]


def test_a_registered_remote_device_is_reused_not_re_added() -> None:
    """A host:port already registered is returned without add_remote_device.

    Re-adding a remote device on every call churns frida's device manager for
    a connection meant to be stable, so the reuse path must be taken whenever
    the registered-device lookup succeeds -- add is never reached.
    """
    frida = _FakeFrida(registered=True)
    device = _client(frida)._resolve_device("10.0.0.5:27042")
    assert device.tag == "reused"
    assert frida._mgr.calls == [("get_device", "10.0.0.5:27042")]
    assert all(call[0] != "add_remote_device" for call in frida._mgr.calls)


def test_an_unregistered_remote_device_falls_back_to_adding_it() -> None:
    """When the registered lookup misses, the host:port is added once.

    The reuse lookup is best-effort; a miss is not a failure, it just means the
    device manager has not seen this endpoint yet, so add_remote_device is the
    fallback -- and it runs only after the reuse attempt, not instead of it.
    """
    frida = _FakeFrida(registered=False)
    device = _client(frida)._resolve_device("10.0.0.5:27042")
    assert device.tag == "added"
    assert frida._mgr.calls == [
        ("get_device", "10.0.0.5:27042"),
        ("add_remote_device", "10.0.0.5:27042"),
    ]


def test_a_device_that_cannot_be_resolved_is_not_found() -> None:
    """A raw frida lookup failure becomes a not_found naming the id.

    Left unclassified, the frida exception reaches the service's BaseException
    arm as an internal_error plus a logged incident; a device that is simply not
    there is a lookup outcome, so it is reported as not_found with the device_id
    the caller asked for.
    """
    frida = _FakeFrida(fail_local=True)
    with pytest.raises(FridaError) as caught:
        _client(frida)._resolve_device("local")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("device_id") == "local"
