"""FridaClient's device-resolution path and its error taxonomy, with a fake frida.

The device operations that serve the Android line -- enumerate_devices,
_resolve_device (local / usb / serial / remote host:port) and the public
add_remote_device -- were only reachable with the real frida module installed,
so on a box without it they never ran. The service-layer tests
(test_frida_service_envelopes) deliberately stub the whole FridaClient, so they
exercise service_frida's envelopes but never this resolution logic. The frida
Python module is not installed in this environment, so these inject a fake frida
into a real client (the same `client._available = True; client._frida = ...`
seam test_frida_attach_fields uses) and pin the branches that matter to an
unattended agent: which lookup each device_id selects, that a remote endpoint is
reused before it is re-added, and that a lookup failure is mapped to a precise
envelope (not_found for a resolve, backend_error for an enumerate) rather than
leaking a raw frida exception up the RPC loop.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _device(dev_id: str = "d0", name: str = "Pixel", dtype: str = "usb") -> SimpleNamespace:
    return SimpleNamespace(id=dev_id, name=name, type=dtype)


def _client_with(frida_obj: Any) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida_obj
    return client


def _raise(exc: BaseException) -> Any:
    def _fn(*_args: Any, **_kwargs: Any) -> Any:
        raise exc

    return _fn


def test_enumerate_devices_shapes_each_row_and_counts_them() -> None:
    """The payload is {devices:[{id,name,type}], count}; id/name/type are coerced
    to str so a frida device whose fields are enum-like objects still serialise."""
    fake = SimpleNamespace(
        enumerate_devices=lambda: [_device("local", "Local", "local"), _device("emulator-5554")]
    )
    result = _client_with(fake).enumerate_devices()
    assert result == {
        "devices": [
            {"id": "local", "name": "Local", "type": "local"},
            {"id": "emulator-5554", "name": "Pixel", "type": "usb"},
        ],
        "count": 2,
    }


def test_enumerate_devices_maps_a_backend_fault_to_backend_error() -> None:
    """A frida that cannot list devices must surface backend_error, not the raw
    exception -- the RPC loop hands the caller an envelope, never a traceback."""
    fake = SimpleNamespace(enumerate_devices=_raise(RuntimeError("frida daemon down")))
    with pytest.raises(FridaError) as caught:
        _client_with(fake).enumerate_devices()
    assert caught.value.code == "backend_error"
    assert "frida daemon down" in caught.value.message


def test_resolve_device_none_empty_and_local_all_take_the_local_lookup() -> None:
    """None, "" and "local" are the local device; the other lookups must not run,
    so a fake that only defines get_local_device proves the branch selection."""
    local = _device("local")
    fake = SimpleNamespace(get_local_device=lambda: local)
    client = _client_with(fake)
    assert client._resolve_device(None) is local
    assert client._resolve_device("") is local
    assert client._resolve_device("local") is local


def test_resolve_device_usb_takes_the_usb_lookup() -> None:
    """"usb" resolves via get_usb_device, which the client calls with a timeout=
    kwarg the fake must accept -- a positional-only fake would falsely fail here."""
    usb = _device("usb-serial")
    fake = SimpleNamespace(get_usb_device=lambda timeout=None: usb)
    assert _client_with(fake)._resolve_device("usb") is usb


def test_resolve_device_plain_serial_takes_the_get_device_lookup() -> None:
    """A serial with no ":" is neither local nor remote; it goes to get_device."""
    target = _device("R58NxxYY")
    fake = SimpleNamespace(get_device=lambda device_id, timeout=None: target)
    assert _client_with(fake)._resolve_device("R58NxxYY") is target


def test_resolve_device_remote_endpoint_is_reused_before_it_is_re_added() -> None:
    """A host:port device already registered must be fetched from the manager, not
    re-added: re-adding on every call churns frida's device manager for what is
    meant to be a stable connection. add_remote_device must not be touched."""
    remote = _device("10.0.0.5:27042", "Remote", "remote")
    added: list[str] = []
    mgr = SimpleNamespace(
        get_device=lambda device_id, timeout=None: remote,
        add_remote_device=lambda endpoint: added.append(endpoint),
    )
    fake = SimpleNamespace(get_device_manager=lambda: mgr)
    assert _client_with(fake)._resolve_device("10.0.0.5:27042") is remote
    assert added == []


def test_resolve_device_remote_endpoint_is_added_when_not_yet_registered() -> None:
    """When the manager has no such device yet, the failed reuse is swallowed and
    the endpoint is added -- the first connect to a remote frida-server."""
    added = _device("10.0.0.5:27042", "Remote", "remote")
    mgr = SimpleNamespace(
        get_device=_raise(RuntimeError("device not found in manager")),
        add_remote_device=lambda endpoint: added,
    )
    fake = SimpleNamespace(get_device_manager=lambda: mgr)
    assert _client_with(fake)._resolve_device("10.0.0.5:27042") is added


def test_resolve_device_maps_a_lookup_failure_to_not_found_with_the_id() -> None:
    """A device that cannot be resolved is not_found (the id the caller asked for
    rides along in details), never a leaked frida exception."""
    fake = SimpleNamespace(get_device=_raise(RuntimeError("no device")))
    with pytest.raises(FridaError) as caught:
        _client_with(fake)._resolve_device("ghost-serial")
    assert caught.value.code == "not_found"
    assert caught.value.details.get("device_id") == "ghost-serial"


def test_add_remote_device_reuses_a_registered_endpoint_and_shapes_the_row() -> None:
    """The public add_remote_device returns {id,name,type}; a registered endpoint
    is returned from the manager without a second add."""
    remote = _device("box:27042", "Box", "remote")
    added: list[str] = []
    mgr = SimpleNamespace(
        get_device=lambda endpoint, timeout=None: remote,
        add_remote_device=lambda endpoint: added.append(endpoint),
    )
    fake = SimpleNamespace(get_device_manager=lambda: mgr)
    result = _client_with(fake).add_remote_device("box:27042")
    assert result == {"id": "box:27042", "name": "Box", "type": "remote"}
    assert added == []


def test_add_remote_device_adds_when_absent_then_shapes_the_row() -> None:
    """A not-yet-registered endpoint falls through the suppressed reuse to add."""
    added = _device("box:27042", "Box", "remote")
    mgr = SimpleNamespace(
        get_device=_raise(RuntimeError("not registered")),
        add_remote_device=lambda endpoint: added,
    )
    fake = SimpleNamespace(get_device_manager=lambda: mgr)
    result = _client_with(fake).add_remote_device("box:27042")
    assert result == {"id": "box:27042", "name": "Box", "type": "remote"}


def test_add_remote_device_maps_an_add_failure_to_backend_error_with_endpoint() -> None:
    """When both the reuse and the add fail, the caller gets backend_error carrying
    the endpoint -- the honest "this host:port never came up" signal."""
    mgr = SimpleNamespace(
        get_device=_raise(RuntimeError("not registered")),
        add_remote_device=_raise(RuntimeError("connection refused")),
    )
    fake = SimpleNamespace(get_device_manager=lambda: mgr)
    with pytest.raises(FridaError) as caught:
        _client_with(fake).add_remote_device("10.0.0.9:1")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("endpoint") == "10.0.0.9:1"


def test_applications_maps_an_enumeration_fault_to_backend_error() -> None:
    """applications resolves the device, then enumerates; a device that refuses the
    enumeration must map to backend_error rather than leak the frida exception."""

    class _BadDevice:
        id = "local"
        name = "Local"
        type = "local"

        def enumerate_applications(self) -> list[Any]:
            raise RuntimeError("app enumeration refused")

    fake = SimpleNamespace(get_local_device=lambda: _BadDevice())
    with pytest.raises(FridaError) as caught:
        _client_with(fake).applications("local", limit=10)
    assert caught.value.code == "backend_error"
    assert "app enumeration refused" in caught.value.message
