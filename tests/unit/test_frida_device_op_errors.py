"""A raw frida failure in a device-discovery op is a backend_error, not an incident.

enumerate_devices / applications / add_remote_device each drive a frida call
that can fail outright -- a frida-server that is unreachable, a device that goes
offline mid-enumeration, a remote endpoint that refuses both the registered
lookup and a fresh add. Left unclassified, those raw frida exceptions reach the
service's BaseException arm as internal_error plus a logged incident, which
reads as a fault in this process rather than the device outcome it is. Every one
of these ops must name it a backend_error, the same code the enumeration and
attach paths already use, so the reply is honest and no incident is minted for a
device that was simply not answering.

These run with an injected fake frida module (or a fake resolved device) -- no
USB, no emulator -- exactly where the classification lives.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.frida.client import FridaClient, FridaError


def _client(frida: object) -> FridaClient:
    client = FridaClient()
    client._available = True
    client._frida = frida
    return client


def test_enumerate_devices_classifies_a_raw_frida_failure() -> None:
    """frida.enumerate_devices raising becomes a backend_error, not an incident."""

    class _Frida:
        def enumerate_devices(self) -> list[object]:
            raise RuntimeError("frida-server unreachable")

    with pytest.raises(FridaError) as caught:
        _client(_Frida()).enumerate_devices()
    assert caught.value.code == "backend_error"
    assert "enumerate devices" in caught.value.message


def test_applications_classifies_a_device_that_fails_mid_enumeration() -> None:
    """A device that goes offline while listing apps is a backend_error.

    applications resolves a device (already pinned elsewhere) and then calls
    enumerate_applications; a failure there is the device's, so it is classified
    rather than surfaced raw.
    """

    class _Device:
        def enumerate_applications(self) -> list[object]:
            raise RuntimeError("device offline")

    client = FridaClient()
    client._available = True
    client._frida = object()
    client._resolve_device = lambda device_id: _Device()  # type: ignore[method-assign]
    with pytest.raises(FridaError) as caught:
        client.applications("usb")
    assert caught.value.code == "backend_error"
    assert "enumerate applications" in caught.value.message


def test_add_remote_device_classifies_when_both_lookup_and_add_fail() -> None:
    """A remote endpoint that refuses reuse and a fresh add is a backend_error.

    add_remote_device tries the registered-device lookup first and falls back to
    add_remote_device on the manager; when both raise -- an endpoint that is
    unreachable, not merely unregistered -- the failure is a backend_error that
    carries the endpoint the caller named.
    """

    class _Manager:
        def get_device(self, endpoint: str, timeout: int = 1) -> object:
            del endpoint, timeout
            raise RuntimeError("not registered")

        def add_remote_device(self, endpoint: str) -> object:
            del endpoint
            raise RuntimeError("connection refused")

    class _Frida:
        def get_device_manager(self) -> _Manager:
            return _Manager()

    with pytest.raises(FridaError) as caught:
        _client(_Frida()).add_remote_device("10.0.0.1:27042")
    assert caught.value.code == "backend_error"
    assert caught.value.details.get("endpoint") == "10.0.0.1:27042"
