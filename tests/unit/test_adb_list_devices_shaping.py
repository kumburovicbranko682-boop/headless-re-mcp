"""AdbBackend.list_devices must shape rows the same across adbutils versions.

``list_devices`` accepts whatever the installed adbutils hands back: newer
releases expose ``client.list()`` returning objects with ``serial`` / ``state``,
some return ``(serial, state)`` tuples, and older ones only offer
``device_list()`` of connected devices. ``_device_info_row`` is the shim that
flattens all three to ``{"serial", "state"}``, and the result is capped at
``_MAX_DEVICES`` with a ``has_more`` flag. A shim that quietly returns blank
serials after an adbutils upgrade would make every device unaddressable while
the call still looks like it succeeded, so the shapes are pinned here with a
fake client -- no adbutils, no emulator.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.backends.adb.client import _MAX_DEVICES, AdbBackend


class _Info:
    def __init__(self, serial: str, state: str) -> None:
        self.serial = serial
        self.state = state


class _ListClient:
    """A modern adbutils client: list() yields rows to shape."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def list(self) -> list[Any]:
        return self._rows


class _DeviceListOnlyClient:
    """An older client with no list(), only device_list() of connected devices."""

    def __init__(self, devices: list[Any]) -> None:
        self._devices = devices

    def device_list(self) -> list[Any]:
        return self._devices


def _backend_with_client(client: Any) -> AdbBackend:
    backend = AdbBackend()
    backend._available = True
    backend._client = lambda **kwargs: client  # type: ignore[method-assign]
    return backend


def test_attribute_style_rows_are_shaped() -> None:
    """Objects with serial/state flatten to those two fields.

    The page is sorted by serial (adb does not promise a stable order), so
    ``abc123`` precedes ``emulator-5554`` regardless of input order.
    """
    client = _ListClient([_Info("emulator-5554", "device"), _Info("abc123", "unauthorized")])
    payload = _backend_with_client(client).list_devices()
    assert payload["devices"] == [
        {"serial": "abc123", "state": "unauthorized"},
        {"serial": "emulator-5554", "state": "device"},
    ]
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_tuple_style_rows_are_shaped() -> None:
    """(serial, state) tuples flatten the same way as objects.

    Sorted by serial, ``192.168.0.2:5555`` precedes ``emulator-5554``.
    """
    client = _ListClient([("emulator-5554", "device"), ("192.168.0.2:5555", "offline")])
    payload = _backend_with_client(client).list_devices()
    assert payload["devices"] == [
        {"serial": "192.168.0.2:5555", "state": "offline"},
        {"serial": "emulator-5554", "state": "device"},
    ]


def test_a_row_without_state_reads_as_unknown() -> None:
    """A blank state becomes 'unknown' rather than an empty string."""
    client = _ListClient([_Info("emulator-5554", "")])
    payload = _backend_with_client(client).list_devices()
    assert payload["devices"] == [{"serial": "emulator-5554", "state": "unknown"}]


def test_device_list_fallback_when_there_is_no_list_method() -> None:
    """An older client without list() is read through device_list()."""
    client = _DeviceListOnlyClient([_Info("emulator-5554", "ignored")])
    payload = _backend_with_client(client).list_devices()
    # The fallback reports connected devices, so state is the constant "device".
    assert payload["devices"] == [{"serial": "emulator-5554", "state": "device"}]
    assert payload["count"] == 1


def test_the_device_list_is_capped_and_flags_the_overflow() -> None:
    """More devices than the cap are paged, with has_more set."""
    rows = [_Info(f"emulator-{index}", "device") for index in range(_MAX_DEVICES + 5)]
    payload = _backend_with_client(_ListClient(rows)).list_devices()
    assert payload["count"] == _MAX_DEVICES
    assert len(payload["devices"]) == _MAX_DEVICES
    assert payload["has_more"] is True


def test_exactly_the_cap_is_not_flagged_as_overflow() -> None:
    """A count that exactly fills the cap is complete, not partial."""
    rows = [_Info(f"emulator-{index}", "device") for index in range(_MAX_DEVICES)]
    payload = _backend_with_client(_ListClient(rows)).list_devices()
    assert payload["count"] == _MAX_DEVICES
    assert payload["has_more"] is False
