"""Device-control live gate: the parts that need no phone actually work.

The ADB and Frida-device surfaces (``device.*`` / ``frida.devices``) had only
mocked coverage, so nothing proved the real client integrations still work
against the installed adbutils / frida -- both of which change APIs across
versions (the ADB client already carries fallbacks for ``AdbClient`` kwargs and
``list`` vs ``device_list``). Full device operations (install/shell/logcat/
spawn/java) need a real device or emulator and stay uncovered here, but the
device-independent entry points do not, and those are what this gate exercises:

* ``device.list`` talks to a real adb server (adbutils vendors the adb binary
  and auto-starts the daemon) and returns a well-formed, empty device list.
* ``device.connect`` to a refused local port surfaces as an envelope failure --
  the documented contract that a status string from adb is not "connected".
* ``frida.devices`` enumerates the always-present local device.

It skips honestly when adbutils / frida are absent -- skip != pass.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend
from headless_re_mcp.backends.frida.client import FridaClient
from headless_re_mcp.core.service import AnalysisService


def _adb_available() -> bool:
    return AdbBackend().available


def _frida_available() -> bool:
    return FridaClient().available


def _closed_local_port() -> int:
    """A port with nothing listening, so a connect gets an immediate refusal."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="module")
def _service() -> Iterator[AnalysisService]:
    service = AnalysisService()
    try:
        yield service
    finally:
        service.close_all()


@pytest.mark.integration
def test_device_list_reaches_a_real_adb_server(_service: AnalysisService) -> None:
    if not _adb_available():
        pytest.skip("adbutils not installed — Device Control Gate not run (skip != pass)")
    result = _service.device_list()
    assert result.ok, result.error
    data = result.data
    assert isinstance(data["devices"], list)
    # No phone attached here, so the list is empty -- but it must be a real,
    # well-formed answer from the server, not a mock: count tracks the list and
    # has_more is a bool. That the call returns at all proves adbutils started
    # its vendored adb daemon and the list path parsed the reply.
    assert data["count"] == len(data["devices"])
    assert isinstance(data["has_more"], bool)


@pytest.mark.integration
def test_device_connect_to_a_closed_port_fails_closed(_service: AnalysisService) -> None:
    if not _adb_available():
        pytest.skip("adbutils not installed — Device Control Gate not run (skip != pass)")
    dead = _closed_local_port()

    # Backend contract: adb returns a status string, not an exception, and the
    # client reports connected=False rather than pretending a device appeared.
    raw = AdbBackend().connect("127.0.0.1", dead)
    assert raw["connected"] is False
    assert raw["endpoint"].endswith(str(dead))
    assert raw["result"]

    # Service contract: a refused connect is an envelope failure, so a caller
    # that only checks ok never proceeds to operate on a device that is not there.
    result = _service.device_connect(host="127.0.0.1", port=dead)
    assert not result.ok
    assert result.error is not None


@pytest.mark.integration
def test_frida_devices_lists_the_local_device(_service: AnalysisService) -> None:
    if not _frida_available():
        pytest.skip("frida not installed — Device Control Gate not run (skip != pass)")
    result = _service.frida_devices()
    assert result.ok, result.error
    devices = result.data["devices"]
    assert result.data["count"] == len(devices)
    for row in devices:
        assert row["id"]
        assert isinstance(row["name"], str)
        assert isinstance(row["type"], str)
    # The local device is always present; it is the entry point for every
    # device-aware frida call, so its absence would mean the manager is broken.
    local = [row for row in devices if row["id"] == "local"]
    assert local, devices
    assert local[0]["type"] == "local"
