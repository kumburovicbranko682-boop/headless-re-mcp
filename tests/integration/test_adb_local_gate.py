"""Live adb gate: exercise the adbutils integration without a device.

adbutils is the Android device backend's only dependency, and its 1.x -> 2.x
rewrite moved the very calls this backend makes (``AdbClient.list``,
``AdbClient.connect``) -- the same kind of drift that silently broke the Frida
read path. Two operations need no attached device: listing (empty, but the call
must still run) and connecting to an endpoint with nothing behind it. adbutils
ships and auto-spawns its own adb server, so this runs on a bare machine and
skips honestly when adbutils is absent (skip != pass).
"""

from __future__ import annotations

import socket

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend
from headless_re_mcp.core.service import AnalysisService


def _dead_port() -> int:
    """A port nothing is listening on, so connect() must be refused."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.integration
def test_adb_lists_devices_and_refuses_a_dead_endpoint() -> None:
    if not AdbBackend().available:
        pytest.skip("adbutils not installed — adb Gate not run (skip != pass)")

    service = AnalysisService()
    try:
        listed = service.device_list()
        if not listed.ok:
            # adbutils is present but its bundled adb could not start a server
            # here (e.g. no runnable binary for this arch); that is not a code
            # defect, so skip rather than fail.
            code = listed.error.code if listed.error else "unknown"
            pytest.skip(f"adb server unavailable ({code}) — adb Gate not run (skip != pass)")

        # AdbClient.list() drift would break this shape or raise; with no device
        # attached the list is empty, but count must track the rows either way.
        devices = listed.data["devices"]
        assert isinstance(devices, list)
        assert listed.data["count"] == len(devices)
        assert isinstance(listed.data["has_more"], bool)
        for row in devices:
            assert isinstance(row.get("serial"), str)
            assert isinstance(row.get("state"), str)

        # A dead endpoint must surface as a failure, not an ok envelope whose
        # connected flag is false: the service turns adbutils' status string
        # into backend_error so a caller cannot mistake "refused" for "a device
        # is attached" and go on to install onto nothing.
        connected = service.device_connect("127.0.0.1", _dead_port())
        assert connected.ok is False
        assert connected.error is not None
        assert connected.error.code == "backend_error"
        assert "connect failed" in connected.error.message
    finally:
        service.close_all()
