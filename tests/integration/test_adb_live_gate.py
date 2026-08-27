"""Live ADB gate: the adbutils server layer, exercised without a real device.

The adb backend (device.* tools) had no real-backend coverage at all -- every
test drove stubs -- so the parts most likely to break on an adbutils release
bump ran against nothing: AdbClient construction (with the socket_timeout
kwarg and its older-adbutils fallback), the list() vs device_list() shape
fallback, the connect status heuristic, and the mapping of a missing device to
a structured error. That is the same class of break frida 17 was: a client-lib
API drift no stub reproduces.

adbutils ships its own adb binary and auto-spawns a local server, so the whole
server-communication layer runs on a stock machine with no phone attached: an
empty device list, a refused connect to a dead port, hostile inputs rejected,
and an unknown serial surfaced as a structured error rather than a raw
exception. adbutils absent, it skips (skip != pass); a real device attached,
the no-device assertions skip rather than misreport.
"""

from __future__ import annotations

import contextlib
import subprocess
from collections.abc import Iterator

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.core.service import AnalysisService


@pytest.fixture(scope="module", autouse=True)
def _kill_spawned_adb_server() -> Iterator[None]:
    """Stop the adb daemon these tests auto-spawn, so the gate leaks no server.

    adbutils starts a local adb server (tcp:5037) on first use and it outlives
    the process; a bundled adb is always present, so kill-server through it is
    the honest teardown. Best-effort: a failure here must not fail the gate.
    """
    yield
    import adbutils

    adb_path = getattr(adbutils, "adb_path", None)
    if callable(adb_path):
        with contextlib.suppress(Exception):
            subprocess.run([adb_path(), "kill-server"], timeout=15, check=False)


def _backend_or_skip() -> AdbBackend:
    backend = AdbBackend()
    if not backend.available:
        pytest.skip("adbutils not installed — ADB server Gate not run (skip != pass)")
    return backend


@pytest.mark.integration
def test_adb_backend_server_layer_without_a_device() -> None:
    """list/connect/validation/missing-device against the real adbutils server."""
    backend = _backend_or_skip()

    # list_devices reaches a real adb server and returns the paged shape. This
    # is the path with the list()/device_list() fallback and the socket_timeout
    # client kwarg -- the adbutils-version-sensitive plumbing.
    listed = backend.list_devices()
    assert isinstance(listed["devices"], list)
    assert listed["count"] == len(listed["devices"])
    assert isinstance(listed["has_more"], bool)
    if listed["count"] != 0:
        pytest.skip("a real device is attached — no-device path not run (skip!=pass)")

    # A refused connect is a structured result, never an exception, and the
    # connected heuristic reads the adb status string as "not connected". Port 1
    # has nothing behind it on any host, so this is deterministic.
    refused = backend.connect("127.0.0.1", 1)
    assert refused["connected"] is False
    assert refused["endpoint"] == "127.0.0.1:1"
    assert "refused" in refused["result"].lower() or "cannot connect" in refused["result"].lower()

    # Hostile inputs are rejected as invalid_params. connect reaches the server
    # for the client, then refuses the out-of-range port; a serial with a space
    # and a bang can never smuggle shell arguments.
    for bad_port in (0, 70000):
        with pytest.raises(AdbError) as caught:
            backend.connect("127.0.0.1", bad_port)
        assert caught.value.code == "invalid_params"
    with pytest.raises(AdbError) as bad_serial:
        backend.info("bad serial!!")
    assert bad_serial.value.code == "invalid_params"

    # An unknown serial is a structured backend_error (adb "device not found"),
    # not a raw adbutils exception the service would file as internal_error.
    with pytest.raises(AdbError) as missing:
        backend.info("emulator-9999")
    assert missing.value.code == "backend_error"


@pytest.mark.integration
def test_adb_service_layer_envelopes_a_dead_connect_as_failure() -> None:
    """device.* tools: ok envelope for an empty list, failure for a dead connect."""
    _backend_or_skip()
    service = AnalysisService()
    try:
        listed = service.device_list()
        assert listed.ok, listed.error
        data = listed.data if isinstance(listed.data, dict) else {}
        if data.get("count", 0) != 0:
            pytest.skip("a real device is attached — no-device path not run (skip!=pass)")
        assert data["devices"] == []

        # The service upgrades adbutils' non-raising "connected: false" status to
        # a real failure, so a caller reading only .ok cannot mistake a dead
        # endpoint for a live device it can install onto.
        connected = service.device_connect("127.0.0.1", 1)
        assert connected.ok is False
        assert connected.error is not None
        assert connected.error.code == "backend_error"

        # A missing device is a structured failure envelope, never a crash.
        info = service.device_info("emulator-9999")
        assert info.ok is False
        assert info.error is not None
        assert info.error.code == "backend_error"
    finally:
        service.close_all()
