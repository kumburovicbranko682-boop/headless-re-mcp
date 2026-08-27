"""adb live gate: real adb-server round trips on Linux, no device required.

The adb backend talks to a real adb server over TCP 5037 through adbutils, which
bundles its own adb binary and auto-spawns the daemon. Every adb test so far only
asserted graceful degradation when adbutils was *absent*, so nothing ever started
a server or exchanged a single command with it -- the adbutils<->server protocol
path had zero coverage.

This gate drives the two operations that are meaningful without a phone attached:
enumerating devices (the daemon starts, replies, and the backend returns a
well-formed empty page) and connecting to a closed endpoint (the server processes
the request and the backend maps the refusal to a clean ``connected: False``
instead of crashing). Device-level operations -- shell, install, logcat, pull --
genuinely need a device or emulator and are out of scope here.

Skip != pass: the gate skips with a reason only when adbutils is not installed.
CI installs it, so a skip there is a genuine regression rather than a bare
machine.
"""

from __future__ import annotations

import socket

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


def _closed_local_port() -> int:
    """A port with nothing listening, so adb's connect must be refused."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.mark.integration
def test_adb_lists_devices_through_a_real_server() -> None:
    backend = AdbBackend()
    if not backend.available:
        pytest.skip("adbutils not installed — adb live Gate not run (skip != pass)")

    # Starts (or reaches) a real adb daemon and asks it for the device list. No
    # phone is attached in CI, so the page is empty, but the envelope invariants
    # must hold -- proving a genuine server round trip, not a canned reply.
    result = backend.list_devices()
    assert isinstance(result["devices"], list)
    assert result["count"] == len(result["devices"])
    assert isinstance(result["has_more"], bool)


@pytest.mark.integration
def test_adb_connect_to_a_closed_endpoint_is_refused_cleanly() -> None:
    backend = AdbBackend()
    if not backend.available:
        pytest.skip("adbutils not installed — adb live Gate not run (skip != pass)")

    port = _closed_local_port()
    # A closed port makes the outcome deterministic whether or not a device is
    # attached: the adb server tries, fails, and the backend must surface that as
    # connected=False with a reason -- not raise, not hang.
    try:
        result = backend.connect("127.0.0.1", port)
    except AdbError as exc:  # pragma: no cover - only if adb changes its contract
        pytest.fail(f"connect to a closed port should degrade cleanly, not raise: {exc}")
    assert result["connected"] is False
    assert isinstance(result["result"], str) and result["result"].strip()
