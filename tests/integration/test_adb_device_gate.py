"""Live gate for the device.* line against a real adb host server.

No Android device or emulator is required: the adb *server* alone answers the
host protocol -- device enumeration, connect attempts, transport lookups --
and that protocol layer is where the client code under test lives (endpoint
resolution, timeouts, error classification, result shaping). Every response
here crosses a real socket to a real adb server, so a wire-format or
classification break fails the gate even with zero devices attached.

The server is private to the test: it is started on a free port and addressed
through ``ANDROID_ADB_SERVER_PORT``, so the gate also proves end to end that
the standard adb env override is honored (the client used to hardcode
127.0.0.1:5037, which made a hermetic gate impossible and cut off operators
with relocated servers). skip != pass: skips only when adb or adbutils is not
installed.
"""

from __future__ import annotations

import importlib.util
import shutil
import socket
import subprocess
from collections.abc import Iterator

import pytest

from headless_re_mcp.core.service import AnalysisService


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="module")
def adb_server() -> Iterator[int]:
    """A private adb server on a free port, torn down after the module."""
    if shutil.which("adb") is None:
        pytest.skip("adb not installed — device Gate not run (skip != pass)")
    if importlib.util.find_spec("adbutils") is None:
        pytest.skip("adbutils not installed — device Gate not run (skip != pass)")
    port = _free_port()
    started = subprocess.run(
        ["adb", "-P", str(port), "start-server"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if started.returncode != 0:
        pytest.skip(f"adb server would not start — device Gate not run: {started.stderr[:300]}")
    try:
        with pytest.MonkeyPatch.context() as patcher:
            patcher.setenv("ANDROID_ADB_SERVER_PORT", str(port))
            patcher.delenv("ANDROID_ADB_SERVER_HOST", raising=False)
            yield port
    finally:
        subprocess.run(
            ["adb", "-P", str(port), "kill-server"],
            capture_output=True,
            timeout=30,
            check=False,
        )


@pytest.mark.integration
def test_device_list_round_trips_the_private_server(adb_server: int) -> None:
    """An empty server answers with the documented empty shape, not an error.

    The server is created by this gate, so its device list is deterministically
    empty; the exact shape is asserted rather than just ok, because a paging or
    row-shim regression would otherwise hide behind an ok envelope.
    """
    service = AnalysisService()
    try:
        result = service.device_list()
        assert result.ok, result.error
        assert result.data == {"devices": [], "count": 0, "has_more": False}
    finally:
        service.close_all()


@pytest.mark.integration
def test_connect_to_a_dead_port_is_a_classified_failure(adb_server: int) -> None:
    """adb reports the refusal in prose; the envelope must not read as success.

    adbutils returns the failure message instead of raising, and the service
    promotes connected=False to a failure so a caller that only reads ok cannot
    install onto a device that was never there. This is that promotion,
    observed through a real server rather than a fake client.
    """
    dead_port = _free_port()
    service = AnalysisService()
    try:
        result = service.device_connect("127.0.0.1", dead_port)
        assert not result.ok
        assert result.error is not None
        assert result.error.code == "backend_error"
        assert "connect failed" in result.error.message
        assert result.error.details.get("endpoint") == f"127.0.0.1:{dead_port}"
    finally:
        service.close_all()


@pytest.mark.integration
def test_an_unknown_serial_is_a_classified_error_not_an_incident(adb_server: int) -> None:
    """The server's 'device not found' must surface as a classified adb error.

    A raw adbutils exception leaking through would be reported as an
    internal_error incident -- the operator would file a bug against the
    server for asking about a device that is simply not attached.
    """
    service = AnalysisService()
    try:
        info = service.device_info("no-such-serial")
        assert not info.ok
        assert info.error is not None
        assert info.error.code in {"backend_error", "not_found"}
        assert "no-such-serial" in info.error.message

        forwarded = service.device_forward("no-such-serial", "tcp:16100", "tcp:16100")
        assert not forwarded.ok
        assert forwarded.error is not None
        assert forwarded.error.code in {"backend_error", "not_found"}
    finally:
        service.close_all()
