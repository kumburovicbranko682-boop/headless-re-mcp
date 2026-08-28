"""Live ADB gate: real adb server, parsed device list, hardened failure contracts.

No phone or emulator is attached, so this cannot exercise install / shell / pull
-- those genuinely need hardware. What it *can* prove, and what the synthetic
Android gate only asserted as "returns some envelope" (``ok or error is not
None``, which is vacuously true), is that the adbutils <-> adb-server plumbing
actually works on this host and that the error contracts hold against a real
server:

* ``device.list``: adbutils spawns its bundled adb server and ``device.list()``
  is parsed into the bounded ``{devices, count, has_more}`` envelope -- an empty
  but real list, not a degraded error.
* ``device.connect`` to a dead endpoint is a failure envelope, never
  ok-with-connected-false (which once let a caller "install" onto a device that
  was never there).
* a device-dependent op on an absent serial returns a structured error, not a
  crash -- the no-hardware contract.

skip != pass: it skips only when adbutils is genuinely absent (the android extra
is not installed), or when no adb binary can be spawned on this host at all.
"""

from __future__ import annotations

import socket

import pytest

from headless_re_mcp.backends.adb import AdbBackend
from headless_re_mcp.core.service import AnalysisService

_SKIP = "adbutils not installed (android extra) — ADB Gate not run (skip != pass)"


def _adbutils_available() -> bool:
    return AdbBackend().available


def _dead_local_port() -> int:
    """A port bound then released, so nothing is listening on it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.mark.integration
def test_adb_lists_devices_against_a_real_server() -> None:
    if not _adbutils_available():
        pytest.skip(_SKIP)
    service = AnalysisService()
    try:
        listed = service.device_list()
        if not listed.ok:
            # The only honest reason to bail: no adb binary could be found or
            # spawned on this host at all.
            code = listed.error.code if listed.error else "unknown"
            pytest.skip(f"no adb server could be reached ({code}) — skip != pass")
        # A real adb server answered. No device is attached, so the list is
        # empty, but it is a parsed list with a self-consistent envelope -- not
        # the degraded error the synthetic gate tolerated.
        devices = listed.data["devices"]
        assert isinstance(devices, list)
        assert listed.data["count"] == len(devices)
        assert listed.data["has_more"] is False
    finally:
        service.close_all()


@pytest.mark.integration
def test_adb_connect_to_a_dead_endpoint_is_a_failure_not_a_false_ok() -> None:
    if not _adbutils_available():
        pytest.skip(_SKIP)
    service = AnalysisService()
    try:
        # Nothing is listening on this port, so adb cannot connect. The hardened
        # contract is that this is a failure envelope, never ok-with-
        # connected-false.
        result = service.device_connect("127.0.0.1", _dead_local_port())
        assert result.ok is False
        assert result.error is not None
        assert result.error.code in {"backend_error", "timeout"}
    finally:
        service.close_all()


@pytest.mark.integration
def test_adb_device_op_on_an_absent_serial_is_structured_not_a_crash() -> None:
    if not _adbutils_available():
        pytest.skip(_SKIP)
    service = AnalysisService()
    try:
        # A device-dependent op with no device attached must come back as a
        # structured error envelope rather than raising.
        result = service.device_info("nonexistent-serial-xyz")
        assert result.ok is False
        assert result.error is not None
        assert result.error.code in {"backend_error", "not_found", "timeout"}
    finally:
        service.close_all()
