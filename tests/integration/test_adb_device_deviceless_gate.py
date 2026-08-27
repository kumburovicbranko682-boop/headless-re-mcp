"""Deviceless ADB/device gate: strict argument checks and clean degradation.

The whole device.* surface (AdbBackend + the service device_* layer) had no
integration gate. adbutils ships its own adb binary and auto-starts a local adb
server, so the contract that matters for an unattended agent can be proven with
no phone attached: hostile arguments are refused before any device round-trip,
an absent device yields a structured error rather than a crash, and a dead
connect is never reported as a success. Needs only adbutils (a pip install);
skips honestly (skip != pass) when it is absent.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError
from headless_re_mcp.core.service import AnalysisService

# No device is attached in CI, so any operation that reaches one must fail with
# one of these structured codes -- never a raw exception or an internal_error.
_STRUCTURED = {"backend_error", "not_found", "timeout", "capability_unavailable"}
_BOGUS_SERIAL = "emulator-9999"


def _adb_available() -> bool:
    return AdbBackend().available


@pytest.mark.integration
def test_adb_rejects_hostile_arguments_before_touching_a_device() -> None:
    if not _adb_available():
        pytest.skip("adbutils not installed — device Gate not run (skip != pass)")
    backend = AdbBackend()

    # A port outside 1..65535 is refused up front, not handed to adb.
    with pytest.raises(AdbError) as port_err:
        backend.connect("127.0.0.1", 70000)
    assert port_err.value.code == "invalid_params"

    # tcp:70000 is five digits but not a port; a malformed remote is rejected
    # too. Both are checked before the device is resolved.
    with pytest.raises(AdbError) as local_err:
        backend.forward(_BOGUS_SERIAL, "tcp:70000", "tcp:1")
    assert local_err.value.code == "invalid_params"
    with pytest.raises(AdbError) as remote_err:
        backend.forward(_BOGUS_SERIAL, "tcp:1", "not a spec")
    assert remote_err.value.code == "invalid_params"

    # A package name with a space could smuggle a second shell argument.
    with pytest.raises(AdbError) as pkg_err:
        backend.uninstall(_BOGUS_SERIAL, "not a package")
    assert pkg_err.value.code == "invalid_params"

    # Missing local files fail fast as not_found, before any device round-trip,
    # so the common caller mistake is not masked by a device error.
    with pytest.raises(AdbError) as apk_err:
        backend.install(_BOGUS_SERIAL, "/no/such/file.apk")
    assert apk_err.value.code == "not_found"
    with pytest.raises(AdbError) as push_err:
        backend.push(_BOGUS_SERIAL, "/no/such/local/file", "/data/local/tmp/x")
    assert push_err.value.code == "not_found"


@pytest.mark.integration
def test_adb_lists_no_devices_and_fails_structurally_on_a_missing_one() -> None:
    if not _adb_available():
        pytest.skip("adbutils not installed — device Gate not run (skip != pass)")
    backend = AdbBackend()

    # adbutils auto-starts the adb server; with nothing attached the list is a
    # clean empty envelope, not an error.
    listed = backend.list_devices()
    assert listed["devices"] == []
    assert listed["count"] == 0
    assert listed["has_more"] is False

    # Talking to a device that is not there must be a structured AdbError, never
    # a raised non-AdbError escaping to the service as an internal_error.
    with pytest.raises(AdbError) as info_err:
        backend.info(_BOGUS_SERIAL)
    assert info_err.value.code in _STRUCTURED, info_err.value.code


@pytest.mark.integration
def test_device_service_layer_never_reads_a_dead_connect_as_success() -> None:
    if not _adb_available():
        pytest.skip("adbutils not installed — device Gate not run (skip != pass)")
    service = AnalysisService()
    try:
        listed = service.device_list()
        assert listed.ok, listed.error
        assert listed.data["devices"] == []

        # adbutils' connect returns a status string and does not raise, so a
        # dead endpoint comes back connected=False. The service must upgrade
        # that to a backend_error: a caller reading only ok would otherwise
        # install onto a device that was never connected.
        connected = service.device_connect("127.0.0.1", 1)
        assert connected.ok is False
        assert connected.error is not None
        assert connected.error.code == "backend_error", connected.error.code
        assert "incident_id" not in (connected.error.details or {})

        # A device operation against a missing serial is a structured failure
        # with no error-boundary incident -- it is the caller's absent device,
        # not a server defect.
        info = service.device_info(_BOGUS_SERIAL)
        assert info.ok is False
        assert info.error is not None
        assert info.error.code != "internal_error", info.error.code
        assert info.error.code in _STRUCTURED, info.error.code
        assert "incident_id" not in (info.error.details or {})
    finally:
        service.close_all()
