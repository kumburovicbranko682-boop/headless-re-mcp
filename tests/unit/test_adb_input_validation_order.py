"""ADB caller-input validation must precede the adbutils capability probe.

Every serial-taking operation routes through ``_device``, which used to call
``_client`` (the adbutils import probe) before ``_check_serial``. So a malformed
serial returned ``capability_unavailable`` on a host without adbutils but
``invalid_params`` on one with it -- the code drifted with the environment.
``connect`` and ``ensure_frida_server`` had the same shape (port/endpoint and
remote_path validated after the probe). Pin the caller-input checks first so a
malformed request is a deterministic ``invalid_params`` everywhere.
"""

from __future__ import annotations

import pytest

from headless_re_mcp.backends.adb.client import AdbBackend, AdbError


def _unavailable_backend() -> AdbBackend:
    backend = AdbBackend()
    # Force the "adbutils not installed" environment regardless of host: this is
    # exactly where a capability-first guard would mask the invalid_params.
    backend._available = False
    backend._adbutils = None
    return backend


_BAD_SERIALS = ["bad serial!", "a;rm -rf /", "x" * 200, "$(reboot)"]


@pytest.mark.parametrize("bad_serial", _BAD_SERIALS)
@pytest.mark.parametrize(
    "call",
    [
        lambda b, s: b.info(s),
        lambda b, s: b.properties(s),
        lambda b, s: b.packages(s),
        lambda b, s: b.logcat(s),
        lambda b, s: b.current_activity(s),
        lambda b, s: b.screenshot(s, __import__("pathlib").Path("/tmp/x.png")),
    ],
)
def test_serial_methods_report_invalid_params_before_capability(call, bad_serial: str) -> None:
    with pytest.raises(AdbError) as caught:
        call(_unavailable_backend(), bad_serial)
    assert caught.value.code == "invalid_params"


def test_a_well_formed_serial_without_adbutils_still_reports_capability_unavailable() -> None:
    # The reorder must not turn every call into invalid_params: a valid serial
    # passes the shape check and then legitimately hits the capability probe.
    with pytest.raises(AdbError) as caught:
        _unavailable_backend().info("emulator-5554")
    assert caught.value.code == "capability_unavailable"


def test_connect_reports_invalid_params_before_capability() -> None:
    with pytest.raises(AdbError) as caught:
        _unavailable_backend().connect("127.0.0.1", 99999)
    assert caught.value.code == "invalid_params"


def test_ensure_frida_server_rejects_bad_remote_path_before_capability() -> None:
    with pytest.raises(AdbError) as caught:
        _unavailable_backend().ensure_frida_server(
            "emulator-5554", remote_path="/data/local/tmp/x; rm -rf /"
        )
    assert caught.value.code == "invalid_params"
