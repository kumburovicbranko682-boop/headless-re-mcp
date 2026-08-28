"""Live on-device ADB gate: a real device/emulator, driven end to end.

``test_android_device_gate.py`` proves the adbutils<->server plumbing and the
failure contracts with no device attached. This gate is the other half: when a
real Android device or emulator is on adb, it exercises the device-control
surface for real -- info/properties, packages/logcat, a screenshot, a push/pull
byte round-trip, and an adb forward (including the hardened tcp:0 refusal) --
the part mocked unit tests can never reach.

skip != pass: it skips cleanly when adbutils is absent or no device is attached,
so it is honest on a bare machine and real against an emulator. Bring one up
with e.g. ``emulator -avd <name> -no-window -no-audio -gpu swiftshader_indirect``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from headless_re_mcp.backends.adb import AdbBackend
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

_NO_DEVICE = "no adb device attached (bring up an emulator) — skip != pass"


def _service_with_device() -> tuple[AnalysisService, str] | None:
    """An AnalysisService plus the first ready serial, or None to skip.

    Returns None (never raises) when adbutils is missing or no device is
    attached, so each test can skip honestly.
    """
    if not AdbBackend().available:
        return None
    service = AnalysisService()
    listed = service.device_list()
    if not listed.ok:
        service.close_all()
        return None
    ready = [
        str(dev["serial"])
        for dev in listed.data["devices"]
        if dev.get("state") == "device" and dev.get("serial")
    ]
    if not ready:
        service.close_all()
        return None
    return service, ready[0]


def _require_device() -> tuple[AnalysisService, str]:
    got = _service_with_device()
    if got is None:
        pytest.skip(_NO_DEVICE)
    return got


@pytest.mark.integration
def test_device_info_agrees_with_getprop() -> None:
    service, serial = _require_device()
    try:
        info = service.device_info(serial)
        assert info.ok, info.error
        assert info.data["serial"] == serial
        sdk = info.data["sdk"]
        assert sdk.isdigit() and int(sdk) >= 21, info.data
        assert info.data["abi"], info.data
        assert info.data["model"], info.data

        # The raw getprop dump must agree with the summarised info on the SDK
        # level -- two different code paths reading the same device.
        props = service.device_properties(serial, limit=500)
        assert props.ok, props.error
        assert props.data["count"] >= 1
        assert props.data["properties"].get("ro.build.version.sdk") == sdk
    finally:
        service.close_all()


@pytest.mark.integration
def test_device_packages_and_logcat() -> None:
    service, serial = _require_device()
    try:
        pkgs = service.device_packages(serial, limit=500)
        assert pkgs.ok, pkgs.error
        assert pkgs.data["count"] >= 1
        # Framework/system packages exist on every Android build.
        assert any(name.startswith("com.android.") for name in pkgs.data["packages"]), pkgs.data[
            "packages"
        ][:10]

        logcat = service.device_logcat(serial, lines=50)
        assert logcat.ok, logcat.error
        assert isinstance(logcat.data["lines"], list)
        assert logcat.data["count"] >= 1
    finally:
        service.close_all()


@pytest.mark.integration
def test_device_screenshot_writes_a_real_png() -> None:
    service, serial = _require_device()
    try:
        shot = service.device_screenshot(serial)
        assert shot.ok, shot.error
        path = Path(shot.data["path"])
        assert path.is_file()
        assert shot.data["size"] > 0
        # The PNG magic proves a real image was captured and saved, not an empty
        # or error-text file.
        assert path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        service.close_all()


@pytest.mark.integration
def test_device_push_pull_byte_round_trip(tmp_path: Path) -> None:
    service, serial = _require_device()
    try:
        payload = os.urandom(8192)
        local = tmp_path / "probe.bin"
        local.write_bytes(payload)
        remote = f"/data/local/tmp/gate_probe_{os.getpid()}.bin"

        pushed = service.device_push(serial, str(local), remote)
        assert pushed.ok, pushed.error
        assert pushed.data["size"] == len(payload)

        pulled = service.device_pull(serial, remote)
        assert pulled.ok, pulled.error
        # The bytes that came back must equal the bytes sent: proof the sync
        # transfer works both ways, not just that the calls returned.
        assert Path(pulled.data["local"]).read_bytes() == payload
    finally:
        service.close_all()


@pytest.mark.integration
def test_device_forward_and_the_tcp0_refusal() -> None:
    service, serial = _require_device()
    try:
        # tcp:0 means "allocate a free port", but adbutils discards the reply
        # naming it, so the client refuses it up front rather than leak an
        # untrackable listener. This must fail before touching the server.
        bad = service.device_forward(serial, "tcp:0", "tcp:5555")
        assert bad.ok is False
        assert bad.error is not None and bad.error.code == "invalid_params"

        # A concrete local port forwards cleanly; close_all releases it.
        good: Result = service.device_forward(serial, "tcp:18080", "tcp:5555")
        assert good.ok, good.error
        assert good.data["local"] == "tcp:18080"
        assert good.data["remote"] == "tcp:5555"
    finally:
        service.close_all()
