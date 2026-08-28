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

import contextlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.adb import AdbBackend
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService

_NO_DEVICE = "no adb device attached (bring up an emulator) — skip != pass"
_PROBE_PACKAGE = "com.example.gateprobe"


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


def _find_build_tool(name: str) -> Path | None:
    """Locate an Android build tool on PATH or under the SDK's build-tools."""
    on_path = shutil.which(name)
    if on_path:
        return Path(on_path)
    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if not sdk:
        return None
    build_tools = Path(sdk) / "build-tools"
    if not build_tools.is_dir():
        return None
    for version in sorted((p for p in build_tools.iterdir() if p.is_dir()), reverse=True):
        candidate = version / name
        if candidate.is_file():
            return candidate
    return None


def _find_android_jar() -> Path | None:
    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if not sdk:
        return None
    platforms = Path(sdk) / "platforms"
    if not platforms.is_dir():
        return None
    for platform in sorted((p for p in platforms.iterdir() if p.is_dir()), reverse=True):
        jar = platform / "android.jar"
        if jar.is_file():
            return jar
    return None


def _build_signed_apk(tmp_path: Path, package: str) -> Path | None:
    """Build a minimal, signed, installable APK, or None if tooling is missing.

    A code-less APK still needs android:hasCode="false" or SDK 31 rejects it as
    "code is missing", so declare it. Returns None (never raises) whenever a
    required tool -- aapt2, apksigner, android.jar, keytool -- is unavailable, so
    the caller can skip honestly rather than fail on a bare machine.
    """
    aapt2 = _find_build_tool("aapt2")
    apksigner = _find_build_tool("apksigner")
    android_jar = _find_android_jar()
    keytool = shutil.which("keytool")
    if not (aapt2 and apksigner and android_jar and keytool):
        return None

    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"\n'
        f'    package="{package}">\n'
        '    <application android:label="GateProbe" android:hasCode="false"/>\n'
        "</manifest>\n",
        encoding="utf-8",
    )
    unsigned = tmp_path / "unsigned.apk"
    link = subprocess.run(
        [
            str(aapt2),
            "link",
            "-I",
            str(android_jar),
            "--manifest",
            str(manifest),
            "--min-sdk-version",
            "21",
            "--target-sdk-version",
            "31",
            "-o",
            str(unsigned),
        ],
        capture_output=True,
        timeout=120,
    )
    if link.returncode != 0 or not unsigned.is_file():
        return None

    keystore = tmp_path / "debug.keystore"
    minted = subprocess.run(
        [
            keytool,
            "-genkeypair",
            "-keystore",
            str(keystore),
            "-storepass",
            "android",
            "-keypass",
            "android",
            "-alias",
            "androiddebugkey",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "30",
            "-dname",
            "CN=Gate",
        ],
        capture_output=True,
        timeout=120,
    )
    if minted.returncode != 0 or not keystore.is_file():
        return None

    signed = tmp_path / "signed.apk"
    sign = subprocess.run(
        [
            str(apksigner),
            "sign",
            "--ks",
            str(keystore),
            "--ks-pass",
            "pass:android",
            "--ks-key-alias",
            "androiddebugkey",
            "--key-pass",
            "pass:android",
            "--out",
            str(signed),
            str(unsigned),
        ],
        capture_output=True,
        timeout=120,
    )
    if sign.returncode != 0 or not signed.is_file():
        return None
    return signed


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
        # level -- two different code paths reading the same device. getprop is
        # sorted, so ask for the full set (backend caps at 2000; a device has a
        # few hundred): a small limit would truncate before ro.build.version.sdk.
        props = service.device_properties(serial, limit=2000)
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


@pytest.mark.integration
def test_device_install_and_uninstall_round_trip(tmp_path: Path) -> None:
    service, serial = _require_device()
    try:
        apk = _build_signed_apk(tmp_path, _PROBE_PACKAGE)
        if apk is None:
            pytest.skip(
                "android build-tools (aapt2/apksigner/android.jar) or keytool "
                "unavailable to build a test APK — skip != pass"
            )
        # Start from a clean slate in case a previous run left the probe behind.
        service.device_uninstall(serial, _PROBE_PACKAGE)

        installed = service.device_install(serial, str(apk), reinstall=True)
        assert installed.ok, installed.error
        assert installed.data["installed"] is True
        # The install path reads the package from the *binary* manifest and then
        # verifies with `pm path`; both must land on the package we built.
        assert installed.data["package"] == _PROBE_PACKAGE

        after_install = service.device_packages(serial, limit=2000)
        assert after_install.ok, after_install.error
        assert _PROBE_PACKAGE in after_install.data["packages"]

        removed = service.device_uninstall(serial, _PROBE_PACKAGE)
        assert removed.ok, removed.error
        assert removed.data["uninstalled"] is True

        after_uninstall = service.device_packages(serial, limit=2000)
        assert after_uninstall.ok, after_uninstall.error
        assert _PROBE_PACKAGE not in after_uninstall.data["packages"]
    finally:
        with contextlib.suppress(Exception):
            service.device_uninstall(serial, _PROBE_PACKAGE)
        service.close_all()
