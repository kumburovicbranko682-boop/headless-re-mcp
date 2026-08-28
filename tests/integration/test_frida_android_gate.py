"""Live Frida-on-Android gate: spawn a self-built app and enumerate its Java.

This is the mobile dynamic-analysis crown jewel and the part no mocked unit
test can reach: against a real device/emulator with frida-server running, it
builds a tiny APK carrying a known class and method, installs it, spawns it
through frida, and asserts frida enumerates *that* class and *that* method.
Because it drives the real ``Java`` bridge, it is also the regression guard for
the frida>=17 breakage (17.0 removed the built-in Java bridge, so these
assertions fail with "ReferenceError: 'Java' is not defined" until frida is
pinned below 17 or the scripts bundle frida-java-bridge).

skip != pass: it skips cleanly when frida is absent, no device is attached, the
Android build tools are missing, or the device is not frida-reachable (no
frida-server). Bring the stack up with an emulator plus a matching frida-server
(``adb push frida-server /data/local/tmp && adb shell su -c frida-server``, or
point HEADLESS_RE_FRIDA_SERVER at the binary so the gate pushes it for you).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.adb import AdbBackend
from headless_re_mcp.backends.frida.client import FridaClient
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.example.gateapp"
_CLASS = "com.example.gateapp.MainActivity"
_METHOD = "headlessCompute"

_MAIN_JAVA = """\
package com.example.gateapp;
import android.app.Activity;
import android.os.Bundle;
public class MainActivity extends Activity {
    public int headlessCompute(int a, int b) { return a * b + 7; }
    @Override protected void onCreate(Bundle b) { super.onCreate(b); }
}
"""

_MANIFEST = """\
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.gateapp">
    <application android:label="GateApp">
        <activity android:name="com.example.gateapp.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def _find_build_tool(name: str) -> Path | None:
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


def _run(cmd: list[str]) -> bool:
    done = subprocess.run(cmd, capture_output=True, timeout=180)
    return done.returncode == 0


def _build_spawnable_apk(tmp_path: Path) -> Path | None:
    """Build a signed, launchable APK carrying a known class, or None.

    Returns None (never raises) when any required tool is missing, so the caller
    can skip honestly. d8 rejects modern class files, so compile to Java 8
    bytecode; SDK 31 needs the app zipaligned and signed to install and spawn.
    """
    javac = shutil.which("javac")
    keytool = shutil.which("keytool")
    d8 = _find_build_tool("d8")
    aapt2 = _find_build_tool("aapt2")
    zipalign = _find_build_tool("zipalign")
    apksigner = _find_build_tool("apksigner")
    android_jar = _find_android_jar()
    if not (javac and keytool and d8 and aapt2 and zipalign and apksigner and android_jar):
        return None

    src = tmp_path / "src" / "com" / "example" / "gateapp"
    src.mkdir(parents=True)
    (src / "MainActivity.java").write_text(_MAIN_JAVA, encoding="utf-8")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(_MANIFEST, encoding="utf-8")
    classes_dir = tmp_path / "classes"

    if not _run(
        [
            javac,
            "--release",
            "8",
            "-cp",
            str(android_jar),
            "-d",
            str(classes_dir),
            str(src / "MainActivity.java"),
        ]
    ):
        return None
    class_file = classes_dir / "com" / "example" / "gateapp" / "MainActivity.class"
    if not _run(
        [
            str(d8),
            "--min-api",
            "21",
            "--lib",
            str(android_jar),
            "--output",
            str(tmp_path),
            str(class_file),
        ]
    ):
        return None
    dex = tmp_path / "classes.dex"
    if not dex.is_file():
        return None

    base = tmp_path / "base.apk"
    if not _run(
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
            str(base),
        ]
    ):
        return None
    # aapt2 does not add code; drop classes.dex in at the archive root.
    with zipfile.ZipFile(base, "a") as archive:
        archive.write(dex, "classes.dex")

    aligned = tmp_path / "aligned.apk"
    if not _run([str(zipalign), "-f", "4", str(base), str(aligned)]):
        return None

    keystore = tmp_path / "debug.keystore"
    if not _run(
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
        ]
    ):
        return None
    signed = tmp_path / "gateapp-signed.apk"
    if not _run(
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
            str(aligned),
        ]
    ):
        return None
    return signed if signed.is_file() else None


def _first_serial() -> str | None:
    if not AdbBackend().available:
        return None
    service = AnalysisService()
    try:
        listed = service.device_list()
        if not listed.ok:
            return None
        ready = [
            str(dev["serial"])
            for dev in listed.data["devices"]
            if dev.get("state") == "device" and dev.get("serial")
        ]
        return ready[0] if ready else None
    finally:
        service.close_all()


@pytest.mark.integration
def test_frida_android_spawn_and_java_enumeration(tmp_path: Path) -> None:
    if not FridaClient().available:
        pytest.skip("frida python not installed (android extra) — skip != pass")
    serial = _first_serial()
    if serial is None:
        pytest.skip("no adb device attached (bring up an emulator) — skip != pass")
    apk = _build_spawnable_apk(tmp_path)
    if apk is None:
        pytest.skip(
            "android build tools (javac/d8/aapt2/zipalign/apksigner/android.jar/keytool) "
            "unavailable — skip != pass"
        )

    service = AnalysisService()
    try:
        session = service.create_session(str(apk)).data["session"]["id"]

        # If a frida-server binary is configured, push/start it; otherwise rely on
        # one already running on the device.
        server = os.environ.get("HEADLESS_RE_FRIDA_SERVER")
        if server:
            service.frida_server_ensure(session, serial, server_binary=server)

        connected = service.frida_device_connect(session, device_id=serial)
        if not connected.ok:
            code = connected.error.code if connected.error else "unknown"
            pytest.skip(f"frida cannot connect the device ({code}) — skip != pass")

        # Front-probe: prove the device is frida-reachable before we start
        # asserting, so "frida-server not running" is an honest skip rather than a
        # spurious failure. Past this point, failures are real.
        probe = service.frida_applications(session, limit=8)
        if not probe.ok:
            code = probe.error.code if probe.error else "unknown"
            pytest.skip(
                f"frida-server not reachable on the device ({code}); "
                "bring up frida-server — skip != pass"
            )

        # Start clean: a copy left by a previous run is signed with a different
        # throwaway keystore, so a plain reinstall would hit
        # INSTALL_FAILED_UPDATE_INCOMPATIBLE.
        service.device_uninstall(serial, _PACKAGE)
        installed = service.device_install(serial, str(apk), reinstall=True)
        assert installed.ok, installed.error
        assert installed.data["package"] == _PACKAGE

        spawned = service.frida_spawn(session, _PACKAGE)
        assert spawned.ok, spawned.error
        assert spawned.data["package"] == _PACKAGE
        assert int(spawned.data["pid"]) > 0

        # The payoff: frida must enumerate the class and method we built and
        # spawned -- proof the Java bridge is live end to end, which is exactly
        # what breaks under frida 17.
        classes = service.frida_java_classes(session, name_filter=_PACKAGE, limit=50)
        assert classes.ok, classes.error
        assert _CLASS in classes.data["classes"], classes.data

        methods = service.frida_java_methods(session, _CLASS, limit=50)
        assert methods.ok, methods.error
        assert methods.data["found"] is True
        assert any(_METHOD in signature for signature in methods.data["methods"]), methods.data
    finally:
        with contextlib.suppress(Exception):
            service.device_uninstall(serial, _PACKAGE)
        service.close_all()
