"""Android repackaging live gate: apk.decode -> apk.repack -> apk.sign, end to end.

The unit suite drives the apktool/apksigner client and the service mixin with a
faked ``run_bounded`` (no JVM), so it proves the envelopes and the guards but
never that the real chain produces a usable APK. This gate runs the actual tools
on an APK assembled at test time (javac -> d8 -> aapt, so no binary is tracked)
and asserts on content, not just an ``ok`` flag:

* decode yields real smali (``MainActivity`` with ``compute(II)I`` / ``mul-int``)
  and an editable text manifest carrying the original permission;
* an edit made in the decoded tree -- a new ``CAMERA`` permission injected before
  ``<application>`` -- survives the rebuild and the re-signing, verified by
  decoding the *signed* output again and finding the injected permission there
  (and, when androguard is installed, cross-checked by re-parsing the package and
  its permissions);
* the rebuilt APK is a real zip, the signed APK independently passes
  ``apksigner verify``, and the signing keystore lives inside the session tree so
  the path-containment guard accepts it without touching ``$HOME/.android``.

A second, tool-free case pins the path-containment refusals (repack/sign reject a
path outside the session artifact tree) so that contract holds even where the
Android toolchain is absent. skip != pass: the round-trip skips cleanly when
apktool/apksigner or the SDK build tools are not present.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.example.headless"
_ORIGINAL_PERMISSION = "android.permission.INTERNET"
_INJECTED_PERMISSION = "android.permission.CAMERA"

_JAVA_SOURCE = """package com.example;

public class MainActivity {
    public int compute(int a, int b) {
        return a * b + 7;
    }

    public int run() {
        return compute(2, 3);
    }
}
"""

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.headless"
    android:versionCode="1"
    android:versionName="1.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:hasCode="true" android:label="Headless">
        <activity android:name="com.example.MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def _sdk_build_tool(name: str) -> Path | None:
    """Locate an SDK build-tool: PATH first, then the newest build-tools dir.

    aapt and d8 are shell wrappers that live under ``<sdk>/build-tools/<ver>/``
    and are usually not on PATH, so fall back to ANDROID_HOME / ANDROID_SDK_ROOT
    and pick the highest version present.
    """
    on_path = shutil.which(name)
    if on_path:
        return Path(on_path)
    for root in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")):
        if not root:
            continue
        build_tools = Path(root) / "build-tools"
        if not build_tools.is_dir():
            continue
        for version_dir in sorted(build_tools.iterdir(), reverse=True):
            candidate = version_dir / name
            if candidate.is_file():
                return candidate
    return None


def _android_jar() -> Path | None:
    for root in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")):
        if not root:
            continue
        platforms = Path(root) / "platforms"
        if not platforms.is_dir():
            continue
        for platform_dir in sorted(platforms.iterdir(), reverse=True):
            jar = platform_dir / "android.jar"
            if jar.is_file():
                return jar
    return None


def _build_input_apk(tmp_path: Path, aapt: Path, d8: Path, javac: Path, android_jar: Path) -> Path:
    """Assemble a small, real (unsigned) APK with the stock Android build tools."""
    src = tmp_path / "src" / "com" / "example"
    src.mkdir(parents=True)
    (src / "MainActivity.java").write_text(_JAVA_SOURCE, encoding="utf-8")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(_MANIFEST, encoding="utf-8")

    classes = tmp_path / "classes"
    classes.mkdir()
    subprocess.run(
        [str(javac), "--release", "8", "-d", str(classes), str(src / "MainActivity.java")],
        check=True,
        capture_output=True,
    )
    dex = tmp_path / "dex"
    dex.mkdir()
    class_files = sorted(str(p) for p in (classes / "com" / "example").glob("*.class"))
    subprocess.run(
        [str(d8), "--release", "--min-api", "21", "--output", str(dex), *class_files],
        check=True,
        capture_output=True,
    )
    apk = tmp_path / "app.apk"
    subprocess.run(
        [str(aapt), "package", "-f", "-M", str(manifest), "-I", str(android_jar), "-F", str(apk)],
        check=True,
        capture_output=True,
    )
    # Run from the dex dir so the entry is stored as "classes.dex" (aapt add
    # keeps the path it is handed).
    subprocess.run(
        [str(aapt), "add", str(apk), "classes.dex"],
        cwd=str(dex),
        check=True,
        capture_output=True,
    )
    return apk


def _make_keystore(keytool: Path, path: Path, *, password: str, alias: str) -> None:
    subprocess.run(
        [
            str(keytool),
            "-genkeypair",
            "-keystore",
            str(path),
            "-storepass",
            password,
            "-keypass",
            password,
            "-alias",
            alias,
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "1000",
            "-dname",
            "CN=Repackaging Gate, O=HeadlessRE, C=US",
        ],
        check=True,
        capture_output=True,
    )


@pytest.mark.integration
def test_android_repackaging_round_trip(tmp_path: Path) -> None:
    settings = Settings.load()
    apktool = getattr(settings, "apktool", None)
    apksigner = getattr(settings, "apksigner", None)
    if apktool is None or apksigner is None:
        pytest.skip("apktool/apksigner not configured — repackaging gate not run (skip≠pass)")

    aapt = _sdk_build_tool("aapt")
    d8 = _sdk_build_tool("d8")
    javac = shutil.which("javac")
    keytool = shutil.which("keytool")
    android_jar = _android_jar()
    if not (aapt and d8 and javac and keytool and android_jar):
        pytest.skip("Android SDK build-tools / JDK missing — cannot assemble an APK (skip≠pass)")

    apk = _build_input_apk(tmp_path, aapt, d8, Path(javac), android_jar)

    service = AnalysisService()
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        # 1) Decode: real smali + an editable text manifest, not just an envelope.
        decoded = service.apk_decode(session_id)
        assert decoded.ok, decoded.error
        decoded_dir = Path(decoded.data["decoded_dir"])
        assert decoded_dir.is_dir()
        assert decoded.data["smali_dirs"], "apktool reported no smali directories"
        manifest_path = Path(decoded.data["manifest"])
        assert manifest_path.is_file()

        smali = decoded_dir / "smali" / "com" / "example" / "MainActivity.smali"
        assert smali.is_file(), "MainActivity was not disassembled to smali"
        smali_text = smali.read_text(encoding="utf-8")
        assert "compute(II)I" in smali_text
        assert "mul-int" in smali_text

        manifest_text = manifest_path.read_text(encoding="utf-8")
        assert _ORIGINAL_PERMISSION in manifest_text
        assert _INJECTED_PERMISSION not in manifest_text

        # 2) Edit the decoded tree: inject a new permission before <application>,
        #    matching the surrounding indentation so ordering stays valid.
        edited = re.sub(
            r"(\n(\s*))<application\b",
            rf'\1<uses-permission android:name="{_INJECTED_PERMISSION}" />\1<application',
            manifest_text,
            count=1,
        )
        assert edited != manifest_text, "manifest edit anchor did not match"
        manifest_path.write_text(edited, encoding="utf-8")

        # 3) Repack: a real, valid, unsigned APK.
        repacked = service.apk_repack(session_id)
        assert repacked.ok, repacked.error
        repacked_apk = Path(repacked.data["apk"])
        assert repacked_apk.is_file()
        assert zipfile.is_zipfile(repacked_apk)
        assert repacked.data["signed"] is False
        assert repacked.data["size"] > 0

        # 4) Sign with a keystore inside the session tree (path guard accepts it).
        keystore = decoded_dir.parent / "gate.keystore"
        _make_keystore(Path(keytool), keystore, password="gatepw", alias="gatekey")
        signed = service.apk_sign(
            session_id,
            keystore=str(keystore),
            keystore_password="gatepw",
            key_alias="gatekey",
        )
        assert signed.ok, signed.error
        assert signed.data["signed"] is True
        assert signed.data["debug_keystore"] is False
        signed_apk = Path(signed.data["apk"])
        assert zipfile.is_zipfile(signed_apk)

        # Independent second opinion: apksigner itself agrees it is signed.
        verify = subprocess.run(
            [str(apksigner), "verify", str(signed_apk)],
            capture_output=True,
        )
        assert verify.returncode == 0, verify.stderr.decode("utf-8", "replace")

        # 5) Round-trip integrity: decode the *signed* output again and confirm
        #    the injected permission survived the whole edit/rebuild/re-sign cycle.
        reopened = service.create_session(str(signed_apk), target="apk")
        assert reopened.ok, reopened.error
        signed_session = reopened.data["session"]["id"]
        re_decoded = service.apk_decode(signed_session)
        assert re_decoded.ok, re_decoded.error
        re_manifest = Path(re_decoded.data["manifest"]).read_text(encoding="utf-8")
        assert _ORIGINAL_PERMISSION in re_manifest
        assert _INJECTED_PERMISSION in re_manifest

        # Cross-tool check when androguard is installed: the rebuilt package
        # re-parses with the same identity and both permissions.
        if ApkClient().available:
            opened = service.apk_open(signed_session)
            assert opened.ok, opened.error
            assert opened.data["package"] == _PACKAGE
            perms = service.apk_permissions(signed_session)
            assert perms.ok, perms.error
            declared = perms.data["permissions"]
            assert _ORIGINAL_PERMISSION in declared
            assert _INJECTED_PERMISSION in declared
    finally:
        service.close_all()


def _synthetic_apk(path: Path) -> Path:
    """A zip that classifies as an APK without needing any Android tool."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", b"dex\n035\x00placeholder")
        archive.writestr("META-INF/CERT.RSA", b"placeholder-signature")
    return path


@pytest.mark.integration
def test_android_repackaging_refuses_paths_outside_the_session_tree(tmp_path: Path) -> None:
    """repack/sign must refuse a path outside the session artifact tree.

    The containment guard runs before any tool is launched, so this holds with
    no apktool/apksigner installed and pins the contract that a caller cannot
    point these at an arbitrary directory or keystore on disk.
    """
    apk = _synthetic_apk(tmp_path / "sample.apk")
    service = AnalysisService()
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        outside_dir = service.apk_repack(session_id, decoded_dir=str(tmp_path))
        assert outside_dir.ok is False
        assert outside_dir.error is not None
        assert outside_dir.error.code == "invalid_params"

        outside_keystore = service.apk_sign(
            session_id,
            keystore=str(tmp_path / "rogue.keystore"),
            keystore_password="pw",
            key_alias="a",
        )
        assert outside_keystore.ok is False
        assert outside_keystore.error is not None
        assert outside_keystore.error.code == "invalid_params"
    finally:
        service.close_all()
