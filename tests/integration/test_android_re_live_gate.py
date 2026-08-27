"""Android static analysis live gate: real androguard over a real APK.

androguard is a pure-Python parser, so unlike the Windows debugger gates this is
meant to run on Linux CI. Every other Android test builds a *synthetic* archive
(a zip with a fake, non-AXML manifest) and only asserts that a missing tool or a
bad file degrades cleanly -- so nothing ever proved androguard parses a genuine
APK and recovers real facts from it. This gate builds a minimal but valid APK
with the Android SDK (aapt2 compiles the manifest to binary AXML, d8 produces a
real classes.dex, apksigner signs it) and drives ``ApkClient`` directly, the
same client the apk.* tools use.

Skip != pass: the gate skips with a reason when the Android SDK or a JDK is
absent, and runs for real when both are present. CI installs the SDK, so a skip
there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

_PACKAGE = "com.example.gate"
_PERMISSION = "android.permission.INTERNET"

_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{_PACKAGE}">
    <uses-permission android:name="{_PERMISSION}"/>
    <application android:label="Gate">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""

# A plain class (no android imports) keeps javac dependency-free; the manifest
# names it as the activity so androguard resolves .MainActivity against the
# package, and the DEX carries the methods the gate asserts on.
_JAVA_SRC = """
package com.example.gate;

public class MainActivity {
    public static int addNumbers(int a, int b) {
        return a + b;
    }

    public String greet(String who) {
        return "hello " + who;
    }
}
"""


def _newest(paths: list[Path]) -> Path | None:
    existing = [p for p in paths if p.exists()]
    return sorted(existing)[-1] if existing else None


def _resolve_sdk() -> dict[str, Path] | None:
    """Locate aapt2, d8, zipalign, apksigner and an android.jar, or None."""
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not home:
        return None
    root = Path(home)
    build_tools_dir = root / "build-tools"
    build_tools = _newest(list(build_tools_dir.glob("*"))) if build_tools_dir.is_dir() else None
    android_jar = _newest(list((root / "platforms").glob("android-*/android.jar")))
    if build_tools is None or android_jar is None:
        return None
    tools = {
        "aapt2": build_tools / "aapt2",
        "d8": build_tools / "d8",
        "zipalign": build_tools / "zipalign",
        "apksigner": build_tools / "apksigner",
        "android_jar": android_jar,
    }
    for name, path in tools.items():
        if name != "android_jar" and not path.is_file():
            return None
    return tools


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(cmd, capture_output=True, timeout=180, **kwargs)  # type: ignore[call-overload]
    assert result.returncode == 0, (
        f"{cmd[0]} failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace')[:2000]}"
    )
    return result


def _build_apk(tmp_path: Path, sdk: dict[str, Path]) -> Path:
    javac = shutil.which("javac")
    keytool = shutil.which("keytool")
    assert javac and keytool, "JDK (javac/keytool) required once the SDK is present"

    src_dir = tmp_path / "src" / "com" / "example" / "gate"
    src_dir.mkdir(parents=True)
    (src_dir / "MainActivity.java").write_text(_JAVA_SRC, encoding="utf-8")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(_MANIFEST, encoding="utf-8")

    classes = tmp_path / "classes"
    classes.mkdir()
    # --release 11: d8 (R8) in build-tools rejects newer class-file versions than
    # it knows, and CI's JDK may be much newer (JDK 21 emits major version 65,
    # which build-tools 34's d8 refuses). Targeting 11 keeps the bytecode within
    # what any recent d8 accepts, independent of the JDK that runs javac.
    _run([javac, "--release", "11", "-d", str(classes), str(src_dir / "MainActivity.java")])

    dex_out = tmp_path / "dex"
    dex_out.mkdir()
    class_file = classes / "com" / "example" / "gate" / "MainActivity.class"
    _run(
        [
            str(sdk["d8"]),
            "--min-api",
            "21",
            "--lib",
            str(sdk["android_jar"]),
            "--output",
            str(dex_out),
            str(class_file),
        ]
    )

    base_apk = tmp_path / "base.apk"
    _run(
        [
            str(sdk["aapt2"]),
            "link",
            "-o",
            str(base_apk),
            "-I",
            str(sdk["android_jar"]),
            "--manifest",
            str(manifest),
            "--min-sdk-version",
            "21",
            "--target-sdk-version",
            "34",
        ]
    )

    # aapt2 emits a zip; drop the real classes.dex in at the archive root.
    import zipfile

    with zipfile.ZipFile(base_apk, "a") as archive:
        archive.write(dex_out / "classes.dex", "classes.dex")

    aligned = tmp_path / "aligned.apk"
    _run([str(sdk["zipalign"]), "-f", "4", str(base_apk), str(aligned)])

    keystore = tmp_path / "debug.keystore"
    _run(
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
            "gate",
            "-dname",
            "CN=gate",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "10000",
        ]
    )
    _run(
        [
            str(sdk["apksigner"]),
            "sign",
            "--ks",
            str(keystore),
            "--ks-pass",
            "pass:android",
            "--key-pass",
            "pass:android",
            str(aligned),
        ]
    )
    return aligned


@pytest.mark.integration
def test_androguard_parses_a_real_apk(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — Android live Gate not run (skip != pass)")
    sdk = _resolve_sdk()
    if sdk is None:
        pytest.skip(
            "Android SDK not found (set ANDROID_HOME with build-tools + a platform) "
            "— live Gate not run (skip != pass)"
        )
    if shutil.which("javac") is None or shutil.which("keytool") is None:
        pytest.skip("no JDK (javac/keytool) to build the APK — Gate not run (skip != pass)")

    apk = _build_apk(tmp_path, sdk)

    opened = client.open(apk)
    assert opened["opened"] is True
    assert opened["package"] == _PACKAGE
    assert opened["permission_count"] >= 1

    permissions = client.permissions(apk)
    assert _PERMISSION in permissions["permissions"]

    components = client.components(apk)
    # androguard resolves the leading-dot activity name against the package.
    assert any("MainActivity" in name for name in components["activities"])
    assert components["main_activity"] and "MainActivity" in components["main_activity"]

    manifest = client.manifest(apk)
    assert manifest["package"] == _PACKAGE
    assert "uses-permission" in manifest["manifest_xml"]

    classes = client.classes(apk, limit=256)
    assert any("MainActivity" in name for name in classes["classes"])

    target = next(name for name in classes["classes"] if "MainActivity" in name)
    methods = client.methods(apk, target, limit=256)
    method_names = {item.get("name") for item in methods["methods"]}
    # The real DEX carries the methods we compiled, not just <init>.
    assert "addNumbers" in method_names
    assert "greet" in method_names

    certificates = client.certificates(apk)
    # apksigner wrote a v1 signature, so a real parse finds a certificate.
    assert certificates["certificates"], "expected androguard to read the signing certificate"
