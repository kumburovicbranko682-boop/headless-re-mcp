"""apktool live gate: real decode -> rebuild -> re-sign round trip on Linux.

apktool is a cross-platform JVM tool, so this runs on Linux CI. The apk.decode /
apk.repack / apk.sign tools are the Android "repack" workflow, and until now
nothing ever ran them: every Android test built a synthetic (non-AXML) archive
and only checked graceful degradation. This gate builds a genuine APK with the
Android SDK, then drives ``ApktoolClient`` through the full loop the operator
uses -- decode to smali+resources, rebuild from that tree, and re-sign the
result with apksigner verifying the signature -- proving the round trip end to
end.

Skip != pass: the gate skips with a reason when apktool, the Android SDK, or a
JDK is absent, and runs for real when all are present. CI installs them, so a
skip there is a genuine regression rather than a bare machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient

_PACKAGE = "com.example.gate"

_MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{_PACKAGE}">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application android:label="Gate">
        <activity android:name=".MainActivity" android:exported="true"/>
    </application>
</manifest>
"""

_JAVA_SRC = """
package com.example.gate;

public class MainActivity {
    public static int addNumbers(int a, int b) {
        return a + b;
    }
}
"""


def _newest(paths: list[Path]) -> Path | None:
    existing = [p for p in paths if p.exists()]
    return sorted(existing)[-1] if existing else None


def _resolve_sdk() -> dict[str, Path] | None:
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


def _run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, capture_output=True, timeout=180)
    assert result.returncode == 0, (
        f"{cmd[0]} failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace')[:2000]}"
    )


def _build_apk(tmp_path: Path, sdk: dict[str, Path], javac: str) -> Path:
    src_dir = tmp_path / "src" / "com" / "example" / "gate"
    src_dir.mkdir(parents=True)
    (src_dir / "MainActivity.java").write_text(_JAVA_SRC, encoding="utf-8")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(_MANIFEST, encoding="utf-8")

    classes = tmp_path / "classes"
    classes.mkdir()
    # --release 11: build-tools' d8 rejects class-file versions newer than it
    # knows (JDK 21 emits major version 65); targeting 11 stays compatible.
    _run([javac, "--release", "11", "-d", str(classes), str(src_dir / "MainActivity.java")])

    dex_out = tmp_path / "dex"
    dex_out.mkdir()
    _run(
        [
            str(sdk["d8"]),
            "--min-api",
            "21",
            "--lib",
            str(sdk["android_jar"]),
            "--output",
            str(dex_out),
            str(classes / "com" / "example" / "gate" / "MainActivity.class"),
        ]
    )

    # At least one real resource, so aapt2 emits a resources.arsc with a package.
    # apktool refuses to decode a zero-package arsc ("arsc files with zero
    # packages"), which is exactly what a manifest-only link produces.
    res_dir = tmp_path / "res" / "values"
    res_dir.mkdir(parents=True)
    (res_dir / "strings.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources><string name="app_name">Gate</string></resources>\n',
        encoding="utf-8",
    )
    compiled = tmp_path / "compiled"
    compiled.mkdir()
    _run([str(sdk["aapt2"]), "compile", str(res_dir / "strings.xml"), "-o", str(compiled)])

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
            *[str(flat) for flat in sorted(compiled.glob("*.flat"))],
            "--min-sdk-version",
            "21",
            "--target-sdk-version",
            "34",
        ]
    )
    with zipfile.ZipFile(base_apk, "a") as archive:
        archive.write(dex_out / "classes.dex", "classes.dex")

    aligned = tmp_path / "aligned.apk"
    _run([str(sdk["zipalign"]), "-f", "4", str(base_apk), str(aligned)])
    return aligned


def _debug_keystore(tmp_path: Path, keytool: str) -> Path:
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
    return keystore


@pytest.mark.integration
def test_apktool_decode_rebuild_and_resign(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    apktool = shutil.which("apktool")
    if apktool is None:
        pytest.skip("apktool not installed — live Gate not run (skip != pass)")
    sdk = _resolve_sdk()
    if sdk is None:
        pytest.skip(
            "Android SDK not found (set ANDROID_HOME with build-tools + a platform) "
            "— live Gate not run (skip != pass)"
        )
    javac = shutil.which("javac")
    keytool = shutil.which("keytool")
    if javac is None or keytool is None:
        pytest.skip("no JDK (javac/keytool) to build the APK — Gate not run (skip != pass)")

    # apktool's --use-aapt2 rebuild shells out to aapt2; Debian's apktool does
    # not bundle it, so make the SDK's aapt2 discoverable on PATH.
    build_tools_dir = sdk["aapt2"].parent
    monkeypatch.setenv("PATH", f"{build_tools_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    client = ApktoolClient(apktool=Path(apktool), apksigner=sdk["apksigner"])
    apk = _build_apk(tmp_path, sdk, javac)

    decoded = tmp_path / "decoded"
    decode_result = client.decode(apk, decoded, timeout=600.0)
    assert decode_result["manifest"] and Path(decode_result["manifest"]).is_file()
    # apktool disassembles the dex to smali; a real decode produces a smali tree.
    assert decode_result["smali_dirs"], "expected apktool to emit a smali directory"
    manifest_text = Path(decode_result["manifest"]).read_text(encoding="utf-8")
    assert _PACKAGE in manifest_text
    # The decoded smali must carry the class we compiled into the APK.
    smali = (decoded / decode_result["smali_dirs"][0] / "com" / "example" / "gate"
             / "MainActivity.smali")
    assert smali.is_file(), "expected MainActivity.smali in the decoded tree"

    rebuilt = tmp_path / "rebuilt.apk"
    build_result = client.build(decoded, rebuilt, timeout=600.0)
    assert Path(build_result["apk"]).is_file()
    assert build_result["size"] > 0
    assert build_result["signed"] is False

    keystore = _debug_keystore(tmp_path, keytool)
    signed = tmp_path / "signed.apk"
    sign_result = client.sign(
        rebuilt,
        signed,
        keystore=keystore,
        keystore_password="android",
        key_alias="gate",
        timeout=300.0,
    )
    # sign() only returns after apksigner verify succeeds, so this proves the
    # rebuilt APK is genuinely signed, not merely written.
    assert sign_result["signed"] is True
    assert Path(sign_result["apk"]).is_file()
