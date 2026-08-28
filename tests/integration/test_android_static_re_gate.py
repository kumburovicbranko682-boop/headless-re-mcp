"""Android static line live gate: androguard code facts + jadx decompilation.

``test_android_re_gate`` builds a synthetic (not AXML-valid) zip and only checks
that the Android surface returns a structured envelope. That proves the plumbing
but never that the real analysers read real code, so this gate assembles a small,
genuine APK at test time (javac -> d8 -> aapt, nothing tracked) and asserts on the
facts the tools recover, not just an ``ok`` flag:

* androguard: the package name, the single non-external class, its ``compute`` /
  ``run`` methods, the caller edge ``run -> compute`` recovered from bytecode
  xrefs, the declared ``INTERNET`` permission, and the exported ``MainActivity``
  component;
* jadx: a whole-APK export that lands a ``MainActivity.java`` on disk, and a
  single-class decompile whose Java source carries the class, the ``compute``
  method, and the ``compute(2, 3)`` call from ``run`` -- i.e. the arithmetic
  survived the dex -> Java round trip.

This complements the repackaging gate (which exercises apktool + apksigner): here
the focus is the read-only static surface. skip != pass -- the androguard case
skips without the ``[android]`` extra, the jadx case without a configured jadx,
and both without the SDK build tools needed to assemble the APK.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import ApkClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_PACKAGE = "com.example.headless"
_CLASS_DOTTED = "com.example.MainActivity"
_CLASS_SMALI = "Lcom/example/MainActivity;"
_PERMISSION = "android.permission.INTERNET"

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
    """Locate an SDK build-tool: PATH first, then the newest build-tools dir."""
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


def _build_input_apk(tmp_path: Path) -> Path | None:
    """Assemble a small, real (unsigned) APK, or None when the SDK/JDK is absent."""
    aapt = _sdk_build_tool("aapt")
    d8 = _sdk_build_tool("d8")
    javac = shutil.which("javac")
    android_jar = _android_jar()
    if not (aapt and d8 and javac and android_jar):
        return None

    src = tmp_path / "src" / "com" / "example"
    src.mkdir(parents=True)
    (src / "MainActivity.java").write_text(_JAVA_SOURCE, encoding="utf-8")
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(_MANIFEST, encoding="utf-8")

    classes = tmp_path / "classes"
    classes.mkdir()
    subprocess.run(
        [javac, "--release", "8", "-d", str(classes), str(src / "MainActivity.java")],
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
    subprocess.run(
        [str(aapt), "add", str(apk), "classes.dex"],
        cwd=str(dex),
        check=True,
        capture_output=True,
    )
    return apk


@pytest.mark.integration
def test_android_static_facts_via_androguard(tmp_path: Path) -> None:
    if not ApkClient().available:
        pytest.skip("androguard not installed ([android] extra) — not run (skip≠pass)")
    apk = _build_input_apk(tmp_path)
    if apk is None:
        pytest.skip("Android SDK build-tools / JDK missing — cannot assemble an APK (skip≠pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        opened = service.apk_open(session_id)
        assert opened.ok, opened.error
        assert opened.data["package"] == _PACKAGE

        classes = service.apk_classes(session_id)
        assert classes.ok, classes.error
        assert _CLASS_SMALI in classes.data["classes"]
        assert classes.data["total"] == 1

        methods = service.apk_methods(session_id, _CLASS_DOTTED)
        assert methods.ok, methods.error
        names = {m["name"] for m in methods.data["methods"]}
        assert {"compute", "run"} <= names

        # The bytecode xref: run() calls compute(). This is the fact that
        # separates "parsed the dex" from "understood the call graph".
        xrefs = service.apk_xrefs(session_id, "compute")
        assert xrefs.ok, xrefs.error
        callers = {(c["class"], c["method"]) for c in xrefs.data["callers"]}
        assert (_CLASS_SMALI, "run") in callers

        permissions = service.apk_permissions(session_id)
        assert permissions.ok, permissions.error
        assert _PERMISSION in permissions.data["permissions"]

        components = service.apk_components(session_id)
        assert components.ok, components.error
        assert _CLASS_DOTTED in components.data["activities"]
        assert components.data["main_activity"] == _CLASS_DOTTED
    finally:
        service.close_all()


@pytest.mark.integration
def test_android_decompile_via_jadx(tmp_path: Path) -> None:
    jadx = getattr(Settings.load(), "jadx", None)
    if jadx is None:
        pytest.skip("jadx not configured (needs a JRE) — not run (skip≠pass)")
    apk = _build_input_apk(tmp_path)
    if apk is None:
        pytest.skip("Android SDK build-tools / JDK missing — cannot assemble an APK (skip≠pass)")

    service = AnalysisService()
    try:
        created = service.create_session(str(apk), target="apk")
        assert created.ok, created.error
        session_id = created.data["session"]["id"]

        # Whole-APK export: a real Java tree lands on disk.
        exported = service.apk_export_sources(session_id)
        assert exported.ok, exported.error
        assert exported.data["java_file_count"] >= 1
        assert exported.data["sources_dir"] is not None
        assert not exported.data.get("tool_failed")
        assert any(name.endswith("MainActivity.java") for name in exported.data["java_files"])

        # Single-class decompile: the arithmetic survived dex -> Java.
        decompiled = service.apk_decompile(session_id, _CLASS_DOTTED)
        assert decompiled.ok, decompiled.error
        assert decompiled.data["class_name"] == _CLASS_DOTTED
        assert decompiled.data["truncated"] is False
        assert not decompiled.data.get("tool_failed")
        source = decompiled.data["source"]
        assert "class MainActivity" in source
        assert "compute" in source
        assert "compute(2, 3)" in source
    finally:
        service.close_all()
