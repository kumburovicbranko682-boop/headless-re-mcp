"""APK static gate: jadx decompiles real Java bytecode end to end.

The Android RE gate (test_android_re_gate.py) runs tool-free on a synthetic APK;
jadx -- the core of the APK static line -- was only ever exercised through unit
tests with the subprocess mocked. This drives the real jadx CLI against a tiny
class compiled at run time (JDK only, no Android SDK), so the invocation, the
on-disk output layout, and the class-path resolution the adapter depends on are
checked against the tool instead of a stub. jadx accepts .jar / .dex input, not
just .apk, so a javac-built jar is a faithful stand-in for an APK's classes for
this backend. skip != pass when jadx or a JDK is absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient, JadxError
from headless_re_mcp.config import Settings

_SOURCE = """\
package com.example;

public class Sample {
    public static int add(int a, int b) {
        return a + b;
    }

    public static String greet(String who) {
        return "hello " + who;
    }
}
"""


def _configured_jadx() -> Path | None:
    """The jadx path the product would resolve: env, config, then PATH."""
    try:
        return Settings.load().jadx
    except Exception:  # noqa: BLE001 - a config problem is a skip, not an error
        return None


def _build_jar(work: Path) -> Path:
    """Compile the sample class and pack it, or skip if no JDK is present."""
    javac = shutil.which("javac")
    jar = shutil.which("jar")
    if not javac or not jar:
        pytest.skip("no JDK (javac/jar) — cannot build the decompile fixture (skip != pass)")
    work.mkdir(parents=True, exist_ok=True)
    source = work / "Sample.java"
    source.write_text(_SOURCE, encoding="utf-8")
    subprocess.run([javac, "-d", str(work), str(source)], check=True, capture_output=True)
    archive = work / "sample.jar"
    subprocess.run(
        [jar, "cf", str(archive), "-C", str(work), "com"], check=True, capture_output=True
    )
    return archive


@pytest.mark.integration
def test_jadx_decompiles_a_real_class(tmp_path: Path) -> None:
    jadx = _configured_jadx()
    if not jadx:
        pytest.skip("jadx not configured — jadx Gate not run (skip != pass)")
    archive = _build_jar(tmp_path / "build")
    client = JadxClient(executable=jadx)
    assert client.available

    exported = client.export_sources(archive, tmp_path / "out")
    assert exported["java_file_count"] >= 1
    assert exported["sources_dir"] is not None
    assert any(name.endswith("com/example/Sample.java") for name in exported["java_files"])

    decompiled = client.decompile(archive, tmp_path / "out2", "com.example.Sample")
    assert decompiled["class_name"] == "com.example.Sample"
    # Real decompiled Java, not a stubbed string: both method names survive the
    # bytecode round-trip.
    assert "add" in decompiled["source"]
    assert "greet" in decompiled["source"]
    assert decompiled["truncated"] is False


@pytest.mark.integration
def test_jadx_reports_not_found_for_an_absent_class(tmp_path: Path) -> None:
    # A class the caller names but jadx never emitted is a structured not_found,
    # not the first Main.java in the tree and not a crash.
    jadx = _configured_jadx()
    if not jadx:
        pytest.skip("jadx not configured — jadx Gate not run (skip != pass)")
    archive = _build_jar(tmp_path / "build")
    client = JadxClient(executable=jadx)
    with pytest.raises(JadxError) as info:
        client.decompile(archive, tmp_path / "out", "com.example.DoesNotExist")
    assert info.value.code == "not_found"
