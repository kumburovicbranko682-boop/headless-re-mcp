"""Android decompile gate: a real DEX through jadx, end to end via the service.

The Android RE gate proves classification and clean degradation on a *synthetic*
APK; it never decompiles anything, because that needs a real ``classes.dex`` and
a jadx install. This gate builds a genuine Android artifact -- javac then d8 into
a real DEX, zipped into an APK -- and drives ``apk.export_sources`` /
``apk.decompile`` through ``AnalysisService`` exactly as an MCP client would,
asserting the recovered Java carries the methods that were compiled in. That is
the first end-to-end proof of the jadx line off Windows (the unit tests only
mock the subprocess, which is how two Ghidra breakages went unnoticed).

skip != pass: it skips only when jadx is unconfigured or no javac/dexer exists
to build the fixture.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx import JadxClient
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService

_SAMPLE_JAVA = """
package com.example;
public class Sample {
    public static int addOne(int value) { return value + 1; }
    public String greet(String name) { return "hello " + name; }
}
"""


def _find_dexer() -> list[str] | None:
    """An argv prefix that turns .class files into a DEX.

    Prefers a real ``d8`` on PATH (Android build-tools); otherwise the R8 jar
    (which ships D8) pointed at by ``HEADLESS_RE_R8_JAR`` -- the form the Linux
    CI job configures. ``None`` means no dexer, which is an honest skip.
    """
    d8 = shutil.which("d8")
    if d8 is not None:
        return [d8]
    jar = os.environ.get("HEADLESS_RE_R8_JAR")
    java = shutil.which("java")
    if jar and Path(jar).is_file() and java is not None:
        return [java, "-cp", jar, "com.android.tools.r8.D8"]
    return None


def _build_apk_fixture(tmp_path: Path) -> Path | None:
    """Compile Java, dex it, and zip a minimal APK carrying that real DEX."""
    javac = shutil.which("javac")
    dexer = _find_dexer()
    if javac is None or dexer is None:
        return None
    src_dir = tmp_path / "src" / "com" / "example"
    src_dir.mkdir(parents=True)
    source = src_dir / "Sample.java"
    source.write_text(_SAMPLE_JAVA, encoding="utf-8")
    classes = tmp_path / "classes"
    dex_dir = tmp_path / "dex"
    dex_dir.mkdir()
    try:
        subprocess.run(
            [javac, "-d", str(classes), str(source)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        subprocess.run(
            [
                *dexer,
                "--output",
                str(dex_dir),
                "--min-api",
                "21",
                str(classes / "com" / "example" / "Sample.class"),
            ],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    dex = dex_dir / "classes.dex"
    if not dex.is_file():
        return None
    apk = tmp_path / "sample.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        # A placeholder manifest is enough for stdlib APK classification; the DEX
        # is the real payload jadx decompiles.
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.write(dex, "classes.dex")
        archive.writestr("resources.arsc", b"\x02\x00placeholder")
    return apk


@pytest.mark.integration
def test_apk_decompile_recovers_compiled_methods(tmp_path: Path) -> None:
    if not JadxClient(getattr(Settings.load(), "jadx", None)).available:
        pytest.skip("jadx not configured — Android decompile Gate not run (skip != pass)")
    apk = _build_apk_fixture(tmp_path / "build")
    if apk is None:
        pytest.skip("no javac/dexer to build a DEX — Android decompile Gate not run (skip != pass)")

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    try:
        created = service.create_session(str(apk))
        assert created.ok and created.data is not None, created.error
        assert created.data["session"]["target"] == "apk"
        session_id = created.data["session"]["id"]

        exported = service.apk_export_sources(session_id, timeout=180.0)
        assert exported.ok and exported.data is not None, exported.error
        assert exported.data["java_file_count"] >= 1

        decompiled = service.apk_decompile(session_id, "com.example.Sample", timeout=180.0)
        assert decompiled.ok and decompiled.data is not None, decompiled.error
        source = decompiled.data["source"]
        # The decompiler must recover the actual members, not merely return a
        # file: if jadx or the adapter were broken, the source would be empty or
        # the class would be missing.
        assert "class Sample" in source
        assert "addOne" in source
        assert "greet" in source
    finally:
        service.close_all()
