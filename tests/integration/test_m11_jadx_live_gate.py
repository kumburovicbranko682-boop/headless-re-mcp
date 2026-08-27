"""M11 jadx live gate: decompile a real class on the installed jadx.

The jadx path (``apk.export_sources`` / ``apk.decompile``) had no live coverage:
the Android RE gate only builds a synthetic APK and asserts structured
degradation, so a jadx that changed its output layout would slip through -- the
client reads decompiled Java from ``<out>/sources/...`` and maps a class name to
``sources/<pkg>/<Class>.java``, both layout conventions that only a real run
verifies. jadx accepts JVM bytecode as well as Dalvik, so this compiles a tiny
``com.example.Sample`` with javac, jars it, and runs jadx over it. Portable: it
resolves jadx from settings/PATH exactly as the service does and skips
(skip != pass) when jadx or a JDK is absent.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx import JadxClient
from headless_re_mcp.config import Settings

_SAMPLE = """package com.example;

public class Sample {
    public static int addNumbers(int a, int b) {
        return a + b;
    }

    public String greetingMarker() {
        return "JADX_GATE_MARKER";
    }
}
"""


def _jadx_client() -> JadxClient:
    return JadxClient(getattr(Settings.load(), "jadx", None))


def _build_fixture_jar(tmp_path: Path) -> Path:
    """Compile com.example.Sample and package it as a jar jadx can read."""
    javac = shutil.which("javac")
    jar = shutil.which("jar")
    if javac is None or jar is None:
        pytest.skip("no JDK (javac/jar) to build a jadx fixture — jadx Gate not run (skip != pass)")
    src = tmp_path / "src" / "com" / "example" / "Sample.java"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(_SAMPLE, encoding="utf-8")
    classes = tmp_path / "classes"
    classes.mkdir()
    try:
        compiled = subprocess.run(  # noqa: S603 - fixed local toolchain, fixed args
            [javac, "-d", str(classes), str(src)],
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"javac could not build the fixture ({exc}) — skip != pass")
    if compiled.returncode != 0:
        detail = compiled.stderr.decode("utf-8", errors="replace")[:200]
        pytest.skip(f"javac failed ({detail}) — jadx Gate not run (skip != pass)")
    jar_path = tmp_path / "sample.jar"
    try:
        built = subprocess.run(  # noqa: S603 - fixed local toolchain, fixed args
            [jar, "cf", str(jar_path), "-C", str(classes), "com"],
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"jar could not package the fixture ({exc}) — skip != pass")
    if built.returncode != 0 or not jar_path.is_file():
        pytest.skip("jar produced no fixture — jadx Gate not run (skip != pass)")
    return jar_path


@pytest.mark.integration
def test_m11_jadx_live_decompiles_a_real_class(tmp_path: Path) -> None:
    client = _jadx_client()
    if not client.available:
        pytest.skip("jadx not installed/configured — jadx Gate not run (skip != pass)")
    jar = _build_fixture_jar(tmp_path)

    export = client.export_sources(jar, tmp_path / "export")
    # A clean run must not be flagged as a partial decompile.
    assert export.get("tool_failed") is not True, export
    assert export["sources_dir"] is not None
    assert export["java_file_count"] >= 1
    # The client reads decompiled Java from <out>/sources/...; pin that layout so
    # a jadx that relocates its output is caught here rather than returning an
    # empty tree that every mocked test still accepts.
    assert any(
        name.replace("\\", "/") == "sources/com/example/Sample.java"
        for name in export["java_files"]
    ), export["java_files"]

    decompiled = client.decompile(jar, tmp_path / "decompile", "com.example.Sample")
    assert decompiled["class_name"] == "com.example.Sample"
    # A clean decompile does not carry the partial-run flag either.
    assert decompiled.get("tool_failed") is not True, decompiled
    source = decompiled["source"]
    assert "class Sample" in source
    assert "addNumbers" in source
    # The marker string survives decompilation verbatim; a wrong file or an empty
    # read cannot produce it, so it pins the class-name -> path mapping too.
    assert "JADX_GATE_MARKER" in source
