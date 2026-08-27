"""jadx decompile live gate: real bytecode to Java source through the client.

The Android gate builds a *synthetic* APK and only asserts that jadx-backed
calls return "ok or an error" -- it never proves jadx decompiled anything,
because a hand-built zip is not something jadx can decompile. So the whole jadx
pipeline (``export_sources`` walking the emitted tree, ``decompile`` reading one
class's Java back) only ran against mocks and a stub that fails.

jadx decompiles JVM bytecode as readily as Dalvik, so this gate compiles a real
class with ``javac`` (JDK only, no Android SDK), jars it, and drives the exact
``JadxClient`` methods ``apk.export_sources`` / ``apk.decompile`` call. It proves
jadx recovered *this* class -- its declared methods and a distinctive string
literal -- from real bytecode. It exercises the decompiler engine and the
client's tree-walk/read-back, not the DEX front-end specifically (that needs a
real APK, which needs the Android build tools); that boundary is stated so a
green here is not misread as "DEX decompilation is covered".

Skip != pass: the gate skips with a reason when a JDK or jadx is absent, and
runs for real when both are present. CI installs both, so a skip there is a
genuine regression rather than a bare machine.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient

_MARKER = "JADX_GATE_MARKER"
_JAVA_SRC = f"""package com.example;

public class Widget {{
    public static String greeting() {{ return "{_MARKER}"; }}

    public int addNumbers(int a, int b) {{ return a + b; }}

    public static void main(String[] args) {{
        System.out.println(greeting());
    }}
}}
"""


def _jadx_path() -> Path | None:
    configured = os.environ.get("HEADLESS_RE_JADX")
    found = configured or shutil.which("jadx")
    if not found:
        return None
    path = Path(found)
    return path if path.is_file() else None


def _build_jar(tmp_path: Path) -> Path | None:
    javac = shutil.which("javac")
    jar_tool = shutil.which("jar")
    if javac is None or jar_tool is None:
        return None
    src = tmp_path / "com" / "example" / "Widget.java"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(_JAVA_SRC, encoding="utf-8")
    classes = tmp_path / "classes"
    classes.mkdir()
    compiled = subprocess.run(
        [javac, "-d", str(classes), str(src)], capture_output=True, timeout=120
    )
    if compiled.returncode != 0:
        return None
    jar = tmp_path / "app.jar"
    packed = subprocess.run(
        [jar_tool, "cf", str(jar), "-C", str(classes), "."],
        capture_output=True,
        timeout=120,
    )
    return jar if packed.returncode == 0 and jar.is_file() else None


@pytest.mark.integration
def test_jadx_decompiles_real_bytecode_to_java(tmp_path: Path) -> None:
    jadx = _jadx_path()
    if jadx is None:
        pytest.skip("jadx not installed/configured — decompile Gate not run (skip != pass)")
    jar = _build_jar(tmp_path)
    if jar is None:
        pytest.skip("no JDK (javac/jar) to build the fixture — Gate not run (skip != pass)")

    client = JadxClient(jadx)
    assert client.available

    export = client.export_sources(jar, tmp_path / "out", timeout=180.0)
    # jadx must emit a Java tree, and the client must find our class in it.
    assert export.get("java_file_count", 0) >= 1
    assert any("Widget.java" in name for name in export.get("java_files", []))
    assert export.get("sources_dir"), "jadx wrote no sources/ tree"
    # This class decompiles cleanly, so the whole-run verdict must not be failed.
    assert not export.get("tool_failed")

    decompiled = client.decompile(jar, tmp_path / "out2", "com.example.Widget", timeout=180.0)
    source = decompiled.get("source", "")
    assert decompiled.get("class_name") == "com.example.Widget"
    # Real decompilation recovers the class, both methods and the string literal
    # -- not a stub or an empty file.
    assert "class Widget" in source
    assert "greeting" in source
    assert "addNumbers" in source
    assert _MARKER in source
