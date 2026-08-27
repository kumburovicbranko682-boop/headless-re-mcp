"""jadx live gate: real decompilation through the jadx CLI on Linux.

jadx is a cross-platform JVM tool, so this runs on Linux CI rather than only on
Windows. It drives the same adapter path the APK tools use (``export_sources``
then ``decompile``), but feeds it a JAR compiled from Java source: jadx accepts
JARs as a first-class input, so this exercises the whole subprocess/read-back
path for real without needing an Android SDK to produce a DEX/APK. The existing
Android gate only builds a *synthetic* archive and asserts graceful degradation,
so nothing ever ran jadx end to end before this.

Skip != pass: the gate skips with a reason when jadx or a JDK is absent, and
runs for real when both are present. CI installs both, so a skip there is a
genuine regression rather than a bare machine.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.jadx.client import JadxClient
from headless_re_mcp.config import Settings

# Named members so the assertions prove jadx recovered real source, not merely
# emitted some file.
_FIXTURE_SRC = """
package com.example;

public class Secret {
    public static int addNumbers(int a, int b) {
        return a + b;
    }

    public String greet(String who) {
        return "hello " + who;
    }

    public static void main(String[] args) {
        System.out.println(addNumbers(args.length, 7));
    }
}
"""


def _resolve_jadx() -> Path | None:
    """Project config / HEADLESS_RE_JADX, then a jadx already on PATH."""
    configured = getattr(Settings.load(), "jadx", None)
    if configured is not None:
        return Path(configured)
    found = shutil.which("jadx")
    return Path(found) if found else None


def _build_jar(tmp_path: Path) -> Path | None:
    javac = shutil.which("javac")
    jar_tool = shutil.which("jar")
    if javac is None or jar_tool is None:
        return None
    src_dir = tmp_path / "src" / "com" / "example"
    src_dir.mkdir(parents=True)
    (src_dir / "Secret.java").write_text(_FIXTURE_SRC, encoding="utf-8")
    classes = tmp_path / "classes"
    classes.mkdir()
    compiled = subprocess.run(
        [javac, "-d", str(classes), str(src_dir / "Secret.java")],
        capture_output=True,
        timeout=120,
    )
    if compiled.returncode != 0:
        return None
    jar_path = tmp_path / "sample.jar"
    packed = subprocess.run(
        [jar_tool, "cf", str(jar_path), "-C", str(classes), "com"],
        capture_output=True,
        timeout=120,
    )
    return jar_path if packed.returncode == 0 and jar_path.is_file() else None


@pytest.mark.integration
def test_jadx_decompiles_a_real_jar(tmp_path: Path) -> None:
    jadx = _resolve_jadx()
    if jadx is None or not jadx.is_file():
        pytest.skip(
            "jadx not configured (set HEADLESS_RE_JADX) — live Gate not run (skip != pass)"
        )
    client = JadxClient(executable=jadx)
    jar = _build_jar(tmp_path)
    if jar is None:
        pytest.skip("no JDK (javac/jar) to build a fixture — Gate not run (skip != pass)")

    out_dir = tmp_path / "jadx-out"

    exported = client.export_sources(jar, out_dir, timeout=600.0)
    assert exported["java_file_count"] >= 1
    assert any("Secret.java" in name for name in exported["java_files"])
    # A JAR with intact bytecode decompiles cleanly; jadx must not report failure.
    assert not exported.get("tool_failed")

    decompiled = client.decompile(jar, out_dir, "com.example.Secret", timeout=600.0)
    source = decompiled["source"]
    assert isinstance(source, str) and source.strip()
    # Real decompilation recovers the method names, not just a stub.
    assert "addNumbers" in source
    assert "greet" in source
