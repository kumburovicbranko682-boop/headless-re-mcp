"""Android static-tools gate: real jadx decompile and apktool decode/build.

The android RE gate builds a *synthetic* (deliberately invalid) APK to check
session classification and safe degradation, so the external decompilers are
never actually run there. This gate drives the real tools end to end on Linux:

- jadx decompiles a jar compiled on the fly. jadx's decompiler is the same for
  jar, dex and apk input, and a jar needs only a JDK -- no Android SDK -- so this
  exercises JadxClient's real listing / class-path resolution / source reading
  instead of the mocked unit fakes, and asserts a hidden string and method
  bodies come back.
- apktool builds a real APK from a hand-written skeleton (its bundled aapt2
  needs no Android SDK for a framework-free manifest) and decodes it again,
  asserting the manifest round-trips through ApktoolClient.build/decode.

Each half skips honestly when its CLI is not configured (Settings resolves
HEADLESS_RE_JADX / HEADLESS_RE_APKTOOL / PATH). skip != pass.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from headless_re_mcp.backends.apktool.client import ApktoolClient, ApktoolError
from headless_re_mcp.backends.jadx.client import JadxClient
from headless_re_mcp.config import Settings

_JAVA_SOURCE = """package com.headlessre.gate;
public class Secret {
    private static final String FLAG = "H3adl3ss-RE";
    public static int mangle(int x) { return (x ^ 0x41) + 7; }
    public static String reveal() { return FLAG; }
}
"""

_MANIFEST = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="com.headlessre.gate">\n</manifest>\n'
)
# The MetaInfo header is what apktool reads back; a framework-free manifest keeps
# aapt2 from needing an installed android.jar to resolve android:* attributes.
_APKTOOL_YML = "!!brut.androlib.meta.MetaInfo\napkFileName: out.apk\n"


def _build_jar(tmp_path: Path) -> Path | None:
    """Compile a tiny class and jar it, or None when no JDK is present."""
    javac = shutil.which("javac")
    jar = shutil.which("jar")
    if javac is None or jar is None:
        return None
    src_dir = tmp_path / "jsrc" / "com" / "headlessre" / "gate"
    src_dir.mkdir(parents=True)
    (src_dir / "Secret.java").write_text(_JAVA_SOURCE, encoding="utf-8")
    classes = tmp_path / "classes"
    classes.mkdir()
    try:
        subprocess.run(
            [javac, "-d", str(classes), str(src_dir / "Secret.java")],
            check=True,
            capture_output=True,
            timeout=120.0,
        )
        jar_path = tmp_path / "app.jar"
        subprocess.run(
            [jar, "cf", str(jar_path), "-C", str(classes), "com"],
            check=True,
            capture_output=True,
            timeout=60.0,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return None
    return jar_path if jar_path.is_file() else None


@pytest.mark.integration
def test_android_jadx_decompiles_a_real_class(tmp_path: Path) -> None:
    client = JadxClient(executable=Settings.load().jadx)
    if not client.available:
        pytest.skip("jadx not configured (HEADLESS_RE_JADX / PATH) — skip != pass")
    jar = _build_jar(tmp_path)
    if jar is None:
        pytest.skip("no JDK javac/jar — jadx Gate not run (skip != pass)")

    exported = client.export_sources(jar, tmp_path / "jout")
    assert exported["java_file_count"] >= 1
    assert any("Secret.java" in name for name in exported["java_files"]), exported

    # Resolve one class by dotted name: this is _class_to_java_path plus the
    # sources-dir escape checks, not just "a file exists somewhere".
    decompiled = client.decompile(jar, tmp_path / "jout2", "com.headlessre.gate.Secret")
    source = str(decompiled["source"])
    assert decompiled["class_name"] == "com.headlessre.gate.Secret"
    assert "H3adl3ss-RE" in source, source  # the private constant is recovered
    assert "mangle" in source and "reveal" in source, source


@pytest.mark.integration
def test_android_apktool_builds_and_decodes_an_apk(tmp_path: Path) -> None:
    settings = Settings.load()
    client = ApktoolClient(apktool=settings.apktool, apksigner=settings.apksigner)
    if not client.available:
        pytest.skip("apktool not configured (HEADLESS_RE_APKTOOL / PATH) — skip != pass")

    skeleton = tmp_path / "skeleton"
    skeleton.mkdir()
    (skeleton / "AndroidManifest.xml").write_text(_MANIFEST, encoding="utf-8")
    (skeleton / "apktool.yml").write_text(_APKTOOL_YML, encoding="utf-8")

    built = client.build(skeleton, tmp_path / "built.apk")
    assert Path(built["apk"]).is_file()
    assert built["signed"] is False
    assert built["size"] > 0

    decoded = client.decode(tmp_path / "built.apk", tmp_path / "decoded")
    manifest = decoded["manifest"]
    assert manifest and Path(manifest).is_file()
    recovered = Path(manifest).read_text(encoding="utf-8", errors="replace")
    assert "com.headlessre.gate" in recovered, recovered

    # apksigner is a separate Android build-tools binary. Where it is absent the
    # signer must degrade to capability_unavailable, not raise something that
    # surfaces as an internal_error.
    if not client.signer_available:
        with pytest.raises(ApktoolError) as excinfo:
            client.sign(tmp_path / "built.apk", tmp_path / "signed.apk")
        assert excinfo.value.code == "capability_unavailable"
