"""Cross-validate the DEX native-method surface against a real d8 build + androguard.

A session over an APK now reports the Java methods declared ``native`` -- the
DEX side of the JNI bridge, the Android pair to a .NET P/Invoke import and to a
native undefined symbol: where managed code drops into the bundled ``.so``
libraries (whose export side the native-lib facts already read as ``Java_*``
symbols and ``JNI_OnLoad``). The reader walks each class's class_data_item and
names every ACC_NATIVE method, and that walk is ours, so this gate refuses to
trust either a hand-built DEX or the reader's own parse:

* javac (from the JDK) compiles a real Java class declaring native methods, and
  d8 -- the standalone Java->DEX compiler shipped inside r8.jar -- turns it into
  a real classes.dex. Neither the gate nor the reader controls the
  class_data_item layout d8 emits.
* androguard opens that same classes.dex and, through its own ECMA/Dalvik
  parser, lists every EncodedMethod whose access flags carry ACC_NATIVE. The
  reader's ``native_methods`` must equal androguard's set name for name, and its
  ``native_method_count`` must match too -- so the compiler, the referee and the
  reader all agree on the bridge, and a pure-Java class in the same build
  contributes nothing.

d8 comes from r8.jar (env ``HEADLESS_RE_D8_JAR`` in CI, or a ``d8`` on PATH);
androguard from the ``[android]`` extra. skip != pass: the gate skips, naming
the missing piece, only when javac, d8 or androguard is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.core.service import AnalysisService

_JAVA_SOURCE = """\
package com.example.jni;

public class Bridge {
    // The JNI bridge: no bytecode body, bound to a function in a bundled .so.
    public static native int nativeAdd(int a, int b);
    public native String nativeGreeting();

    // A pure-Java method in the same class must NOT be reported as native.
    public int pureJava() {
        return 7;
    }

    static {
        System.loadLibrary("demo");
    }
}
"""

_EXPECTED = {"com.example.jni.Bridge.nativeAdd", "com.example.jni.Bridge.nativeGreeting"}


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def _d8_command() -> list[str] | None:
    """The argv prefix that runs d8, or None when no d8 is reachable."""
    jar = os.environ.get("HEADLESS_RE_D8_JAR")
    java = shutil.which("java")
    if jar and Path(jar).is_file() and java is not None:
        return [java, "-cp", jar, "com.android.tools.r8.D8"]
    standalone = shutil.which("d8")
    if standalone is not None:
        return [standalone]
    return None


def _compile_native_dex(work: Path) -> bytes:
    """javac the native-method class, d8 it, return the real classes.dex bytes."""
    src = work / "com" / "example" / "jni" / "Bridge.java"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(_JAVA_SOURCE)
    classes = work / "classes"
    classes.mkdir()
    subprocess.run(
        ["javac", "-d", str(classes), str(src)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    out = work / "dex"
    out.mkdir()
    d8 = _d8_command()
    assert d8 is not None  # guarded by the caller's skip
    compiled = classes / "com" / "example" / "jni" / "Bridge.class"
    subprocess.run(
        [*d8, "--min-api", "21", "--output", str(out), str(compiled)],
        check=True,
        capture_output=True,
        timeout=180,
    )
    return (out / "classes.dex").read_bytes()


def _apk_with_dex(path: Path, dex: bytes) -> None:
    # A dummy binary AXML manifest is all classify_target needs to treat the
    # archive as an APK; the dex facts come from the classes.dex member.
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
        archive.writestr("classes.dex", dex)


def _session_dex(apk: Path) -> dict:
    service = AnalysisService()
    try:
        created = service.create_session(str(apk))
        assert created.ok, created.error
        return created.data["session"]["metadata"]["apk"]["dex"]
    finally:
        service.close_all()


def _androguard_native_methods(dex: bytes) -> set[str]:
    from loguru import logger

    logger.remove()
    from androguard.core.dex import DEX

    parsed = DEX(dex)
    native: set[str] = set()
    for klass in parsed.get_classes():
        for method in klass.get_methods():  # EncodedMethod: carries access flags
            if method.get_access_flags() & 0x100:  # ACC_NATIVE
                owner = method.get_class_name()[1:-1].replace("/", ".")
                native.add(f"{owner}.{method.get_name()}")
    return native


@pytest.mark.integration
def test_native_methods_agree_with_a_real_d8_build_and_androguard(tmp_path: Path) -> None:
    if shutil.which("javac") is None:
        pytest.skip("javac not installed — DEX native-method gate not run (skip != pass)")
    if _d8_command() is None:
        pytest.skip("d8 (r8.jar) not available — DEX native-method gate not run (skip != pass)")
    if not _androguard_available():
        pytest.skip("androguard not installed — DEX native-method gate not run (skip != pass)")

    dex = _compile_native_dex(tmp_path)

    # The referee first, so a broken parse fails loudly rather than matching an
    # empty reader result: androguard must actually see both native methods.
    referee = _androguard_native_methods(dex)
    assert referee == _EXPECTED, referee

    apk = tmp_path / "bridge.apk"
    _apk_with_dex(apk, dex)
    facts = _session_dex(apk)

    # Name for name and count for count: the reader's ACC_NATIVE walk over d8's
    # class_data_item matches androguard's independent decode, and the
    # pure-Java method contributes to neither side.
    assert set(facts["native_methods"]) == referee
    assert facts["native_method_count"] == len(referee)
