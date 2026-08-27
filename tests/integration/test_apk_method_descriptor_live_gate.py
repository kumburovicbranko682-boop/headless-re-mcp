"""apk.methods live gate: descriptors come back in canonical Dalvik form.

androguard's ``EncodedMethod.get_descriptor()`` documents its output as
``(A A A ...)R`` -- a single space between each argument type, so a two-int
method reads ``(I I)I``. That is not the canonical Dalvik type descriptor the
dex-format spec defines and that baksmali, dexdump, jadx and Frida's ``Java``
overloads all speak (``(II)I``); a caller pasting the spaced form into any of
them is silently wrong. The backend now strips those inter-argument spaces, and
this gate pins the fix against the *real* library: every apk.methods unit test
mocks the parser, so only real androguard proves both that it still emits the
spaced form and that the backend canonicalizes it.

The DEX is embedded (compiled once with javac + Android's D8 dexer, the same
bytecode the DEX-analysis gate uses), so the gate depends only on androguard --
no Android SDK, no emulator. The source class is::

    package com.example;
    public class Widget {
        public static String greeting() { return "ANDROGUARD_DEX_MARKER"; }
        public int addNumbers(int a, int b) { return a + b; }
        public int compute() { return addNumbers(2, 40); }
        public static void main(String[] a) { System.out.println(greeting()); }
    }

so ``addNumbers`` is the two-argument method whose raw androguard descriptor
carries the space the fix removes. The gate first confirms androguard really
produced a spaced descriptor (else the test would prove nothing), then that
apk.methods handed back the space-free canonical form with ``access`` still
populated -- the version-sensitive MethodAnalysis attributes a rename would
silently empty.

Skip != pass: the gate skips with a reason when androguard is absent and runs
for real when present. CI installs it, so a skip there is a genuine regression.
"""

from __future__ import annotations

import base64
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

# D8 (--release --min-api 21) output for the class shown in the module docstring.
_DEX_B64 = (
    "ZGV4CjAzNQBOm914vMLkiqXTohpe1zmo61VscZANTXVUBAAAcAAAAHhWNBIAAAAAAAAAALQDAAAVAAAAcAAAAAgA"
    "AADEAAAABgAAAOQAAAABAAAALAEAAAcAAAA0AQAAAQAAAGwBAADIAgAAjAEAAD4CAABGAgAAXQIAAGACAABlAgAA"
    "aAIAAH4CAACVAgAAqQIAAL0CAADRAgAA1AIAANgCAADlAgAA+gIAAAYDAAAPAwAAGQMAAB8DAAAkAwAALQMAAAIA"
    "AAAFAAAABgAAAAcAAAAIAAAACQAAAAoAAAANAAAAAgAAAAAAAAAAAAAAAwAAAAAAAAAoAgAABAAAAAQAAAAAAAAA"
    "CgAAAAYAAAAAAAAACwAAAAYAAAAwAgAACwAAAAYAAAA4AgAABQACABIAAAABAAMAAAAAAAEAAQAOAAAAAQAAAA8A"
    "AAABAAIAEAAAAAEABQARAAAAAgAEABMAAAADAAMAAAAAAAEAAAABAAAAAwAAAAAAAAAMAAAAAAAAAJcDAAAAAAAA"
    "AwADAAAAAAAAAAAAAgAAALAhDwEDAAEAAwAAABQCAAAIAAAAEiATASgAbjABAAIBCgAPAAEAAAAAAAAAGAIAAAMA"
    "AAAaAAEAEQAAAAEAAQABAAAAHAIAAAQAAABwEAYAAAAOAAIAAQACAAAAIAIAAAoAAABiAQAAcQADAAAADABuIAUA"
    "AQAOAAUAOwADAA4AAgAOAAYBAA4AAAAAAgAAAAAAAAABAAAABAAAAAEAAAAHAAY8aW5pdD4AFUFORFJPR1VBUkRf"
    "REVYX01BUktFUgABSQADSUlJAAFMABRMY29tL2V4YW1wbGUvV2lkZ2V0OwAVTGphdmEvaW8vUHJpbnRTdHJlYW07"
    "ABJMamF2YS9sYW5nL09iamVjdDsAEkxqYXZhL2xhbmcvU3RyaW5nOwASTGphdmEvbGFuZy9TeXN0ZW07AAFWAAJW"
    "TAALV2lkZ2V0LmphdmEAE1tMamF2YS9sYW5nL1N0cmluZzsACmFkZE51bWJlcnMAB2NvbXB1dGUACGdyZWV0aW5n"
    "AARtYWluAANvdXQAB3ByaW50bG4AaH5+RDh7ImJhY2tlbmQiOiJkZXgiLCJjb21waWxhdGlvbi1tb2RlIjoicmVs"
    "ZWFzZSIsImhhcy1jaGVja3N1bXMiOmZhbHNlLCJtaW4tYXBpIjoyMSwidmVyc2lvbiI6IjguOS4zNSJ9AAAAAwIA"
    "gYAE2AMDCcADAQnwAwEBjAMBAaADAAAADQAAAAAAAAABAAAAAAAAAAEAAAAVAAAAcAAAAAIAAAAIAAAAxAAAAAMA"
    "AAAGAAAA5AAAAAQAAAABAAAALAEAAAUAAAAHAAAANAEAAAYAAAABAAAAbAEAAAEgAAAFAAAAjAEAAAMgAAAEAAAA"
    "FAIAAAEQAAADAAAAKAIAAAIgAAAVAAAAPgIAAAAgAAABAAAAlwMAAAAQAAABAAAAtAMAAA=="
)

_CLASS_SMALI = "Lcom/example/Widget;"
_CLASS_DOTTED = "com.example.Widget"


def _quiet_androguard() -> None:
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - logging quiet is best-effort
        pass


def _raw_addnumbers_descriptor(apk: Path) -> str:
    """The descriptor androguard itself reports for addNumbers, before the backend."""
    from androguard.misc import AnalyzeAPK

    _, _, dx = AnalyzeAPK(str(apk))
    for klass in dx.get_classes():
        if klass.name != _CLASS_SMALI:
            continue
        for method in klass.get_methods():
            if method.name == "addNumbers":
                return str(method.descriptor)
    raise AssertionError("addNumbers not found in the fixture DEX")


@pytest.mark.integration
def test_apk_methods_descriptor_is_canonical_dalvik(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — descriptor Gate not run (skip != pass)")
    _quiet_androguard()

    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", base64.b64decode(_DEX_B64))

    # Guard the guard: the fix is only meaningful if androguard really emits the
    # space. If a future androguard stops doing so, this makes the test say so
    # instead of passing vacuously.
    raw = _raw_addnumbers_descriptor(apk)
    assert raw == "(I I)I", f"androguard's raw descriptor changed shape: {raw!r}"

    payload = client.methods(apk, _CLASS_DOTTED)
    by_name = {m["name"]: m for m in payload["methods"]}
    assert "addNumbers" in by_name, by_name

    add = by_name["addNumbers"]
    # The two-int descriptor came back canonical: no inter-argument space, the
    # exact form baksmali/dexdump/jadx/Frida use.
    assert add["descriptor"] == "(II)I"
    assert " " not in add["descriptor"]

    # No method's descriptor leaks androguard's spacing, and class-type
    # descriptors keep their slashes and trailing ';'.
    for method in payload["methods"]:
        assert " " not in method["descriptor"], method
    assert by_name["greeting"]["descriptor"] == "()Ljava/lang/String;"

    # access stayed populated -- the version-sensitive MethodAnalysis attribute
    # a rename would silently empty.
    assert add["access"]
    assert "public" in add["access"]
