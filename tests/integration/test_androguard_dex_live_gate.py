"""androguard DEX-analysis live gate: real Dalvik bytecode through ApkClient.

The Android static line's only integration coverage builds a *synthetic* APK (a
hand-made zip) and asserts nothing more than "androguard returned ok or an
error" -- so ``apk.classes`` / ``apk.methods`` / ``apk.strings`` / ``apk.xrefs``
never actually analysed a DEX; their parsing and paging only ran against mocks.
Those four go through androguard's ``AnalyzeAPK``, which analyses the classes.dex
inside the archive; it does not need the binary AndroidManifest.xml to do so, so
a real DEX packed into a minimal zip exercises the whole DEX-analysis path.

The DEX is embedded (compiled once with javac and Android's D8 dexer from these
sources, then dexed to real Dalvik bytecode), so the gate depends only on
androguard -- no Android SDK, no emulator. The source class is::

    package com.example;
    public class Widget {
        public static String greeting() { return "ANDROGUARD_DEX_MARKER"; }
        public int addNumbers(int a, int b) { return a + b; }
        public int compute() { return addNumbers(2, 40); }
        public static void main(String[] a) { System.out.println(greeting()); }
    }

so the gate can assert androguard recovered *these* classes, methods, a
distinctive string, and the real call from ``compute`` to ``addNumbers``.

This covers the DEX-analysis tools only. The manifest-level tools (``apk.open``,
``apk.manifest``, ``apk.permissions``, ``apk.components``) parse binary AXML,
which needs the Android build tools to produce; that boundary is stated so a
green here is not read as "the whole APK surface is covered".

Skip != pass: the gate skips with a reason when androguard is absent and runs
for real when present. CI installs it, so a skip there is a genuine regression
rather than a bare machine.
"""

from __future__ import annotations

import base64
import zipfile
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient

_MARKER = "ANDROGUARD_DEX_MARKER"

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


def _quiet_androguard() -> None:
    # androguard logs every parsed map item at DEBUG through loguru; disabling
    # its namespace keeps the gate's output readable without touching handlers
    # other tests rely on.
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - logging quiet is best-effort
        pass


@pytest.mark.integration
def test_androguard_recovers_classes_methods_strings_xrefs(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — DEX analysis Gate not run (skip != pass)")
    _quiet_androguard()

    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", base64.b64decode(_DEX_B64))

    # classes: the one internal class is recovered; androguard's own external
    # classes (java.lang.Object) are filtered by the backend.
    classes = client.classes(apk)
    assert "Lcom/example/Widget;" in classes["classes"]

    # methods: the real methods of that class, by name.
    methods = client.methods(apk, "com.example.Widget")
    names = {m["name"] for m in methods["methods"]}
    assert {"greeting", "addNumbers", "compute"} <= names

    # strings: the distinctive literal embedded in greeting().
    strings = client.strings(apk)
    assert any(_MARKER in value for value in strings["strings"])

    # xrefs: real cross-reference analysis found that compute() calls
    # addNumbers() -- not merely an empty caller list.
    xrefs = client.xrefs(apk, "addNumbers")
    callers = {(c["class"], c["method"]) for c in xrefs["callers"]}
    assert ("Lcom/example/Widget;", "compute") in callers
