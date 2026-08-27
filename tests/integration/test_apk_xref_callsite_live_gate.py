"""apk.xrefs live gate: each caller carries the real call-site offset.

androguard's ``MethodAnalysis.get_xref_from()`` yields
``(ClassAnalysis, MethodAnalysis, int)`` where the third element is the offset,
in 16-bit code units, of the invoke instruction *inside the caller* -- the same
figure ``show_xrefs``, baksmali and jadx print so a reverse engineer can jump to
the exact call site. The backend used to iterate ``for _, call, _`` and throw
that offset away, so a caller that invoked the target more than once produced
several records identical in class+method (phantom duplicates) and nothing said
where any call was. Every apk.xrefs unit test fakes the parser, so only real
androguard proves the offset the tuple carries is surfaced faithfully.

The DEX is embedded (compiled once with javac + Android's D8, the same bytecode
the descriptor gate uses), so the gate depends only on androguard -- no Android
SDK, no emulator. The source class is::

    package com.example;
    public class Widget {
        public static String greeting() { return "ANDROGUARD_DEX_MARKER"; }
        public int addNumbers(int a, int b) { return a + b; }
        public int compute() { return addNumbers(2, 40); }
        public static void main(String[] a) { System.out.println(greeting()); }
    }

so ``compute`` calls ``addNumbers`` and ``main`` calls ``greeting`` -- two known
xrefs with known call sites. The gate first reads the offset androguard itself
reports for the ``compute`` -> ``addNumbers`` edge (guarding the guard: a real,
non-negative int, else the test would prove nothing), then pins that apk.xrefs
returned that same offset on the ``compute`` caller record.

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


def _quiet_androguard() -> None:
    try:
        from loguru import logger

        logger.disable("androguard")
    except Exception:  # noqa: BLE001 - logging quiet is best-effort
        pass


def _raw_xref(apk: Path, target: str) -> tuple[str, str, int]:
    """The (caller class, caller method, offset) androguard reports for one edge.

    Reads the first xref-from ``target`` straight off androguard, before the
    backend touches it, so the gate can pin the backend against the library's
    own numbers rather than a hardcoded constant.
    """
    from androguard.misc import AnalyzeAPK

    _, _, dx = AnalyzeAPK(str(apk))
    for method in dx.get_methods():
        if method.is_external() or method.name != target:
            continue
        for _classobj, call, offset in method.get_xref_from():
            return str(call.class_name), str(call.name), int(offset)
    raise AssertionError(f"no xref-from found for {target!r} in the fixture DEX")


@pytest.mark.integration
def test_apk_xrefs_surface_real_call_site_offset(tmp_path: Path) -> None:
    client = ApkClient()
    if not client.available:
        pytest.skip("androguard not installed — xref-callsite Gate not run (skip != pass)")
    _quiet_androguard()

    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", base64.b64decode(_DEX_B64))

    # Guard the guard: androguard must really report a real, non-negative call
    # offset for compute -> addNumbers, or the assertion below proves nothing.
    raw_class, raw_method, raw_offset = _raw_xref(apk, "addNumbers")
    assert raw_class == _CLASS_SMALI
    assert raw_method == "compute"
    assert isinstance(raw_offset, int) and raw_offset >= 0

    payload = client.xrefs(apk, "addNumbers")
    assert payload["method_name"] == "addNumbers"
    callers = payload["callers"]
    assert callers, "compute should show up as a caller of addNumbers"

    caller = callers[0]
    assert caller["class"] == _CLASS_SMALI
    assert caller["method"] == "compute"
    # The load-bearing part: the surfaced offset is exactly androguard's, not a
    # dropped-then-defaulted 0, and never the -1 the helper uses for "absent".
    assert caller["offset"] == raw_offset
    assert caller["offset"] >= 0

    # The other known edge resolves too: main calls greeting.
    greeting = client.xrefs(apk, "greeting")["callers"]
    assert any(
        c["class"] == _CLASS_SMALI and c["method"] == "main" and c["offset"] >= 0
        for c in greeting
    ), greeting
