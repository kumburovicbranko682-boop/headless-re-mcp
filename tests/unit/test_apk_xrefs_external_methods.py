"""apk.xrefs must list callers of framework/library (external) methods too.

The tool documents itself as listing callers of *every* method named
method_name, but the implementation skipped ``method.is_external()`` -- so a
query for a framework API (``Cipher.doFinal``, ``Runtime.exec``,
``URL.openConnection``) matched no method and returned an empty caller list,
which for a reverse-engineering tool is the single most common thing to ask.
In androguard the target of such a query is an *external* MethodAnalysis whose
``get_xref_from()`` is exactly the set of in-app call sites, so including
external methods is what makes the contract hold.

These use fake analysis objects (building a real APK with both app-defined and
framework methods needs a full Android toolchain); each asserts callers that
the old ``is_external()`` skip would have dropped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient


class _Caller:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _Method:
    def __init__(self, name: str, *, external: bool, callers: list[_Caller]) -> None:
        self.name = name
        self._external = external
        self._callers = callers

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, _Caller, int]]:
        return [(None, caller, index) for index, caller in enumerate(self._callers)]


class _Analysis:
    def __init__(self, methods: list[_Method]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_Method]:
        return self._methods


def test_xrefs_lists_callers_of_an_external_framework_method(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """A framework API target (is_external True) must surface its in-app callers."""
    external = _Method(
        "doFinal",
        external=True,
        callers=[_Caller("Lcom/app/Crypto;", "encrypt"), _Caller("Lcom/app/Net;", "send")],
    )
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Analysis([external]))
    client = ApkClient()

    payload = client.xrefs(tmp_path / "app.apk", "doFinal")

    assert payload["count"] == 2
    assert {caller["class"] for caller in payload["callers"]} == {
        "Lcom/app/Crypto;",
        "Lcom/app/Net;",
    }


def test_xrefs_merges_internal_and_external_methods_of_that_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # "Every method named X" must mean both the app-defined and the framework one.
    internal = _Method("run", external=False, callers=[_Caller("Lcom/app/A;", "a")])
    external = _Method("run", external=True, callers=[_Caller("Lcom/app/B;", "b")])
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Analysis([internal, external]))
    client = ApkClient()

    payload = client.xrefs(tmp_path / "app.apk", "run")

    assert {caller["class"] for caller in payload["callers"]} == {"Lcom/app/A;", "Lcom/app/B;"}
