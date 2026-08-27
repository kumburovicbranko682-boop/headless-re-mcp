"""apk.xrefs must count only callers of the app's OWN method of that exact name.

``apk.xrefs(method_name)`` walks ``analysis.get_methods()`` and, for each method,
skips it unless it is internal and its name matches exactly:
``if method.is_external() or method.name != target: continue``. Only the callers
of the surviving methods are returned. Both halves of that guard matter:

* ``is_external()`` -- androguard's analysis carries *external* method nodes
  (framework/library entry points the app references). An external method can
  share a name with the app's own (``onCreate``, ``run``, ``decrypt`` in an
  obfuscated app), and its ``get_xref_from`` are the framework-internal call
  sites, not answers to "who in this app calls our method". Counting them
  pollutes the result with references the operator did not ask about.
* ``name != target`` -- without it, ``get_xref_from`` would be gathered from
  *every* method in the DEX, so ``apk.xrefs("decrypt")`` would return the entire
  app's call graph rather than the callers of ``decrypt``.

Every existing xrefs test -- in ``test_apk_fields.py``, ``test_android_backends.py``
and ``test_apk_page_clamp.py`` -- drives a single, internal, exactly-matching
method (``_FakeMethod("decrypt", n)``, ``is_external`` hard-wired False). With one
matching method and nothing else present, neither ``continue`` branch ever fires:
delete the whole ``if`` and those suites still pass, because there is no external
node and no other-named node for the filter to have excluded. They pin the
pagination/`has_more` contract, not the selection.

These tests supply the heterogeneous method set the homogeneous fakes never do --
an external ``decrypt``, an internal ``decrypt``, and an internal ``other`` -- and
assert only the internal ``decrypt``'s callers come back, so dropping the
``is_external()`` check readmits the framework caller and dropping the name check
readmits ``other``'s caller. A second case pins that two internal overloads of the
same name both contribute, so the fix for the filter cannot over-correct into
"first match wins".
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient


class _Call:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _Method:
    def __init__(self, name: str, *, external: bool, callers: list[tuple[str, str]]) -> None:
        self.name = name
        self._external = external
        self._callers = callers

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[tuple[object, _Call, int]]:
        return [(None, _Call(cls, name), index) for index, (cls, name) in enumerate(self._callers)]


class _Parsed:
    def __init__(self, methods: list[_Method]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_Method]:
        return self._methods


def _client(monkeypatch: Any, methods: list[_Method]) -> ApkClient:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _Parsed(methods))
    return ApkClient()


def _pairs(payload: dict[str, Any]) -> set[tuple[str, str]]:
    return {(row["class"], row["method"]) for row in payload["callers"]}


def test_xrefs_skips_external_and_other_named_methods(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Only the internal, exactly-named method's callers are returned.

    The method set is deliberately heterogeneous and ordered so the wanted node
    is neither first nor last: an external ``decrypt`` (its caller must be
    excluded as a framework reference), an internal ``decrypt`` (the one node
    whose callers are the answer), and an internal ``other`` (excluded by name).
    Asserting the exact caller set proves both ``continue`` branches fire -- a
    dropped ``is_external()`` readmits ``Lframework/Sys;`` and a dropped name
    check readmits ``Lapp/Other;``.
    """
    methods = [
        _Method("decrypt", external=True, callers=[("Lframework/Sys;", "call")]),
        _Method("decrypt", external=False, callers=[("Lapp/Real;", "onCreate")]),
        _Method("other", external=False, callers=[("Lapp/Other;", "run")]),
    ]
    payload = _client(monkeypatch, methods).xrefs(tmp_path / "app.apk", "decrypt", limit=100)

    assert _pairs(payload) == {("Lapp/Real;", "onCreate")}
    assert payload["count"] == 1
    assert payload["method_name"] == "decrypt"
    # The excluded nodes' callers must be absent, not merely outnumbered.
    assert ("Lframework/Sys;", "call") not in _pairs(payload)
    assert ("Lapp/Other;", "run") not in _pairs(payload)


def test_xrefs_accumulates_callers_across_internal_overloads_of_the_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """Two internal methods sharing the name both contribute -- not first-wins.

    An obfuscated app routinely has overloads (``decrypt(String)`` /
    ``decrypt(byte[])``) that androguard exposes as distinct method nodes of the
    same name. The loop must gather callers from every internal match, so a fix
    that tightened the filter into "stop at the first matching method" is caught
    here while the external/other-named exclusions above still hold.
    """
    methods = [
        _Method("decrypt", external=False, callers=[("Lapp/A;", "one")]),
        _Method("decrypt", external=False, callers=[("Lapp/B;", "two")]),
        _Method("decrypt", external=True, callers=[("Lframework/Sys;", "call")]),
    ]
    payload = _client(monkeypatch, methods).xrefs(tmp_path / "app.apk", "decrypt", limit=100)

    assert _pairs(payload) == {("Lapp/A;", "one"), ("Lapp/B;", "two")}
    assert payload["count"] == 2
    assert ("Lframework/Sys;", "call") not in _pairs(payload)


def test_xrefs_with_only_an_external_match_returns_no_callers(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """If the sole method of that name is external, the answer is empty, not its refs.

    This isolates the ``is_external()`` half: there is nothing else to match, so a
    non-empty result could only come from counting the external node's callers --
    exactly what a dropped external check would do.
    """
    methods = [
        _Method("decrypt", external=True, callers=[("Lframework/Sys;", "call")]),
    ]
    payload = _client(monkeypatch, methods).xrefs(tmp_path / "app.apk", "decrypt", limit=100)

    assert payload["callers"] == []
    assert payload["count"] == 0
    assert payload["has_more"] is False
