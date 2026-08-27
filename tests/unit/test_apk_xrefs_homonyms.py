"""apk.xrefs must disclose when a bare name matched several distinct methods.

``method_name`` is a bare name, so ``get_methods()`` can return several methods
that share it -- overloads with different descriptors, or same-named methods in
different classes -- and ``xrefs`` walks every one, merging their callers into a
single list. The reply used to name only the callers, so a caller reading
"xrefs of decrypt" could not tell a list belonging to one method from one that
silently merged the callers of a dozen methods called ``decrypt``. These lock
in that ``matched_methods`` reports how many methods the name hit, that
``matched`` lists their identities (bounded), and that the caller list itself is
unchanged.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


class _FakeCall:
    def __init__(self, class_name: str, name: str = "invoke") -> None:
        self.class_name = class_name
        self.name = name


class _FakeMethod:
    def __init__(
        self, name: str, class_name: str, descriptor: str, caller_classes: list[str]
    ) -> None:
        self.name = name
        self.class_name = class_name
        self.descriptor = descriptor
        self._callers = caller_classes

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(cls), index) for index, cls in enumerate(self._callers)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            for keyword in decorator.keywords:
                if (
                    keyword.arg == "name"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value == name
                ):
                    return ast.get_docstring(node) or ""
    return ""


def test_apk_xrefs_discloses_several_methods_sharing_the_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    methods = [
        _FakeMethod("decrypt", "Lcom/a/A;", "(I)V", ["Lcom/x/One;", "Lcom/x/Two;"]),
        _FakeMethod("decrypt", "Lcom/b/B;", "()V", ["Lcom/y/Three;"]),
    ]
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeParsed(methods))
    client = ApkClient()

    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=100)

    assert payload["matched_methods"] == 2
    assert payload["matched"] == [
        {"class": "Lcom/a/A;", "descriptor": "(I)V"},
        {"class": "Lcom/b/B;", "descriptor": "()V"},
    ]
    # The callers of both methods are merged into one list, in method order.
    assert [c["class"] for c in payload["callers"]] == [
        "Lcom/x/One;",
        "Lcom/x/Two;",
        "Lcom/y/Three;",
    ]
    assert payload["count"] == 3
    assert payload["has_more"] is False


def test_apk_xrefs_reports_one_match_for_a_unique_name(
    tmp_path: Path, monkeypatch: Any
) -> None:
    methods = [_FakeMethod("solo", "Lcom/a/A;", "()V", ["Lcom/x/One;"])]
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeParsed(methods))
    client = ApkClient()

    payload = client.xrefs(tmp_path / "app.apk", "solo", limit=100)

    assert payload["matched_methods"] == 1
    assert payload["matched"] == [{"class": "Lcom/a/A;", "descriptor": "()V"}]


def test_apk_xrefs_counts_all_matches_even_when_the_page_is_full(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # First method alone fills the page; matched_methods must still count the
    # second, so the disclosure is not truncated by pagination.
    methods = [
        _FakeMethod("hit", "Lcom/a/A;", "(I)V", ["Lcom/x/One;", "Lcom/x/Two;"]),
        _FakeMethod("hit", "Lcom/b/B;", "()V", ["Lcom/y/Three;"]),
    ]
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeParsed(methods))
    client = ApkClient()

    payload = client.xrefs(tmp_path / "app.apk", "hit", limit=1)

    assert payload["count"] == 1
    assert payload["has_more"] is True
    assert payload["matched_methods"] == 2
    assert len(payload["matched"]) == 2


def test_apk_xrefs_matched_list_is_bounded_while_count_stays_true(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_XREFS_MATCHED", 3)
    methods = [
        _FakeMethod("wide", f"Lcom/p{index}/C;", "()V", ["Lcom/x/One;"])
        for index in range(6)
    ]
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeParsed(methods))
    client = ApkClient()

    payload = client.xrefs(tmp_path / "app.apk", "wide", limit=100)

    assert payload["matched_methods"] == 6
    assert len(payload["matched"]) == 3


def test_docstring_names_the_matched_fields() -> None:
    doc = " ".join(_tool_docstring("apk.xrefs").split())
    assert "matched_methods" in doc
    assert "matched lists their class and descriptor" in doc
