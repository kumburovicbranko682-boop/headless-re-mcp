"""apk.classes must sort before applying the collection cap.

Capping the DEX-iteration order first and only then sorting returned an
arbitrary slice of classes shown sorted: an app with more classes than the cap
silently dropped alphabetically-early classes that sat past the cap in DEX
order, so a caller paging the "sorted" list walked an alphabetical range that
was actually missing entries. Sorting before the cap keeps the
alphabetically-first classes, making pagination a true alphabetical walk.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import headless_re_mcp.backends.apk.client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


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


class _FakeClass:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_external(self) -> bool:
        return False


class _FakeParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def _client_with(names: list[str]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(  # type: ignore[method-assign,return-value]
        [_FakeClass(name) for name in names]
    )
    return client


def test_classes_over_the_cap_keeps_the_alphabetically_first(monkeypatch: Any) -> None:
    """The cap must keep the alphabetically-first classes, not a DEX-order slice."""
    # DEX order puts the alphabetically-latest names first, so a cap applied
    # before sorting would keep z/y/x and drop a/b -- the bug this pins.
    dex_order = ["Lz;", "Ly;", "Lx;", "Lb;", "La;"]
    monkeypatch.setattr(apk_client, "_MAX_CLASSES_COLLECT", 3)
    payload = _client_with(dex_order).classes(Path("app.apk"), offset=0, limit=100)

    assert payload["scan_capped"] is True
    assert payload["total"] == 3
    # a/b appear LAST in DEX order yet must survive the cap; z (alphabetically
    # last) must be dropped. The old sort-after-cap would have returned x/y/z.
    assert payload["classes"] == ["La;", "Lb;", "Lx;"]
    assert "Lz;" not in payload["classes"]


def test_classes_under_the_cap_are_all_returned_sorted(monkeypatch: Any) -> None:
    """Under the cap, every class comes back sorted -- no behavior regression."""
    monkeypatch.setattr(apk_client, "_MAX_CLASSES_COLLECT", 100)
    payload = _client_with(["Lc;", "La;", "Lb;"]).classes(Path("app.apk"), offset=0, limit=100)
    assert payload["scan_capped"] is False
    assert payload["total"] == 3
    assert payload["classes"] == ["La;", "Lb;", "Lc;"]


def test_classes_docstring_states_sort_before_cap() -> None:
    """The description must say the cap keeps the alphabetically-first classes."""
    doc = _tool_docstring("apk.classes")
    assert "alphabetically-first" in doc
    assert "sorted before the cap" in doc
