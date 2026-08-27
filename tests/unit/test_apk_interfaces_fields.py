"""apk.interfaces censuses implemented interfaces, ranked by implementor count."""

from __future__ import annotations

import ast
from pathlib import Path

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
    def __init__(
        self,
        name: str,
        implements: list[str] | None = None,
        *,
        external: bool = False,
    ) -> None:
        self.name = name
        self.implements = implements or []
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _FakeParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return list(self._classes)


def _client(classes: list[_FakeClass]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(classes)  # type: ignore[method-assign, assignment, return-value]
    return client


def test_interfaces_counts_implementors_and_ranks_by_use() -> None:
    """The most-implemented interface leads; a class contributes to each of its.

    Runnable is implemented by three classes, Serializable by two, the custom
    Callback by one, so the order is Runnable, Serializable, Callback.
    """
    classes = [
        _FakeClass("Lcom/example/A;", ["Ljava/lang/Runnable;", "Ljava/io/Serializable;"]),
        _FakeClass("Lcom/example/B;", ["Ljava/lang/Runnable;"]),
        _FakeClass("Lcom/example/C;", ["Ljava/lang/Runnable;", "Ljava/io/Serializable;"]),
        _FakeClass("Lcom/example/D;", ["Lcom/example/Callback;"]),
    ]
    payload = _client(classes).interfaces(Path("dummy.apk"))
    assert payload["interfaces"] == [
        {"interface": "Ljava/lang/Runnable;", "implementor_count": 3},
        {"interface": "Ljava/io/Serializable;", "implementor_count": 2},
        {"interface": "Lcom/example/Callback;", "implementor_count": 1},
    ]
    assert payload["total"] == 3
    assert payload["classes_scanned"] == 4


def test_interfaces_ties_sort_by_name() -> None:
    """Equal counts fall back to interface name for stable pagination."""
    classes = [
        _FakeClass("Lc/A;", ["Lz/I;"]),
        _FakeClass("Lc/B;", ["La/I;"]),
        _FakeClass("Lc/C;", ["Lm/I;"]),
    ]
    payload = _client(classes).interfaces(Path("dummy.apk"))
    assert [row["interface"] for row in payload["interfaces"]] == ["La/I;", "Lm/I;", "Lz/I;"]


def test_interfaces_skips_external_and_no_interface_classes() -> None:
    classes = [
        _FakeClass("Landroid/Api;", ["Ljava/lang/Runnable;"], external=True),
        _FakeClass("Lcom/example/Plain;", []),
        _FakeClass("Lcom/example/Impl;", ["Ljava/lang/Runnable;"]),
    ]
    payload = _client(classes).interfaces(Path("dummy.apk"))
    assert payload["interfaces"] == [
        {"interface": "Ljava/lang/Runnable;", "implementor_count": 1},
    ]
    assert payload["classes_scanned"] == 2


def test_interfaces_paginates() -> None:
    classes = [_FakeClass(f"Lc/C{index:03d};", [f"Li/I{index:03d};"]) for index in range(5)]
    payload = _client(classes).interfaces(Path("dummy.apk"), offset=2, limit=2)
    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_interfaces_empty() -> None:
    payload = _client([]).interfaces(Path("dummy.apk"))
    assert payload["interfaces"] == []
    assert payload["total"] == 0
    assert payload["classes_scanned"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_interfaces_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.interfaces")
    assert "interfaces" in doc
    assert "implementor_count" in doc
    assert "classes_scanned" in doc
