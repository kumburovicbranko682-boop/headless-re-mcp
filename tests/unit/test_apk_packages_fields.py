"""apk.packages groups internal classes by Java package and counts each."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _smali_package
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
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
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


def test_smali_package_derivation() -> None:
    assert _smali_package("Lcom/example/Foo;") == "com.example"
    assert _smali_package("Lcom/example/Foo$Bar;") == "com.example"
    assert _smali_package("LFoo;") == ""
    assert _smali_package("Lcom/a/b/c/Deep;") == "com.a.b.c"


def test_packages_counts_and_sorts_by_weight() -> None:
    """Heaviest package leads; ties break by package name.

    com.example has three classes, com.google.ads two, com.google.gson one,
    so the order is example (3), ads (2), gson (1).
    """
    classes = [
        _FakeClass("Lcom/example/A;"),
        _FakeClass("Lcom/example/B;"),
        _FakeClass("Lcom/example/C;"),
        _FakeClass("Lcom/google/ads/X;"),
        _FakeClass("Lcom/google/ads/Y;"),
        _FakeClass("Lcom/google/gson/Z;"),
    ]
    payload = _client(classes).packages(Path("dummy.apk"))
    assert payload["packages"] == [
        {"package": "com.example", "class_count": 3},
        {"package": "com.google.ads", "class_count": 2},
        {"package": "com.google.gson", "class_count": 1},
    ]
    assert payload["total"] == 3
    assert payload["total_classes"] == 6


def test_packages_skips_external_and_handles_default_package() -> None:
    classes = [
        _FakeClass("Landroid/app/Activity;", external=True),
        _FakeClass("LTopLevel;"),
        _FakeClass("Lcom/example/A;"),
    ]
    payload = _client(classes).packages(Path("dummy.apk"))
    packages = {row["package"]: row["class_count"] for row in payload["packages"]}
    assert packages == {"": 1, "com.example": 1}
    assert payload["total_classes"] == 2


def test_packages_nested_classes_keep_outer_package() -> None:
    classes = [
        _FakeClass("Lcom/example/Outer$Inner;"),
        _FakeClass("Lcom/example/Outer$Inner$Deeper;"),
    ]
    payload = _client(classes).packages(Path("dummy.apk"))
    assert payload["packages"] == [{"package": "com.example", "class_count": 2}]


def test_packages_ties_sort_by_name() -> None:
    """Equal counts fall back to package name order for stable pagination."""
    classes = [
        _FakeClass("Lz/pkg/A;"),
        _FakeClass("La/pkg/A;"),
        _FakeClass("Lm/pkg/A;"),
    ]
    payload = _client(classes).packages(Path("dummy.apk"))
    assert [row["package"] for row in payload["packages"]] == ["a.pkg", "m.pkg", "z.pkg"]


def test_packages_paginates() -> None:
    classes = [_FakeClass(f"Lp{index:03d}/C;") for index in range(5)]
    payload = _client(classes).packages(Path("dummy.apk"), offset=2, limit=2)
    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_packages_empty() -> None:
    payload = _client([]).packages(Path("dummy.apk"))
    assert payload["packages"] == []
    assert payload["total"] == 0
    assert payload["total_classes"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_packages_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.packages")
    assert "packages" in doc
    assert "class_count" in doc
    assert "total_classes" in doc
