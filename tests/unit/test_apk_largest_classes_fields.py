"""apk.largest_classes ranks internal classes by method and field count."""

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
        num_methods: int,
        num_fields: int = 0,
        *,
        external: bool = False,
    ) -> None:
        self.name = name
        self._num_methods = num_methods
        self._num_fields = num_fields
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_nb_methods(self) -> int:
        return self._num_methods

    def get_fields(self) -> list[object]:
        return [object() for _ in range(self._num_fields)]


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


def test_largest_classes_ranks_by_method_count_descending() -> None:
    """The heaviest class leads regardless of declaration or name order."""
    classes = [
        _FakeClass("Lcom/example/Small;", 2, 1),
        _FakeClass("Lcom/example/God;", 300, 40),
        _FakeClass("Lcom/example/Mid;", 50, 10),
    ]
    payload = _client(classes).largest_classes(Path("dummy.apk"))
    assert [row["class_name"] for row in payload["classes"]] == [
        "Lcom/example/God;",
        "Lcom/example/Mid;",
        "Lcom/example/Small;",
    ]
    assert payload["classes"][0] == {
        "class_name": "Lcom/example/God;",
        "num_methods": 300,
        "num_fields": 40,
    }
    assert payload["total"] == 3


def test_largest_classes_tie_breaks_on_fields_then_name() -> None:
    """Equal method counts fall back to field count, then class name."""
    classes = [
        _FakeClass("Lz/A;", 10, 5),
        _FakeClass("La/A;", 10, 5),
        _FakeClass("Lm/A;", 10, 9),
    ]
    payload = _client(classes).largest_classes(Path("dummy.apk"))
    assert [row["class_name"] for row in payload["classes"]] == ["Lm/A;", "La/A;", "Lz/A;"]


def test_largest_classes_skips_external() -> None:
    classes = [
        _FakeClass("Landroid/app/Activity;", 999, external=True),
        _FakeClass("Lcom/example/A;", 3),
    ]
    payload = _client(classes).largest_classes(Path("dummy.apk"))
    assert [row["class_name"] for row in payload["classes"]] == ["Lcom/example/A;"]
    assert payload["total"] == 1


def test_largest_classes_paginates() -> None:
    classes = [_FakeClass(f"Lc/C{index:03d};", 100 - index) for index in range(5)]
    payload = _client(classes).largest_classes(Path("dummy.apk"), offset=1, limit=2)
    assert payload["offset"] == 1
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [row["class_name"] for row in payload["classes"]] == ["Lc/C001;", "Lc/C002;"]


def test_largest_classes_empty() -> None:
    payload = _client([]).largest_classes(Path("dummy.apk"))
    assert payload["classes"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_largest_classes_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.largest_classes")
    assert "num_methods" in doc
    assert "num_fields" in doc
    assert "Answers with classes" in doc
