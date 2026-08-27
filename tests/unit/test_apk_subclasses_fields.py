"""apk.subclasses lists classes that extend or implement a given type."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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
        *,
        extends: str = "Ljava/lang/Object;",
        implements: list[str] | None = None,
        external: bool = False,
    ) -> None:
        self.name = name
        self.extends = extends
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


def test_subclasses_reports_extends_and_implements_relations() -> None:
    """A superclass match is 'extends'; an interface match is 'implements'.

    Searching for the framework Activity finds the two classes that extend it
    and none of the Runnable implementors.
    """
    classes = [
        _FakeClass("Lcom/example/MainActivity;", extends="Landroid/app/Activity;"),
        _FakeClass("Lcom/example/SettingsActivity;", extends="Landroid/app/Activity;"),
        _FakeClass(
            "Lcom/example/Worker;",
            extends="Ljava/lang/Object;",
            implements=["Ljava/lang/Runnable;"],
        ),
    ]
    payload = _client(classes).subclasses(Path("dummy.apk"), "android.app.Activity")
    assert payload["target"] == "Landroid/app/Activity;"
    assert payload["subclasses"] == [
        {"class_name": "Lcom/example/MainActivity;", "relation": "extends"},
        {"class_name": "Lcom/example/SettingsActivity;", "relation": "extends"},
    ]
    assert payload["total"] == 2


def test_subclasses_matches_interface_implementors() -> None:
    """The target is an interface, so matches come through implements."""
    classes = [
        _FakeClass(
            "Lcom/example/Task;",
            extends="Ljava/lang/Object;",
            implements=["Ljava/lang/Runnable;", "Ljava/io/Serializable;"],
        ),
        _FakeClass("Lcom/example/Other;", extends="Ljava/lang/Object;"),
    ]
    payload = _client(classes).subclasses(Path("dummy.apk"), "Ljava/lang/Runnable;")
    assert payload["subclasses"] == [
        {"class_name": "Lcom/example/Task;", "relation": "implements"},
    ]


def test_subclasses_accepts_smali_and_dotted_target() -> None:
    """Either target spelling resolves to the same smali name."""
    classes = [_FakeClass("Lcom/example/A;", extends="Lcom/base/Base;")]
    dotted = _client(classes).subclasses(Path("dummy.apk"), "com.base.Base")
    smali = _client(classes).subclasses(Path("dummy.apk"), "Lcom/base/Base;")
    assert dotted["subclasses"] == smali["subclasses"] == [
        {"class_name": "Lcom/example/A;", "relation": "extends"},
    ]


def test_subclasses_skips_external_and_unknown_target_is_empty() -> None:
    """External classes are skipped; an unmatched target is empty, not error."""
    classes = [
        _FakeClass("Landroid/app/Activity;", external=True),
        _FakeClass("Lcom/example/A;", extends="Ljava/lang/Object;"),
    ]
    payload = _client(classes).subclasses(Path("dummy.apk"), "Lcom/nowhere/Missing;")
    assert payload["subclasses"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_subclasses_paginates_sorted_rows() -> None:
    classes = [
        _FakeClass(f"Lcom/example/C{index:03d};", extends="Lcom/base/Base;")
        for index in range(5)
    ]
    payload = _client(classes).subclasses(Path("dummy.apk"), "Lcom/base/Base;", offset=1, limit=2)
    assert payload["offset"] == 1
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [row["class_name"] for row in payload["subclasses"]] == [
        "Lcom/example/C001;",
        "Lcom/example/C002;",
    ]


def test_subclasses_requires_class_name() -> None:
    client = _client([_FakeClass("Lcom/example/A;")])
    with pytest.raises(ApkError) as excinfo:
        client.subclasses(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_subclasses_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.subclasses")
    assert "target" in doc
    assert "relation" in doc
    assert "extends" in doc
    assert "implements" in doc
