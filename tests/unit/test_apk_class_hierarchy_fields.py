"""apk.class_hierarchy walks a class's superclass chain to its root."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import _MAX_HIERARCHY_DEPTH, ApkClient, ApkError
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
    def __init__(self, name: str, extends: str, *, external: bool = False) -> None:
        self.name = name
        self.extends = extends
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


def test_class_hierarchy_walks_internal_chain_and_stops_at_framework() -> None:
    """The walk follows APK-defined parents and stops at the first framework class.

    MainActivity -> AppCompatActivity (bundled, internal) -> Activity (framework,
    external), so Activity is the root and is not itself an APK class.
    """
    classes = [
        _FakeClass("Lcom/example/MainActivity;", "Landroidx/appcompat/AppCompatActivity;"),
        _FakeClass("Landroidx/appcompat/AppCompatActivity;", "Landroid/app/Activity;"),
        _FakeClass("Landroid/app/Activity;", "Ljava/lang/Object;", external=True),
    ]
    payload = _client(classes).class_hierarchy(Path("dummy.apk"), "com.example.MainActivity")
    assert payload["class_name"] == "Lcom/example/MainActivity;"
    assert payload["ancestors"] == [
        "Landroidx/appcompat/AppCompatActivity;",
        "Landroid/app/Activity;",
    ]
    assert payload["depth"] == 2
    assert payload["root"] == "Landroid/app/Activity;"
    assert payload["root_in_apk"] is False
    assert payload["truncated"] is False


def test_class_hierarchy_accepts_smali_form() -> None:
    classes = [
        _FakeClass("Lcom/example/A;", "Lcom/example/B;"),
        _FakeClass("Lcom/example/B;", "Ljava/lang/Object;", external=True),
    ]
    payload = _client(classes).class_hierarchy(Path("dummy.apk"), "Lcom/example/A;")
    assert payload["ancestors"] == ["Lcom/example/B;"]
    assert payload["root"] == "Lcom/example/B;"


def test_class_hierarchy_unknown_class_is_not_found() -> None:
    client = _client([_FakeClass("Lcom/example/A;", "Ljava/lang/Object;")])
    with pytest.raises(ApkError) as excinfo:
        client.class_hierarchy(Path("dummy.apk"), "Lcom/example/Missing;")
    assert excinfo.value.code == "not_found"


def test_class_hierarchy_external_only_target_is_not_found() -> None:
    """An external (only referenced) class has no known parentage here."""
    client = _client([_FakeClass("Landroid/app/Activity;", "Ljava/lang/Object;", external=True)])
    with pytest.raises(ApkError) as excinfo:
        client.class_hierarchy(Path("dummy.apk"), "Landroid/app/Activity;")
    assert excinfo.value.code == "not_found"


def test_class_hierarchy_cycle_terminates() -> None:
    """A malformed A->B->A cycle must not spin; the seen-guard stops it."""
    classes = [
        _FakeClass("Lcom/example/A;", "Lcom/example/B;"),
        _FakeClass("Lcom/example/B;", "Lcom/example/A;"),
    ]
    payload = _client(classes).class_hierarchy(Path("dummy.apk"), "Lcom/example/A;")
    assert payload["ancestors"] == ["Lcom/example/B;", "Lcom/example/A;"]
    assert payload["truncated"] is False


def test_class_hierarchy_caps_depth_and_flags_truncated() -> None:
    """A pathologically deep chain is capped at the guard and flagged."""
    depth = _MAX_HIERARCHY_DEPTH + 40
    classes = [
        _FakeClass(f"Lc/C{index:04d};", f"Lc/C{index + 1:04d};") for index in range(depth)
    ]
    payload = _client(classes).class_hierarchy(Path("dummy.apk"), "Lc/C0000;")
    assert payload["depth"] == _MAX_HIERARCHY_DEPTH
    assert payload["truncated"] is True


def test_class_hierarchy_requires_class_name() -> None:
    client = _client([_FakeClass("Lcom/example/A;", "Ljava/lang/Object;")])
    with pytest.raises(ApkError) as excinfo:
        client.class_hierarchy(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_class_hierarchy_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.class_hierarchy")
    assert "ancestors" in doc
    assert "root" in doc
    assert "depth" in doc
