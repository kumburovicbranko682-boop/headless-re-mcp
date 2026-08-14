"""apk tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import _MAX_MANIFEST_CHARS, ApkClient
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


class _FakeCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _FakeMethod:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callers)]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


def test_apk_xrefs_puts_the_list_in_callers_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said xrefs-from and never named the payload.

    Measured: 25 callers, limit 10 -> count 10, has_more True, field is
    callers not xrefs. Looking for xrefs after a successful call reads as
    no callers, and a full page with no has_more reads as the whole list.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed([_FakeMethod("decrypt", 25)]),
    )
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10)
    assert "xrefs" not in payload
    assert payload["count"] == 10
    assert len(payload["callers"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.xrefs")
    assert "Answers with callers" in doc
    assert "has_more" in doc


class _ManifestBody:
    def get_xml(self) -> bytes:
        return b"<manifest/>" * ((_MAX_MANIFEST_CHARS // 10) + 20)


class _FakeApk:
    def get_android_manifest_axml(self) -> _ManifestBody:
        return _ManifestBody()

    def get_package(self) -> str:
        return "com.example.app"


def test_apk_manifest_names_manifest_xml_and_says_when_it_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said AndroidManifest.xml and never named the payload.

    Measured: truncated True, manifest_xml 200000 chars (the cap), no
    manifest or xml field. Looking for those after a successful call reads
    as a missing manifest, and a 200000-char string with no truncated flag
    reads as the whole file.
    """
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_apk", lambda self, path: _FakeApk())
    payload = client.manifest(tmp_path / "app.apk")
    assert "manifest" not in payload
    assert "xml" not in payload
    assert payload["truncated"] is True
    assert payload["package"] == "com.example.app"
    assert len(payload["manifest_xml"]) == _MAX_MANIFEST_CHARS
    doc = _tool_docstring("apk.manifest")
    assert "manifest_xml" in doc
    assert "truncated" in doc

class _FakeClass:
    def __init__(self, name: str, *, external: bool = False) -> None:
        self.name = name
        self._external = external

    def is_external(self) -> bool:
        return self._external


class _FakeClassParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def test_apk_classes_puts_the_list_in_classes_and_says_when_it_stopped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog said pagination and never named the payload.

    Measured: 25 classes, limit 10 -> count 10, total 25, has_more True,
    field is classes not class_list or items. Looking for those after a
    successful call reads as no classes, and a full page with no has_more
    reads as the whole DEX.
    """
    client = ApkClient()
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeClassParsed(
            [_FakeClass(f"L{index};") for index in range(25)]
        ),
    )
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=10)
    assert "class_list" not in payload
    assert "items" not in payload
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert len(payload["classes"]) == 10
    assert payload["has_more"] is True
    doc = _tool_docstring("apk.classes")
    assert "Answers with classes" in doc
    assert "has_more" in doc
