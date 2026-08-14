"""apk tool descriptions must name the fields the backends return."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

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
