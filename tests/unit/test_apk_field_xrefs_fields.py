"""apk.field_xrefs lists read/write access sites of a named field.

The fake parsed APK stands in for androguard's analysis.get_fields plus each
FieldAnalysis's get_field()/get_xref_read()/get_xref_write(), matching the real
4.x shape: xref tuples are (ClassAnalysis, MethodAnalysis) and the accessing
method exposes class_name / name. That exercises the read/write labelling,
de-duplication, sorting, matched flag, cap and error path.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import _MAX_XREFS_PAGE, ApkClient, ApkError
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


class _FakeMethodAnalysis:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeEncodedField:
    def __init__(self, name: str) -> None:
        self._name = name

    def get_name(self) -> str:
        return self._name


class _FakeFieldAnalysis:
    def __init__(
        self,
        name: str,
        reads: list[_FakeMethodAnalysis],
        writes: list[_FakeMethodAnalysis],
    ) -> None:
        self._field = _FakeEncodedField(name)
        self._reads = reads
        self._writes = writes

    def get_field(self) -> _FakeEncodedField:
        return self._field

    def get_xref_read(self) -> set[tuple[object, _FakeMethodAnalysis]]:
        return {(object(), m) for m in self._reads}

    def get_xref_write(self) -> set[tuple[object, _FakeMethodAnalysis]]:
        return {(object(), m) for m in self._writes}


class _FakeParsed:
    def __init__(self, fields: list[_FakeFieldAnalysis]) -> None:
        self.analysis = self
        self._fields = fields

    def get_fields(self) -> list[_FakeFieldAnalysis]:
        return self._fields


def _client(fields: list[_FakeFieldAnalysis]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(fields)  # type: ignore[method-assign]
    return client


def test_labels_reads_and_writes_deduped_and_sorted() -> None:
    """Read and write sites are tagged, deduped and sorted; counts split.

    Measured: a field read by two methods and written by one yields three rows
    with the right access labels, reads=2, writes=1, matched True.
    """
    field = _FakeFieldAnalysis(
        "API_KEY",
        reads=[
            _FakeMethodAnalysis("La;", "load"),
            _FakeMethodAnalysis("Lb;", "init"),
        ],
        writes=[_FakeMethodAnalysis("Lb;", "init")],
    )
    payload = _client([field]).field_xrefs(Path("dummy.apk"), "API_KEY")
    assert payload["accesses"] == [
        {"access": "read", "class": "La;", "method": "load"},
        {"access": "read", "class": "Lb;", "method": "init"},
        {"access": "write", "class": "Lb;", "method": "init"},
    ]
    assert payload["reads"] == 2
    assert payload["writes"] == 1
    assert payload["count"] == 3
    assert payload["matched"] is True
    assert payload["has_more"] is False


def test_unions_fields_sharing_a_name() -> None:
    """Two fields with the same name across classes both contribute."""
    f1 = _FakeFieldAnalysis("TAG", reads=[_FakeMethodAnalysis("La;", "x")], writes=[])
    f2 = _FakeFieldAnalysis("TAG", reads=[_FakeMethodAnalysis("Lb;", "y")], writes=[])
    payload = _client([f1, f2]).field_xrefs(Path("dummy.apk"), "TAG")
    assert payload["reads"] == 2
    assert payload["matched"] is True


def test_matched_false_when_no_such_field() -> None:
    payload = _client(
        [_FakeFieldAnalysis("other", reads=[_FakeMethodAnalysis("La;", "x")], writes=[])]
    ).field_xrefs(Path("dummy.apk"), "missing")
    assert payload["matched"] is False
    assert payload["accesses"] == []
    assert payload["count"] == 0


def test_matched_true_but_untouched_field() -> None:
    payload = _client([_FakeFieldAnalysis("dead", reads=[], writes=[])]).field_xrefs(
        Path("dummy.apk"), "dead"
    )
    assert payload["matched"] is True
    assert payload["accesses"] == []


def test_caps_and_flags_has_more() -> None:
    reads = [_FakeMethodAnalysis(f"L{i:04d};", "m") for i in range(_MAX_XREFS_PAGE + 5)]
    payload = _client([_FakeFieldAnalysis("big", reads=reads, writes=[])]).field_xrefs(
        Path("dummy.apk"), "big", limit=10
    )
    assert payload["count"] == 10
    assert payload["has_more"] is True


def test_requires_a_field_name() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client([]).field_xrefs(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_field_xrefs_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.field_xrefs")
    assert "Answers" in doc
    assert "read" in doc and "write" in doc
    assert "matched" in doc
