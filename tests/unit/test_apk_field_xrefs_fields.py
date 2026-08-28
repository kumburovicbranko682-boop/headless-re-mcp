"""apk.field_xrefs must return the read/write access edges it promises.

This names a field and reports the methods that read or write it, via
androguard's FieldAnalysis.get_xref_read / get_xref_write (each yields
(class, method) pairs whose method is a MethodAnalysis carrying class_name/name,
the same shape the other xref tools read). Field names collide across classes,
so the test fakes two same-named fields in different classes and pins: name
matching aggregates across the module, every row carries the declaring
field_class and a read/write kind, matched_fields counts the distinct fields,
found separates an unaccessed field from an absent one, and has_more only trips
when the page dropped a row. No real DEX or JRE is needed.
"""

from __future__ import annotations

import ast
from pathlib import Path

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


class _FakeMethod:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeEncodedField:
    def __init__(self, class_name: str) -> None:
        self._class_name = class_name

    def get_class_name(self) -> str:
        return self._class_name


class _FakeField:
    def __init__(
        self,
        name: str,
        class_name: str,
        *,
        readers: list[_FakeMethod],
        writers: list[_FakeMethod],
    ) -> None:
        self.name = name
        self._encoded = _FakeEncodedField(class_name)
        self._readers = readers
        self._writers = writers

    def get_field(self) -> _FakeEncodedField:
        return self._encoded

    def get_xref_read(self) -> list[tuple[object, _FakeMethod]]:
        return [(None, m) for m in self._readers]

    def get_xref_write(self) -> list[tuple[object, _FakeMethod]]:
        return [(None, m) for m in self._writers]


class _FakeParsed:
    def __init__(self, fields: list[_FakeField]) -> None:
        self.analysis = self
        self._fields = fields

    def get_fields(self) -> list[_FakeField]:
        return self._fields


def _client(fields: list[_FakeField]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(fields)  # type: ignore[method-assign]
    return client


def test_field_xrefs_reports_reads_and_writes_with_kind() -> None:
    fields = [
        _FakeField(
            "sToken",
            "Lcom/app/Auth;",
            readers=[_FakeMethod("Lcom/app/Net;", "send")],
            writers=[_FakeMethod("Lcom/app/Auth;", "login")],
        ),
        _FakeField(
            "other", "Lcom/app/X;", readers=[_FakeMethod("Y", "z")], writers=[]
        ),
    ]
    payload = _client(fields).field_xrefs(Path("dummy.apk"), "sToken", limit=100)

    assert payload["field_name"] == "sToken"
    assert payload["found"] is True
    assert payload["matched_fields"] == 1
    assert "callers" not in payload
    assert "callees" not in payload
    assert payload["accesses"] == [
        {
            "class": "Lcom/app/Net;",
            "method": "send",
            "kind": "read",
            "field_class": "Lcom/app/Auth;",
        },
        {
            "class": "Lcom/app/Auth;",
            "method": "login",
            "kind": "write",
            "field_class": "Lcom/app/Auth;",
        },
    ]
    assert payload["count"] == 2
    assert payload["has_more"] is False


def test_same_named_fields_in_different_classes_are_aggregated() -> None:
    fields = [
        _FakeField(
            "TAG",
            "Lcom/app/A;",
            readers=[_FakeMethod("Lcom/app/A;", "onCreate")],
            writers=[],
        ),
        _FakeField(
            "TAG",
            "Lcom/app/B;",
            readers=[_FakeMethod("Lcom/app/B;", "run")],
            writers=[],
        ),
    ]
    payload = _client(fields).field_xrefs(Path("dummy.apk"), "TAG")
    assert payload["matched_fields"] == 2
    assert payload["count"] == 2
    field_classes = {row["field_class"] for row in payload["accesses"]}
    assert field_classes == {"Lcom/app/A;", "Lcom/app/B;"}


def test_field_present_but_unaccessed_is_found_with_no_accesses() -> None:
    fields = [_FakeField("dead", "Lcom/app/A;", readers=[], writers=[])]
    payload = _client(fields).field_xrefs(Path("dummy.apk"), "dead")
    assert payload["found"] is True
    assert payload["matched_fields"] == 1
    assert payload["accesses"] == []
    assert payload["count"] == 0


def test_absent_field_reports_found_false() -> None:
    fields = [_FakeField("something", "Lcom/app/A;", readers=[], writers=[])]
    payload = _client(fields).field_xrefs(Path("dummy.apk"), "missing")
    assert payload["found"] is False
    assert payload["matched_fields"] == 0
    assert payload["accesses"] == []


def test_has_more_trips_only_when_a_row_is_dropped() -> None:
    readers = [_FakeMethod(f"L{i};", f"m{i}") for i in range(5)]
    fields = [_FakeField("hot", "Lcom/app/A;", readers=readers, writers=[])]

    full = _client(fields).field_xrefs(Path("dummy.apk"), "hot", limit=5)
    assert full["count"] == 5
    assert full["has_more"] is False

    clipped = _client(fields).field_xrefs(Path("dummy.apk"), "hot", limit=3)
    assert clipped["count"] == 3
    assert clipped["has_more"] is True


def test_blank_field_name_is_rejected() -> None:
    client = _client([])
    try:
        client.field_xrefs(Path("dummy.apk"), "   ", limit=10)
    except ApkError as exc:
        assert exc.code == "invalid_params"
    else:  # pragma: no cover - the call must raise
        raise AssertionError("blank field_name was accepted")


def test_field_xrefs_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.field_xrefs")
    assert "Answers with accesses" in doc
    assert "field_name" in doc
    assert "matched" in doc and "fields" in doc
    assert "has_more" in doc
