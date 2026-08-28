"""Field-level tests for ApkClient.method_refs.

Lightweight fakes stand in for androguard's analysis objects so the test runs
with or without androguard installed: method_refs reaches the DEX only through
``_parsed`` (monkeypatched here) and classifies each instruction by its mnemonic
plus ``get_translated_kind``. The live end-to-end proof (a real DEX summarised
through the service) lives in the APK integration gate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient, ApkError


class _FakeIns:
    """One decoded instruction. ``ref`` None models an op with no c-operand."""

    def __init__(self, name: str, ref: str | None) -> None:
        self._name = name
        self._ref = ref

    def get_name(self) -> str:
        return self._name

    def get_translated_kind(self) -> str:
        if self._ref is None:
            # androguard raises IndexError for ops without a class/method/field/
            # string operand (return-void, const/4, ...); the reader must guard.
            raise IndexError("list index out of range")
        return self._ref


class _FakeEncoded:
    def __init__(self, insns: list[_FakeIns], *, has_code: bool = True) -> None:
        self._insns = insns
        self._has_code = has_code

    def get_code(self) -> Any:
        return object() if self._has_code else None

    def get_instructions(self) -> Any:
        return iter(self._insns)


class _FakeMCA:
    def __init__(
        self,
        name: str,
        descriptor: str,
        access: str,
        encoded: _FakeEncoded,
        *,
        external: bool = False,
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = access
        self._encoded = encoded
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_method(self) -> _FakeEncoded:
        return self._encoded


class _FakeClass:
    def __init__(self, name: str, methods: list[_FakeMCA]) -> None:
        self.name = name
        self._methods = methods

    def get_methods(self) -> list[_FakeMCA]:
        return self._methods


class _FakeAnalysis:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


class _FakeParsed:
    def __init__(self, analysis: _FakeAnalysis) -> None:
        self.analysis = analysis


def _client_with(classes: list[_FakeClass], monkeypatch: pytest.MonkeyPatch) -> ApkClient:
    client = ApkClient()
    monkeypatch.setattr(client, "_parsed", lambda _path: _FakeParsed(_FakeAnalysis(classes)))
    return client


_APK = Path("/nonexistent/app.apk")


def test_summarises_calls_fields_and_strings(monkeypatch: pytest.MonkeyPatch) -> None:
    method = _FakeMCA(
        "run",
        "()V",
        "public",
        _FakeEncoded(
            [
                _FakeIns("const-string", "hello world"),
                _FakeIns("invoke-static", "Lcom/example/App;->onCreate()V"),
                _FakeIns("sget", "Lcom/example/Store;->secret I"),
                _FakeIns("sput", "Lcom/example/Store;->secret I"),
                _FakeIns("return-void", None),
            ]
        ),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [method])], monkeypatch)

    data = client.method_refs(_APK, "com.example.App", "run")

    assert data["class_name"] == "Lcom/example/App;"
    assert data["method"] == "run"
    assert data["has_code"] is True
    assert data["calls"] == [{"target": "Lcom/example/App;->onCreate()V", "count": 1}]
    # sget then sput on the same field merge into one entry with both counts.
    assert data["fields"] == [
        {"field": "Lcom/example/Store;->secret I", "reads": 1, "writes": 1}
    ]
    assert data["strings"] == [{"value": "hello world", "count": 1}]
    assert data["call_count"] == 1
    assert data["field_count"] == 1
    assert data["string_count"] == 1
    assert data["calls_truncated"] is False
    assert data["fields_truncated"] is False
    assert data["strings_truncated"] is False


def test_dedups_repeated_sites_and_sorts(monkeypatch: pytest.MonkeyPatch) -> None:
    method = _FakeMCA(
        "run",
        "()V",
        "public",
        _FakeEncoded(
            [
                _FakeIns("invoke-virtual", "Lz/Z;->b()V"),
                _FakeIns("invoke-virtual", "La/A;->a()V"),
                _FakeIns("invoke-virtual", "La/A;->a()V"),
                _FakeIns("const-string", "dup"),
                _FakeIns("const-string", "dup"),
            ]
        ),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [method])], monkeypatch)

    data = client.method_refs(_APK, "com.example.App", "run")

    # Two unique targets, sorted; the repeated one carries count 2.
    assert data["calls"] == [
        {"target": "La/A;->a()V", "count": 2},
        {"target": "Lz/Z;->b()V", "count": 1},
    ]
    assert data["strings"] == [{"value": "dup", "count": 2}]


def test_iget_and_iput_variants_classify_as_read_and_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    method = _FakeMCA(
        "run",
        "()V",
        "public",
        _FakeEncoded(
            [
                _FakeIns("iget-object", "Lc/C;->f Ljava/lang/String;"),
                _FakeIns("iput-boolean", "Lc/C;->g Z"),
            ]
        ),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [method])], monkeypatch)

    data = client.method_refs(_APK, "com.example.App", "run")

    fields = {f["field"]: f for f in data["fields"]}
    assert fields["Lc/C;->f Ljava/lang/String;"]["reads"] == 1
    assert fields["Lc/C;->f Ljava/lang/String;"]["writes"] == 0
    assert fields["Lc/C;->g Z"]["writes"] == 1
    assert fields["Lc/C;->g Z"]["reads"] == 0


def test_abstract_method_has_empty_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    abstract = _FakeMCA("run", "()V", "public abstract", _FakeEncoded([], has_code=False))
    client = _client_with([_FakeClass("Lcom/example/App;", [abstract])], monkeypatch)

    data = client.method_refs(_APK, "com.example.App", "run")

    assert data["has_code"] is False
    assert data["calls"] == []
    assert data["fields"] == []
    assert data["strings"] == []


def test_overloads_and_descriptor_share_the_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    check_bool = _FakeMCA(
        "check", "(I)Z", "public", _FakeEncoded([_FakeIns("invoke-static", "Lp/P;->x()V")])
    )
    check_str = _FakeMCA(
        "check",
        "(Ljava/lang/String;)Z",
        "public",
        _FakeEncoded([_FakeIns("invoke-static", "Lp/P;->y()V")]),
    )
    client = _client_with(
        [_FakeClass("Lcom/example/App;", [check_bool, check_str])], monkeypatch
    )

    first = client.method_refs(_APK, "com.example.App", "check")
    assert first["overloads"] == 2
    assert first["descriptor"] == "(I)Z"
    assert first["calls"][0]["target"] == "Lp/P;->x()V"

    picked = client.method_refs(
        _APK, "com.example.App", "check", descriptor="(Ljava/lang/String;)Z"
    )
    assert picked["descriptor"] == "(Ljava/lang/String;)Z"
    assert picked["calls"][0]["target"] == "Lp/P;->y()V"


def test_missing_and_blank_inputs_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    method = _FakeMCA("run", "()V", "public", _FakeEncoded([]))
    client = _client_with([_FakeClass("Lcom/example/App;", [method])], monkeypatch)

    with pytest.raises(ApkError) as no_class:
        client.method_refs(_APK, "com.example.Absent", "run")
    assert no_class.value.code == "not_found"

    with pytest.raises(ApkError) as no_method:
        client.method_refs(_APK, "com.example.App", "absent")
    assert no_method.value.code == "not_found"

    with pytest.raises(ApkError) as blank:
        client.method_refs(_APK, "  ", "run")
    assert blank.value.code == "invalid_params"


def test_backend_error_when_androguard_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeEncoded):
        def get_instructions(self) -> Any:
            raise RuntimeError("bad code item")

    boom = _FakeMCA("run", "()V", "public", _Boom([]))
    client = _client_with([_FakeClass("Lcom/example/App;", [boom])], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.method_refs(_APK, "com.example.App", "run")
    assert excinfo.value.code == "backend_error"


def test_unique_lists_are_capped_with_disclosure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_METHOD_REFS", 2)
    method = _FakeMCA(
        "run",
        "()V",
        "public",
        _FakeEncoded([_FakeIns("invoke-static", f"Lp/P;->m{i}()V") for i in range(3)]),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [method])], monkeypatch)

    data = client.method_refs(_APK, "com.example.App", "run")

    assert len(data["calls"]) == 2
    assert data["calls_truncated"] is True


def test_docstring_names_the_fields_agents_read() -> None:
    doc = ApkClient.method_refs.__doc__ or ""
    for token in ("calls", "fields", "strings", "reads", "writes"):
        assert token in doc, token
