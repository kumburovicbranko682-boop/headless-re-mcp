"""Field-level tests for ApkClient.class_summary.

Lightweight fakes stand in for androguard's ClassAnalysis so the test runs with
or without androguard: class_summary reaches the DEX only through ``_parsed``
(monkeypatched here). The live end-to-end proof (a real DEX summarised through
the service) lives in the APK integration gate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError


class _FakeVM:
    def __init__(self, access: str, superclass: str) -> None:
        self._access = access
        self._superclass = superclass

    def get_access_flags_string(self) -> str:
        return self._access

    def get_superclassname(self) -> str:
        return self._superclass


class _FakeClass:
    def __init__(
        self,
        name: str,
        *,
        extends: str = "Ljava/lang/Object;",
        implements: list[str] | None = None,
        access: str = "public",
        methods: int = 0,
        fields: int = 0,
        external: bool = False,
        vm_superclass: str | None = None,
    ) -> None:
        self.name = name
        self.extends = extends
        self.implements = implements or []
        self._methods = [object() for _ in range(methods)]
        self._fields = [object() for _ in range(fields)]
        self._external = external
        self._vm = _FakeVM(access, vm_superclass if vm_superclass is not None else extends)

    def is_external(self) -> bool:
        return self._external

    def get_methods(self) -> list[Any]:
        return self._methods

    def get_fields(self) -> list[Any]:
        return self._fields

    def get_vm_class(self) -> _FakeVM:
        return self._vm


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


def test_summarises_a_class_header(monkeypatch: pytest.MonkeyPatch) -> None:
    klass = _FakeClass(
        "Lcom/example/App;",
        extends="Lcom/example/Base;",
        implements=["Lcom/example/Runnable;", "Lcom/example/Closeable;"],
        access="public abstract",
        methods=3,
        fields=2,
    )
    client = _client_with([klass], monkeypatch)

    # Dotted form resolves to the Lsmali/ class.
    data = client.class_summary(_APK, "com.example.App")

    assert data == {
        "class_name": "Lcom/example/App;",
        "superclass": "Lcom/example/Base;",
        "interfaces": ["Lcom/example/Runnable;", "Lcom/example/Closeable;"],
        "access": "public abstract",
        "method_count": 3,
        "field_count": 2,
        "is_external": False,
    }


def test_prefers_the_defined_class_over_an_external_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    external = _FakeClass("Lcom/example/App;", access="", methods=0, external=True)
    defined = _FakeClass("Lcom/example/App;", access="public final", methods=5, fields=1)
    # External listed first: the summary must still describe the real body.
    client = _client_with([external, defined], monkeypatch)

    data = client.class_summary(_APK, "Lcom/example/App;")

    assert data["is_external"] is False
    assert data["access"] == "public final"
    assert data["method_count"] == 5


def test_superclass_falls_back_to_the_vm_class(monkeypatch: pytest.MonkeyPatch) -> None:
    # ClassAnalysis.extends empty, but the encoded class still names the parent.
    klass = _FakeClass("Lcom/example/App;", extends="", vm_superclass="Lx/Parent;")
    client = _client_with([klass], monkeypatch)

    data = client.class_summary(_APK, "com.example.App")
    assert data["superclass"] == "Lx/Parent;"


def test_missing_and_blank_class(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_FakeClass("Lcom/example/App;")], monkeypatch)

    with pytest.raises(ApkError) as missing:
        client.class_summary(_APK, "com.example.Absent")
    assert missing.value.code == "not_found"

    with pytest.raises(ApkError) as blank:
        client.class_summary(_APK, "   ")
    assert blank.value.code == "invalid_params"


def test_backend_error_when_androguard_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeClass):
        def get_methods(self) -> list[Any]:
            raise RuntimeError("bad class data")

    client = _client_with([_Boom("Lcom/example/App;")], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.class_summary(_APK, "com.example.App")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_the_fields_agents_read() -> None:
    doc = ApkClient.class_summary.__doc__ or ""
    for token in ("superclass", "interfaces", "access", "method_count", "field_count"):
        assert token in doc, token
