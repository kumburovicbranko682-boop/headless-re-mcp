"""Tests for ApkClient.subclasses, the inverse-hierarchy (extends/implements) reader.

These fake androguard's analysis object -- exactly like the apk.xrefs tests -- so
the hierarchy logic runs without building a real DEX.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient, ApkError


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


class _VmClass:
    def __init__(self, superclass: str) -> None:
        self._superclass = superclass

    def get_superclassname(self) -> str:
        return self._superclass


class _FakeClassViaVm:
    """A class whose superclass is only reachable through get_vm_class()."""

    def __init__(self, name: str, superclass: str) -> None:
        self.name = name
        self.extends = ""  # empty -> _supertypes falls back to the vm class
        self.implements: list[str] = []
        self._vm = _VmClass(superclass)

    def is_external(self) -> bool:
        return False

    def get_vm_class(self) -> _VmClass:
        return self._vm


class _FakeParsed:
    def __init__(self, classes: list[Any]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[Any]:
        return self._classes


def _client(monkeypatch: pytest.MonkeyPatch, classes: list[Any]) -> ApkClient:
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeParsed(classes))
    return client


_BASE = "Lcom/example/Base;"
_IFACE = "Lcom/example/Cb;"


def _standard_app() -> list[Any]:
    return [
        _FakeClass(_BASE),
        _FakeClass(_IFACE),
        _FakeClass("Lcom/example/ChildB;", extends=_BASE),
        _FakeClass("Lcom/example/ChildA;", extends=_BASE),
        _FakeClass("Lcom/example/Impl;", implements=[_IFACE]),
        _FakeClass("Lcom/example/Unrelated;"),
    ]


def test_finds_direct_subclasses_sorted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _standard_app())
    result = client.subclasses(tmp_path / "app.apk", "com.example.Base")

    assert result["target"] == _BASE
    assert result["target_defined"] is True
    assert result["subtypes"] == [
        {"class_name": "Lcom/example/ChildA;", "relation": "extends"},
        {"class_name": "Lcom/example/ChildB;", "relation": "extends"},
    ]
    assert result["subclass_count"] == 2
    assert result["implementer_count"] == 0
    assert result["total"] == 2
    assert result["has_more"] is False
    assert result["scan_capped"] is False


def test_finds_interface_implementers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, _standard_app())
    result = client.subclasses(tmp_path / "app.apk", "com.example.Cb")

    assert result["subtypes"] == [
        {"class_name": "Lcom/example/Impl;", "relation": "implements"}
    ]
    assert result["implementer_count"] == 1
    assert result["subclass_count"] == 0


def test_dotted_and_smali_forms_resolve_the_same(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, _standard_app())
    dotted = client.subclasses(tmp_path / "app.apk", "com.example.Base")
    smali = client.subclasses(tmp_path / "app.apk", _BASE)
    assert dotted["subtypes"] == smali["subtypes"]


def test_framework_target_not_in_dex_is_not_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Subclasses of a class the DEX does not define still resolve; no not_found."""
    classes = [
        _FakeClass("Lcom/example/MainActivity;", extends="Landroid/app/Activity;"),
        _FakeClass("Lcom/example/Other;"),
    ]
    client = _client(monkeypatch, classes)
    result = client.subclasses(tmp_path / "app.apk", "android.app.Activity")

    assert result["target"] == "Landroid/app/Activity;"
    assert result["target_defined"] is False
    assert result["subtypes"] == [
        {"class_name": "Lcom/example/MainActivity;", "relation": "extends"}
    ]


def test_external_classes_are_not_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An external stub that names the target is a reference, not a real subtype."""
    classes = [
        _FakeClass(_BASE),
        _FakeClass("Lcom/example/RealChild;", extends=_BASE),
        _FakeClass("Lext/Stub;", extends=_BASE, external=True),
    ]
    client = _client(monkeypatch, classes)
    result = client.subclasses(tmp_path / "app.apk", _BASE)
    names = [s["class_name"] for s in result["subtypes"]]
    assert names == ["Lcom/example/RealChild;"]


def test_superclass_via_vm_class_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A class exposing its superclass only through get_vm_class() still matches."""
    classes = [_FakeClassViaVm("Lcom/example/ViaVm;", _BASE)]
    client = _client(monkeypatch, classes)
    result = client.subclasses(tmp_path / "app.apk", _BASE)
    assert result["subtypes"] == [
        {"class_name": "Lcom/example/ViaVm;", "relation": "extends"}
    ]


def test_paging_over_matches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    classes = [_FakeClass(_BASE)] + [
        _FakeClass(f"Lcom/example/Child{i:02d};", extends=_BASE) for i in range(5)
    ]
    client = _client(monkeypatch, classes)
    first = client.subclasses(tmp_path / "app.apk", _BASE, offset=0, limit=2)
    assert first["count"] == 2
    assert first["total"] == 5
    assert first["has_more"] is True
    last = client.subclasses(tmp_path / "app.apk", _BASE, offset=4, limit=2)
    assert last["count"] == 1
    assert last["has_more"] is False


def test_scan_cap_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_CLASSES_COLLECT", 2)
    classes = [_FakeClass(f"Lcom/example/Child{i};", extends=_BASE) for i in range(3)]
    client = _client(monkeypatch, classes)
    result = client.subclasses(tmp_path / "app.apk", _BASE)
    assert result["scan_capped"] is True


def test_no_matches_is_a_clean_empty_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, [_FakeClass("Lcom/example/Lonely;")])
    result = client.subclasses(tmp_path / "app.apk", "com.example.Nope")
    assert result["subtypes"] == []
    assert result["total"] == 0
    assert result["target_defined"] is False


def test_empty_class_name_is_invalid_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, [])
    with pytest.raises(ApkError) as excinfo:
        client.subclasses(tmp_path / "app.apk", "   ")
    assert excinfo.value.code == "invalid_params"


def test_docstring_names_the_fields() -> None:
    doc = ApkClient.subclasses.__doc__ or ""
    for token in ("subtypes", "extends", "implements"):
        assert token in doc, token
