"""Unit tests for apk.class_xrefs (who references a class).

These pin the flattening of ClassAnalysis.get_xref_from() into (class, method)
rows: the target is looked up by dotted or smali name (internal or external),
rows are deduped and sorted, pagination is honest, and the collect cap trips
scan_capped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    ApkError,
)


class _FakeMethod:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeCaller:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeClass:
    def __init__(self, name: str, xref_from: dict | None = None) -> None:
        self.name = name
        self._xref_from = xref_from or {}

    def get_xref_from(self) -> dict:
        return self._xref_from


class _FakeParsed:
    def __init__(self, classes: list[_FakeClass]) -> None:
        self.analysis = self
        self._classes = classes

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


def _client_with(classes: list[_FakeClass], monkeypatch: Any) -> ApkClient:
    monkeypatch.setattr(
        ApkClient,
        "_parsed",
        lambda self, path: _FakeParsed(classes),  # type: ignore[method-assign, assignment, return-value]
    )
    return ApkClient()


def test_class_xrefs_flattens_dedupes_and_sorts(tmp_path: Path, monkeypatch: Any) -> None:
    caller_b = _FakeCaller("Lcom/example/B;")
    caller_a = _FakeCaller("Lcom/example/A;")
    xref_from = {
        caller_b: {(0, _FakeMethod("run"), 4), (0, _FakeMethod("run"), 8)},
        caller_a: {(0, _FakeMethod("init"), 0), (0, _FakeMethod("stop"), 12)},
    }
    target = _FakeClass("Lcom/example/Target;", xref_from)
    client = _client_with([target, caller_a, caller_b], monkeypatch)

    payload = client.class_xrefs(tmp_path / "app.apk", "com.example.Target")

    assert payload["class_name"] == "Lcom/example/Target;"
    assert payload["xrefs"] == [
        {"class": "Lcom/example/A;", "method": "init"},
        {"class": "Lcom/example/A;", "method": "stop"},
        {"class": "Lcom/example/B;", "method": "run"},
    ]
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["offset"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_class_xrefs_accepts_smali_name(tmp_path: Path, monkeypatch: Any) -> None:
    caller = _FakeCaller("Lcom/example/Caller;")
    target = _FakeClass(
        "Lcom/example/Target;", {caller: {(0, _FakeMethod("use"), 0)}}
    )
    client = _client_with([target, caller], monkeypatch)

    payload = client.class_xrefs(tmp_path / "app.apk", "Lcom/example/Target;")

    assert payload["xrefs"] == [{"class": "Lcom/example/Caller;", "method": "use"}]


def test_class_xrefs_finds_external_target(tmp_path: Path, monkeypatch: Any) -> None:
    caller = _FakeCaller("Lcom/example/Caller;")
    external = _FakeClass(
        "Landroid/telephony/TelephonyManager;",
        {caller: {(0, _FakeMethod("getImei"), 0)}},
    )
    client = _client_with([external, caller], monkeypatch)

    payload = client.class_xrefs(
        tmp_path / "app.apk", "android.telephony.TelephonyManager"
    )

    assert payload["class_name"] == "Landroid/telephony/TelephonyManager;"
    assert payload["xrefs"] == [
        {"class": "Lcom/example/Caller;", "method": "getImei"}
    ]


def test_class_xrefs_not_found_for_unknown_class(tmp_path: Path, monkeypatch: Any) -> None:
    known = _FakeClass("Lcom/example/Known;", {})
    client = _client_with([known], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.class_xrefs(tmp_path / "app.apk", "com.example.Missing")
    assert excinfo.value.code == "not_found"


def test_class_xrefs_empty_when_unreferenced(tmp_path: Path, monkeypatch: Any) -> None:
    target = _FakeClass("Lcom/example/Target;", {})
    client = _client_with([target], monkeypatch)

    payload = client.class_xrefs(tmp_path / "app.apk", "com.example.Target")

    assert payload["xrefs"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_class_xrefs_paginates(tmp_path: Path, monkeypatch: Any) -> None:
    xref_from = {
        _FakeCaller(f"Lcom/example/C{index:03d};"): {(0, _FakeMethod("use"), 0)}
        for index in range(5)
    }
    target = _FakeClass("Lcom/example/Target;", xref_from)
    client = _client_with([target], monkeypatch)

    payload = client.class_xrefs(
        tmp_path / "app.apk", "com.example.Target", offset=2, limit=2
    )

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["xrefs"] == [
        {"class": "Lcom/example/C002;", "method": "use"},
        {"class": "Lcom/example/C003;", "method": "use"},
    ]


def test_class_xrefs_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.apk.client._MAX_CLASSES_COLLECT", 3
    )
    xref_from = {
        _FakeCaller(f"Lcom/example/C{index:03d};"): {(0, _FakeMethod("use"), 0)}
        for index in range(10)
    }
    target = _FakeClass("Lcom/example/Target;", xref_from)
    client = _client_with([target], monkeypatch)

    payload = client.class_xrefs(tmp_path / "app.apk", "com.example.Target")

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_class_xrefs_skips_malformed_refs(tmp_path: Path, monkeypatch: Any) -> None:
    caller = _FakeCaller("Lcom/example/Caller;")
    xref_from = {
        caller: {
            (0, _FakeMethod("good"), 0),
            ("too", "short"),
        }
    }
    target = _FakeClass("Lcom/example/Target;", xref_from)
    client = _client_with([target], monkeypatch)

    payload = client.class_xrefs(tmp_path / "app.apk", "com.example.Target")

    assert payload["xrefs"] == [{"class": "Lcom/example/Caller;", "method": "good"}]


def test_class_xrefs_requires_class_name(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client_with([_FakeClass("Lcom/example/Target;", {})], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.class_xrefs(tmp_path / "app.apk", "   ")
    assert excinfo.value.code == "invalid_params"


def test_class_xrefs_docstring_names_shape() -> None:
    doc = ApkClient.class_xrefs.__doc__ or ""
    assert "class-level xref" in doc
    assert "who uses this type" in doc
    assert "scan_capped" in doc
