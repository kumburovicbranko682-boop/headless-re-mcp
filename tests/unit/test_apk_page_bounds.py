"""apk list backends must bound a page even when the caller does not.

The apk.* tool schema pins offset >= 0 and limit to [1, max], and
``test_apk_offset_schema`` guards that. But the schema only protects the MCP
transport: ``CommandCatalog.invoke`` (the agent transport) forwards raw
arguments straight to the handler with no schema validation, so a run whose
model emits ``limit: -1`` reaches ``ApkClient.classes`` unvalidated. There the
old ``names[offset:offset + limit]`` trusted both numbers -- ``names[0:-1]`` is
every row but the last, the opposite of a small page, and a negative offset read
the tail of the DEX as page zero. Every sibling backend (web, jsre, proxy, jadx)
clamps its own pages; these tests hold the apk backend to the same bound.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_CLASSES_PAGE,
    _MAX_STRINGS_PAGE,
    _MAX_XREFS_PAGE,
    ApkClient,
)


class _FakeClass:
    def __init__(self, name: str) -> None:
        self.name = name

    def is_external(self) -> bool:
        return False


class _FakeClassParsed:
    def __init__(self, count: int) -> None:
        self.analysis = self
        self._classes = [_FakeClass(f"L{index:04d};") for index in range(count)]

    def get_classes(self) -> list[_FakeClass]:
        return self._classes


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeStringParsed:
    def __init__(self, count: int) -> None:
        self.analysis = self
        self._count = count

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(f"s{index:05d}") for index in range(self._count)]


class _FakeApkMethod:
    def __init__(self, index: int) -> None:
        self.name = f"m{index:04d}"
        self.descriptor = "()V"
        self.access = "public"


class _FakeMethodClass:
    def __init__(self, count: int) -> None:
        self.name = "Lcom/example/Foo;"
        self._methods = [_FakeApkMethod(index) for index in range(count)]

    def get_methods(self) -> list[_FakeApkMethod]:
        return self._methods


class _FakeMethodParsed:
    def __init__(self, count: int) -> None:
        self.analysis = self
        self._classes = [_FakeMethodClass(count)]

    def get_classes(self) -> list[_FakeMethodClass]:
        return self._classes


class _FakeCall:
    def __init__(self, index: int) -> None:
        self.class_name = f"Lcom/example/Caller{index};"
        self.name = "invoke"


class _FakeXrefMethod:
    def __init__(self, name: str, callers: int) -> None:
        self.name = name
        self._callers = callers

    def is_external(self) -> bool:
        return False

    def get_xref_from(self) -> list[tuple[object, _FakeCall, int]]:
        return [(None, _FakeCall(index), index) for index in range(self._callers)]


class _FakeXrefParsed:
    def __init__(self, callers: int) -> None:
        self.analysis = self
        self._methods = [_FakeXrefMethod("decrypt", callers)]

    def get_methods(self) -> list[_FakeXrefMethod]:
        return self._methods


def _classes(monkeypatch: pytest.MonkeyPatch, count: int) -> ApkClient:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeClassParsed(count))
    return ApkClient()


def test_classes_negative_limit_is_not_a_near_complete_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """limit=-1 used to page as names[0:-1]: every class but the last one."""
    client = _classes(monkeypatch, count=50)
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=-1)
    # Clamped to the smallest legal page, not 49 rows.
    assert payload["count"] == 1
    assert payload["total"] == 50
    assert payload["has_more"] is True


def test_classes_huge_limit_is_capped_at_the_page_maximum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A limit past the schema ceiling must not spill the whole collected list."""
    client = _classes(monkeypatch, count=_MAX_CLASSES_PAGE + 500)
    payload = client.classes(tmp_path / "app.apk", offset=0, limit=10**9)
    assert payload["count"] == _MAX_CLASSES_PAGE
    assert payload["has_more"] is True


def test_classes_negative_offset_is_page_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """offset=-5 used to slice names[-5:5] -> empty, reported with has_more."""
    client = _classes(monkeypatch, count=25)
    payload = client.classes(tmp_path / "app.apk", offset=-5, limit=10)
    assert payload["offset"] == 0
    assert payload["count"] == 10
    # Page zero is the front of the sorted list, not a tail slice.
    assert payload["classes"][0] == "L0000;"
    assert payload["has_more"] is True


def test_classes_coerces_a_numeric_string_the_way_the_schema_would(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The agent transport may hand over strings the MCP schema would parse."""
    client = _classes(monkeypatch, count=25)
    payload = client.classes(tmp_path / "app.apk", offset="5", limit="10")  # type: ignore[arg-type]
    assert payload["offset"] == 5
    assert payload["count"] == 10
    assert payload["classes"][0] == "L0005;"


def test_methods_negative_limit_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeMethodParsed(50))
    client = ApkClient()
    payload = client.methods(tmp_path / "app.apk", "com.example.Foo", offset=0, limit=-1)
    assert payload["count"] == 1
    assert payload["total"] == 50
    assert payload["has_more"] is True


def test_strings_huge_limit_is_capped_at_the_page_maximum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeStringParsed(_MAX_STRINGS_PAGE + 300)
    )
    client = ApkClient()
    payload = client.strings(tmp_path / "app.apk", offset=0, limit=10**9)
    assert payload["count"] == _MAX_STRINGS_PAGE
    assert payload["has_more"] is True


def test_xrefs_huge_limit_is_capped_at_the_page_maximum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """xrefs had no upper bound: a giant limit collected every caller inline."""
    monkeypatch.setattr(
        ApkClient, "_parsed", lambda self, path: _FakeXrefParsed(_MAX_XREFS_PAGE + 200)
    )
    client = ApkClient()
    payload = client.xrefs(tmp_path / "app.apk", "decrypt", limit=10**9)
    assert payload["count"] == _MAX_XREFS_PAGE
    assert payload["has_more"] is True


def test_a_valid_page_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The clamp must be a no-op for arguments the schema already allows."""
    client = _classes(monkeypatch, count=25)
    payload = client.classes(tmp_path / "app.apk", offset=10, limit=10)
    assert payload["offset"] == 10
    assert payload["count"] == 10
    assert payload["classes"][0] == "L0010;"
    assert payload["has_more"] is True
