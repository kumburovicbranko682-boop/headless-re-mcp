"""ApkClient.class_xrefs: class-level usage edges (who uses a class / what it uses).

Fakes androguard's analysis object exactly like the apk.xrefs and apk.subclasses
tests, so the edge collection runs without a real DEX. The ClassAnalysis xref
maps are dict[ClassAnalysis, set[(REF_TYPE, MethodAnalysis, offset)]].
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient, ApkError


class _Method:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _Kind:
    """A hashable stand-in for androguard's REF_TYPE enum (sets need hashable)."""

    __slots__ = ("name",)

    def __init__(self, name: str) -> None:
        self.name = name

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Kind) and other.name == self.name


def _kind(name: str) -> Any:
    return _Kind(name)


class _ClassAnalysis:
    def __init__(
        self,
        name: str,
        *,
        external: bool = False,
        xref_from: dict[Any, set[tuple[Any, Any, int]]] | None = None,
        xref_to: dict[Any, set[tuple[Any, Any, int]]] | None = None,
    ) -> None:
        self.name = name
        self._external = external
        self._xf = xref_from or {}
        self._xt = xref_to or {}

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> dict[Any, set[tuple[Any, Any, int]]]:
        return self._xf

    def get_xref_to(self) -> dict[Any, set[tuple[Any, Any, int]]]:
        return self._xt


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


_TARGET = "Lcom/example/Crypto;"


def test_from_lists_who_references_the_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    caller_a = _ClassAnalysis("Lcom/example/A;")
    caller_b = _ClassAnalysis("Lcom/example/B;")
    target = _ClassAnalysis(
        _TARGET,
        xref_from={
            caller_a: {(_kind("REF_NEW_INSTANCE"), _Method("Lcom/example/A;", "onCreate"), 4)},
            caller_b: {(_kind("INVOKE_VIRTUAL"), _Method("Lcom/example/B;", "run"), 12)},
        },
    )
    client = _client(monkeypatch, [target, caller_a, caller_b])

    out = client.class_xrefs(tmp_path / "app.apk", "com.example.Crypto")
    assert out["direction"] == "from"
    assert out["target"] == _TARGET
    assert out["class_name"] == _TARGET
    assert out["total"] == 2
    edges = {(e["class"], e["method"], e["kind"], e["offset"]) for e in out["xrefs"]}
    assert edges == {
        ("Lcom/example/A;", "onCreate", "REF_NEW_INSTANCE", 4),
        ("Lcom/example/B;", "run", "INVOKE_VIRTUAL", 12),
    }
    assert out["scan_capped"] is False
    assert out["has_more"] is False


def test_to_lists_what_the_class_uses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dep = _ClassAnalysis("Ljava/util/Base64;")
    target = _ClassAnalysis(
        _TARGET,
        xref_to={
            dep: {(_kind("INVOKE_STATIC"), _Method("Ljava/util/Base64;", "encode"), 8)},
        },
    )
    client = _client(monkeypatch, [target, dep])

    out = client.class_xrefs(tmp_path / "app.apk", _TARGET, direction="to")
    assert out["direction"] == "to"
    assert out["xrefs"] == [
        {
            "class": "Ljava/util/Base64;",
            "method": "encode",
            "kind": "INVOKE_STATIC",
            "offset": 8,
        }
    ]


def test_external_framework_target_still_resolves_inbound_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """"Who uses javax.crypto.Cipher" works even though Cipher is not defined."""
    user = _ClassAnalysis("Lcom/example/Secure;")
    cipher = _ClassAnalysis(
        "Ljavax/crypto/Cipher;",
        external=True,
        xref_from={
            user: {(_kind("INVOKE_VIRTUAL"), _Method("Lcom/example/Secure;", "decrypt"), 20)},
        },
    )
    client = _client(monkeypatch, [user, cipher])

    out = client.class_xrefs(tmp_path / "app.apk", "javax.crypto.Cipher")
    assert out["total"] == 1
    assert out["xrefs"][0]["class"] == "Lcom/example/Secure;"
    assert out["xrefs"][0]["method"] == "decrypt"


def test_dotted_and_smali_forms_resolve_the_same(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    caller = _ClassAnalysis("Lcom/example/A;")
    target = _ClassAnalysis(
        _TARGET,
        xref_from={caller: {(_kind("REF_CLASS_USAGE"), _Method("Lcom/example/A;", "f"), 0)}},
    )
    client = _client(monkeypatch, [target, caller])

    dotted = client.class_xrefs(tmp_path / "app.apk", "com.example.Crypto")
    smali = client.class_xrefs(tmp_path / "app.apk", _TARGET)
    assert dotted["xrefs"] == smali["xrefs"]


def test_edges_are_deduplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    caller = _ClassAnalysis("Lcom/example/A;")
    # The same edge reported twice (androguard sets dedup, but a merged multi-
    # match anchor could still repeat) collapses to one row.
    target = _ClassAnalysis(
        _TARGET,
        xref_from={
            caller: {
                (_kind("INVOKE_VIRTUAL"), _Method("Lcom/example/A;", "f"), 4),
            }
        },
    )
    target_dup = _ClassAnalysis(
        _TARGET,
        xref_from={
            caller: {
                (_kind("INVOKE_VIRTUAL"), _Method("Lcom/example/A;", "f"), 4),
            }
        },
    )
    client = _client(monkeypatch, [target, target_dup])
    out = client.class_xrefs(tmp_path / "app.apk", _TARGET)
    assert out["total"] == 1


def test_paging_over_edges(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    callers = [_ClassAnalysis(f"Lcom/example/C{i:02d};") for i in range(5)]
    xref_from = {
        c: {(_kind("INVOKE_VIRTUAL"), _Method(c.name, "m"), i)}
        for i, c in enumerate(callers)
    }
    target = _ClassAnalysis(_TARGET, xref_from=xref_from)
    client = _client(monkeypatch, [target, *callers])

    first = client.class_xrefs(tmp_path / "app.apk", _TARGET, offset=0, limit=2)
    assert first["count"] == 2
    assert first["total"] == 5
    assert first["has_more"] is True
    last = client.class_xrefs(tmp_path / "app.apk", _TARGET, offset=4, limit=2)
    assert last["count"] == 1
    assert last["has_more"] is False


def test_scan_cap_is_disclosed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_CLASS_XREFS_COLLECT", 2)
    callers = [_ClassAnalysis(f"Lcom/example/C{i};") for i in range(4)]
    xref_from = {
        c: {(_kind("INVOKE_VIRTUAL"), _Method(c.name, "m"), i)}
        for i, c in enumerate(callers)
    }
    target = _ClassAnalysis(_TARGET, xref_from=xref_from)
    client = _client(monkeypatch, [target, *callers])
    out = client.class_xrefs(tmp_path / "app.apk", _TARGET)
    assert out["scan_capped"] is True
    assert out["total"] <= 2


def test_unknown_class_is_not_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, [_ClassAnalysis("Lcom/example/Other;")])
    with pytest.raises(ApkError) as info:
        client.class_xrefs(tmp_path / "app.apk", "com.example.Nope")
    assert info.value.code == "not_found"


def test_invalid_direction_and_empty_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, [_ClassAnalysis(_TARGET)])
    with pytest.raises(ApkError) as bad_dir:
        client.class_xrefs(tmp_path / "app.apk", _TARGET, direction="sideways")
    assert bad_dir.value.code == "invalid_params"
    with pytest.raises(ApkError) as empty:
        client.class_xrefs(tmp_path / "app.apk", "   ")
    assert empty.value.code == "invalid_params"


def test_docstring_names_the_fields() -> None:
    doc = ApkClient.class_xrefs.__doc__ or ""
    for token in ("xrefs", "kind", "offset", "direction"):
        assert token in doc, token
