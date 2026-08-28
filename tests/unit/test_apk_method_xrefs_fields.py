"""Field-level tests for ApkClient.method_xrefs.

Lightweight fakes stand in for androguard's analysis objects so the test runs
with or without androguard installed: method_xrefs reaches the DEX only through
``_parsed`` (monkeypatched here) and walks a resolved method's
get_xref_from/get_xref_to, keeping each edge's class, method, descriptor and
bytecode offset. The live end-to-end proof (a real DEX through the service)
lives in the APK integration gate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService


class _Edge:
    """The method at the other end of an xref edge."""

    def __init__(self, class_name: str, name: str, descriptor: str) -> None:
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor


class _EdgeClass:
    def __init__(self, name: str) -> None:
        self.name = name


def _ref(class_name: str, name: str, descriptor: str, offset: int) -> tuple[Any, Any, int]:
    return (_EdgeClass(class_name), _Edge(class_name, name, descriptor), offset)


class _FakeMCA:
    def __init__(
        self,
        name: str,
        descriptor: str,
        *,
        xref_from: tuple[Any, ...] = (),
        xref_to: tuple[Any, ...] = (),
        external: bool = False,
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self.access = "public"
        self._xref_from = list(xref_from)
        self._xref_to = list(xref_to)
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_from(self) -> list[Any]:
        return list(self._xref_from)

    def get_xref_to(self) -> list[Any]:
        return list(self._xref_to)


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


def test_callers_carry_descriptor_and_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _FakeMCA(
        "check",
        "(I)Z",
        xref_from=(
            _ref("Lcom/example/Caller;", "run", "()V", 12),
            _ref("Lcom/example/Other;", "go", "(I)V", 40),
        ),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "check")

    assert data["class_name"] == "Lcom/example/App;"
    assert data["method"] == "check"
    assert data["descriptor"] == "(I)Z"
    assert data["direction"] == "callers"
    assert data["xrefs"] == [
        {"class": "Lcom/example/Caller;", "method": "run", "descriptor": "()V", "offset": 12},
        {"class": "Lcom/example/Other;", "method": "go", "descriptor": "(I)V", "offset": 40},
    ]
    assert data["total"] == 2
    assert data["scan_capped"] is False


def test_callees_walk_xref_to(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _FakeMCA(
        "run",
        "()V",
        xref_to=(_ref("Ljavax/crypto/Cipher;", "doFinal", "([B)[B", 8),),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "run", direction="callees")

    assert data["direction"] == "callees"
    assert data["xrefs"] == [
        {
            "class": "Ljavax/crypto/Cipher;",
            "method": "doFinal",
            "descriptor": "([B)[B",
            "offset": 8,
        }
    ]


def test_descriptor_pins_the_overload(monkeypatch: pytest.MonkeyPatch) -> None:
    check_int = _FakeMCA("check", "(I)Z", xref_from=(_ref("La/A;", "x", "()V", 1),))
    check_str = _FakeMCA(
        "check", "(Ljava/lang/String;)Z", xref_from=(_ref("Lb/B;", "y", "()V", 2),)
    )
    client = _client_with(
        [_FakeClass("Lcom/example/App;", [check_int, check_str])], monkeypatch
    )

    first = client.method_xrefs(_APK, "com.example.App", "check")
    assert first["overloads"] == 2
    assert first["descriptor"] == "(I)Z"
    assert first["xrefs"][0]["method"] == "x"

    picked = client.method_xrefs(
        _APK, "com.example.App", "check", descriptor="(Ljava/lang/String;)Z"
    )
    assert picked["descriptor"] == "(Ljava/lang/String;)Z"
    assert picked["xrefs"][0]["method"] == "y"


def test_edges_dedup_but_distinct_offsets_stay(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _FakeMCA(
        "m",
        "()V",
        xref_from=(
            _ref("Lc/C;", "a", "()V", 4),
            _ref("Lc/C;", "a", "()V", 4),  # exact duplicate collapses
            _ref("Lc/C;", "a", "()V", 16),  # same site, different offset stays
        ),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "m")
    offsets = [x["offset"] for x in data["xrefs"]]
    assert offsets == [4, 16]
    assert data["total"] == 2


def test_edges_are_sorted(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _FakeMCA(
        "m",
        "()V",
        xref_from=(
            _ref("Lz/Z;", "b", "()V", 0),
            _ref("La/A;", "a", "()V", 0),
        ),
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "m")
    assert [x["class"] for x in data["xrefs"]] == ["La/A;", "Lz/Z;"]


def test_non_int_offset_becomes_minus_one(monkeypatch: pytest.MonkeyPatch) -> None:
    edge = (_EdgeClass("Lc/C;"), _Edge("Lc/C;", "a", "()V"), None)
    target = _FakeMCA("m", "()V", xref_from=(edge,))
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "m")
    assert data["xrefs"][0]["offset"] == -1


def test_class_name_falls_back_to_edge_class(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the edge method has no class_name, the edge's class object is used."""
    edge_method = _Edge("", "a", "()V")  # empty class_name
    target = _FakeMCA("m", "()V", xref_from=((_EdgeClass("Lfallback/F;"), edge_method, 3),))
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "m")
    assert data["xrefs"][0]["class"] == "Lfallback/F;"


def test_empty_walk_is_a_clean_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _FakeMCA("m", "()V")
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "m")
    assert data["xrefs"] == []
    assert data["total"] == 0
    assert data["has_more"] is False


def test_invalid_direction_faults(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _FakeMCA("m", "()V")
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.method_xrefs(_APK, "com.example.App", "m", direction="sideways")
    assert excinfo.value.code == "invalid_params"


def test_missing_and_blank_inputs_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    target = _FakeMCA("m", "()V")
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    with pytest.raises(ApkError) as no_class:
        client.method_xrefs(_APK, "com.example.Absent", "m")
    assert no_class.value.code == "not_found"

    with pytest.raises(ApkError) as no_method:
        client.method_xrefs(_APK, "com.example.App", "absent")
    assert no_method.value.code == "not_found"

    with pytest.raises(ApkError) as blank:
        client.method_xrefs(_APK, "  ", "m")
    assert blank.value.code == "invalid_params"


def test_pagination_windows_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    refs = tuple(_ref(f"L{i:02d}/C;", "a", "()V", i) for i in range(5))
    target = _FakeMCA("m", "()V", xref_from=refs)
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    page = client.method_xrefs(_APK, "com.example.App", "m", offset=1, limit=2)
    assert page["offset"] == 1
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True


def test_collect_cap_discloses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk_client, "_MAX_METHOD_XREFS_COLLECT", 2)
    refs = tuple(_ref(f"L{i:02d}/C;", "a", "()V", i) for i in range(5))
    target = _FakeMCA("m", "()V", xref_from=refs)
    client = _client_with([_FakeClass("Lcom/example/App;", [target])], monkeypatch)

    data = client.method_xrefs(_APK, "com.example.App", "m")
    assert data["scan_capped"] is True
    assert data["total"] == 2


def test_service_wraps_unknown_session_as_failure() -> None:
    service = AnalysisService(Settings.load())
    result = service.apk_method_xrefs("no-such-session", "com.example.App", "m")
    assert not result.ok
    assert result.error is not None


def test_docstring_names_the_contract() -> None:
    doc = ApkClient.method_xrefs.__doc__ or ""
    for token in ("callers", "callees", "descriptor", "offset", "xref_from"):
        assert token in doc, token
