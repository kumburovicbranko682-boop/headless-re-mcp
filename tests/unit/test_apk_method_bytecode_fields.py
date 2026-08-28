"""Field-level tests for ApkClient.method_bytecode.

These drive the resolution and shaping logic with lightweight fakes standing in
for androguard's analysis objects, so the test runs whether or not androguard is
installed: method_bytecode reaches the DEX only through ``_parsed``, which is
monkeypatched here. The live end-to-end proof (a real DEX disassembled through
the service) lives in the APK integration gate.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError


class _FakeIns:
    def __init__(self, name: str, output: str, hexs: str, length: int) -> None:
        self._name = name
        self._output = output
        self._hex = hexs
        self._len = length

    def get_name(self) -> str:
        return self._name

    def get_output(self) -> str:
        return self._output

    def get_hex(self) -> str:
        return self._hex

    def get_length(self) -> int:
        return self._len


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


def _main_method() -> _FakeMCA:
    # const-string v0, "hello world"; invoke-static onCreate; return-void
    return _FakeMCA(
        "main",
        "()V",
        "public static",
        _FakeEncoded(
            [
                _FakeIns("const-string", 'v0, "hello world"', "1a 00 04 00", 4),
                _FakeIns("invoke-static", "Lcom/example/App;->onCreate()V", "71 00 01 00 00 00", 6),
                _FakeIns("return-void", "", "0e 00", 2),
            ]
        ),
    )


def _client_with(classes: list[_FakeClass], monkeypatch: pytest.MonkeyPatch) -> ApkClient:
    client = ApkClient()
    monkeypatch.setattr(client, "_parsed", lambda _path: _FakeParsed(_FakeAnalysis(classes)))
    return client


_APK = Path("/nonexistent/app.apk")


def test_disassembles_a_method_and_names_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_FakeClass("Lcom/example/App;", [_main_method()])], monkeypatch)

    # Dotted class form resolves to the Lsmali/form class.
    data = client.method_bytecode(_APK, "com.example.App", "main")

    assert data["class_name"] == "Lcom/example/App;"
    assert data["method"] == "main"
    assert data["descriptor"] == "()V"
    assert data["access"] == "public static"
    assert data["has_code"] is True
    assert data["overloads"] == 1
    assert data["insns_capped"] is False
    ins = data["instructions"]
    assert [i["mnemonic"] for i in ins] == ["const-string", "invoke-static", "return-void"]
    # addr is the byte offset within the method code, accumulated from op sizes.
    assert [i["addr"] for i in ins] == [0, 4, 10]
    assert [i["size"] for i in ins] == [4, 6, 2]
    # Spaces are stripped so bytes is a clean hex string.
    assert ins[0]["bytes"] == "1a000400"
    # The reason to read bytecode: the operand names the target, not an index.
    assert "onCreate" in ins[1]["operands"]
    assert "hello world" in ins[0]["operands"]
    assert data["count"] == 3
    assert data["total"] == 3
    assert data["has_more"] is False


def test_paginates_with_offset_and_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_FakeClass("Lcom/example/App;", [_main_method()])], monkeypatch)

    page = client.method_bytecode(_APK, "Lcom/example/App;", "main", offset=1, limit=1)

    assert page["offset"] == 1
    assert page["count"] == 1
    assert page["total"] == 3
    assert page["has_more"] is True
    assert page["instructions"][0]["mnemonic"] == "invoke-static"


def test_overloads_are_reported_and_descriptor_disambiguates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check_bool = _FakeMCA(
        "check", "(I)Z", "public", _FakeEncoded([_FakeIns("return", "v0", "0f 00", 2)])
    )
    check_str = _FakeMCA(
        "check",
        "(Ljava/lang/String;)Z",
        "public",
        _FakeEncoded([_FakeIns("const/4", "v0, 0x1", "12 10", 2)]),
    )
    client = _client_with(
        [_FakeClass("Lcom/example/App;", [check_bool, check_str])], monkeypatch
    )

    # No descriptor: first overload chosen, overloads discloses there are more.
    first = client.method_bytecode(_APK, "com.example.App", "check")
    assert first["overloads"] == 2
    assert first["descriptor"] == "(I)Z"

    # A descriptor pins the intended overload.
    picked = client.method_bytecode(
        _APK, "com.example.App", "check", descriptor="(Ljava/lang/String;)Z"
    )
    assert picked["descriptor"] == "(Ljava/lang/String;)Z"
    assert picked["overloads"] == 2
    assert picked["instructions"][0]["mnemonic"] == "const/4"


def test_unknown_descriptor_lists_the_available_overloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client_with([_FakeClass("Lcom/example/App;", [_main_method()])], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.method_bytecode(_APK, "com.example.App", "main", descriptor="(I)V")

    assert excinfo.value.code == "not_found"
    assert excinfo.value.details.get("available") == ["()V"]


def test_external_methods_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    external = _FakeMCA(
        "main", "()V", "public", _FakeEncoded([]), external=True
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [external])], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.method_bytecode(_APK, "com.example.App", "main")
    assert excinfo.value.code == "not_found"


def test_abstract_method_has_no_code(monkeypatch: pytest.MonkeyPatch) -> None:
    abstract = _FakeMCA(
        "run", "()V", "public abstract", _FakeEncoded([], has_code=False)
    )
    client = _client_with([_FakeClass("Lcom/example/App;", [abstract])], monkeypatch)

    data = client.method_bytecode(_APK, "com.example.App", "run")
    assert data["has_code"] is False
    assert data["instructions"] == []
    assert data["count"] == 0
    assert data["total"] == 0
    assert data["has_more"] is False


def test_missing_class_and_method_and_blanks(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client_with([_FakeClass("Lcom/example/App;", [_main_method()])], monkeypatch)

    with pytest.raises(ApkError) as no_class:
        client.method_bytecode(_APK, "com.example.Absent", "main")
    assert no_class.value.code == "not_found"

    with pytest.raises(ApkError) as no_method:
        client.method_bytecode(_APK, "com.example.App", "absent")
    assert no_method.value.code == "not_found"

    with pytest.raises(ApkError) as blank_class:
        client.method_bytecode(_APK, "   ", "main")
    assert blank_class.value.code == "invalid_params"

    with pytest.raises(ApkError) as blank_method:
        client.method_bytecode(_APK, "com.example.App", "  ")
    assert blank_method.value.code == "invalid_params"


def test_backend_error_when_androguard_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom(_FakeEncoded):
        def get_instructions(self) -> Any:
            raise RuntimeError("bad code item")

    boom = _FakeMCA("main", "()V", "public", _Boom([]))
    client = _client_with([_FakeClass("Lcom/example/App;", [boom])], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.method_bytecode(_APK, "com.example.App", "main")
    assert excinfo.value.code == "backend_error"


def test_docstring_names_the_fields_agents_read() -> None:
    doc = ApkClient.method_bytecode.__doc__ or ""
    for token in ("has_code", "descriptor", "overloads", "operands", "offset"):
        assert token in doc, token
