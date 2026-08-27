"""Unit tests for apk.smali (per-method Dalvik disassembly).

These pin the shape produced from androguard's EncodedMethod.get_instructions():
class/method resolution (dotted or smali), overload disambiguation via
descriptor, code-unit addr accumulation from get_length(), the no-code (empty
list, not error) path, honest pagination, and the collect cap.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError


class _FakeInsn:
    def __init__(self, name: str, output: str = "", length: int = 2) -> None:
        self._name = name
        self._output = output
        self._length = length

    def get_name(self) -> str:
        return self._name

    def get_output(self, idx: int = -1) -> str:
        return self._output

    def get_length(self) -> int:
        return self._length


class _FakeEncoded:
    def __init__(self, insns: list[_FakeInsn]) -> None:
        self._insns = insns

    def get_instructions(self) -> list[_FakeInsn]:
        return self._insns


class _FakeMethod:
    def __init__(
        self,
        name: str,
        descriptor: str,
        insns: list[_FakeInsn],
        *,
        external: bool = False,
    ) -> None:
        self.name = name
        self.descriptor = descriptor
        self._encoded = _FakeEncoded(insns)
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_method(self) -> _FakeEncoded:
        return self._encoded


class _FakeClass:
    def __init__(self, name: str, methods: list[_FakeMethod]) -> None:
        self.name = name
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return self._methods


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


def test_smali_renders_rows_and_accumulates_addr(
    tmp_path: Path, monkeypatch: Any
) -> None:
    insns = [
        _FakeInsn("const/4", "v0, 0x1", length=2),
        _FakeInsn("invoke-virtual", "v0, Lp/C;->m()V", length=6),
        _FakeInsn("return-void", "", length=2),
    ]
    method = _FakeMethod("run", "()V", insns)
    klass = _FakeClass("Lcom/example/Target;", [method])
    client = _client_with([klass], monkeypatch)

    payload = client.disassemble(tmp_path / "app.apk", "com.example.Target", "run")

    assert payload["class_name"] == "Lcom/example/Target;"
    assert payload["method_name"] == "run"
    assert payload["descriptor"] == "()V"
    assert payload["overloads"] == ["()V"]
    assert payload["instructions"] == [
        {"addr": 0, "mnemonic": "const/4", "operands": "v0, 0x1"},
        {"addr": 1, "mnemonic": "invoke-virtual", "operands": "v0, Lp/C;->m()V"},
        {"addr": 4, "mnemonic": "return-void", "operands": ""},
    ]
    assert payload["count"] == 3
    assert payload["total"] == 3
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_smali_accepts_smali_class_name(tmp_path: Path, monkeypatch: Any) -> None:
    method = _FakeMethod("m", "()V", [_FakeInsn("nop")])
    klass = _FakeClass("Lcom/example/Target;", [method])
    client = _client_with([klass], monkeypatch)

    payload = client.disassemble(tmp_path / "app.apk", "Lcom/example/Target;", "m")

    assert payload["instructions"] == [{"addr": 0, "mnemonic": "nop", "operands": ""}]


def test_smali_lists_overloads_and_picks_first(
    tmp_path: Path, monkeypatch: Any
) -> None:
    a = _FakeMethod("do", "()V", [_FakeInsn("nop")])
    b = _FakeMethod("do", "(I)V", [_FakeInsn("return-void")])
    klass = _FakeClass("Lcom/example/Target;", [a, b])
    client = _client_with([klass], monkeypatch)

    payload = client.disassemble(tmp_path / "app.apk", "com.example.Target", "do")

    assert payload["descriptor"] == "()V"
    assert payload["overloads"] == ["()V", "(I)V"]
    assert payload["instructions"][0]["mnemonic"] == "nop"


def test_smali_descriptor_selects_overload(tmp_path: Path, monkeypatch: Any) -> None:
    a = _FakeMethod("do", "()V", [_FakeInsn("nop")])
    b = _FakeMethod("do", "(I)V", [_FakeInsn("return-void")])
    klass = _FakeClass("Lcom/example/Target;", [a, b])
    client = _client_with([klass], monkeypatch)

    payload = client.disassemble(
        tmp_path / "app.apk", "com.example.Target", "do", descriptor="(I)V"
    )

    assert payload["descriptor"] == "(I)V"
    assert payload["instructions"][0]["mnemonic"] == "return-void"


def test_smali_unknown_descriptor_is_not_found(
    tmp_path: Path, monkeypatch: Any
) -> None:
    method = _FakeMethod("do", "()V", [_FakeInsn("nop")])
    klass = _FakeClass("Lcom/example/Target;", [method])
    client = _client_with([klass], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.disassemble(
            tmp_path / "app.apk", "com.example.Target", "do", descriptor="(J)V"
        )
    assert excinfo.value.code == "not_found"


def test_smali_no_code_yields_empty_not_error(
    tmp_path: Path, monkeypatch: Any
) -> None:
    method = _FakeMethod("native0", "()V", [])
    klass = _FakeClass("Lcom/example/Target;", [method])
    client = _client_with([klass], monkeypatch)

    payload = client.disassemble(tmp_path / "app.apk", "com.example.Target", "native0")

    assert payload["instructions"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_smali_skips_external_method(tmp_path: Path, monkeypatch: Any) -> None:
    external = _FakeMethod("m", "()V", [_FakeInsn("nop")], external=True)
    klass = _FakeClass("Lcom/example/Target;", [external])
    client = _client_with([klass], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.disassemble(tmp_path / "app.apk", "com.example.Target", "m")
    assert excinfo.value.code == "not_found"


def test_smali_unknown_class_is_not_found(tmp_path: Path, monkeypatch: Any) -> None:
    klass = _FakeClass("Lcom/example/Known;", [_FakeMethod("m", "()V", [])])
    client = _client_with([klass], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.disassemble(tmp_path / "app.apk", "com.example.Missing", "m")
    assert excinfo.value.code == "not_found"


def test_smali_unknown_method_is_not_found(tmp_path: Path, monkeypatch: Any) -> None:
    klass = _FakeClass("Lcom/example/Target;", [_FakeMethod("present", "()V", [])])
    client = _client_with([klass], monkeypatch)

    with pytest.raises(ApkError) as excinfo:
        client.disassemble(tmp_path / "app.apk", "com.example.Target", "absent")
    assert excinfo.value.code == "not_found"


def test_smali_paginates(tmp_path: Path, monkeypatch: Any) -> None:
    insns = [_FakeInsn(f"op{index}", length=2) for index in range(5)]
    method = _FakeMethod("run", "()V", insns)
    klass = _FakeClass("Lcom/example/Target;", [method])
    client = _client_with([klass], monkeypatch)

    payload = client.disassemble(
        tmp_path / "app.apk", "com.example.Target", "run", offset=2, limit=2
    )

    assert payload["offset"] == 2
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert [row["mnemonic"] for row in payload["instructions"]] == ["op2", "op3"]
    assert [row["addr"] for row in payload["instructions"]] == [2, 3]


def test_smali_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.apk.client._MAX_SMALI_COLLECT", 3
    )
    insns = [_FakeInsn("nop") for _ in range(10)]
    method = _FakeMethod("run", "()V", insns)
    klass = _FakeClass("Lcom/example/Target;", [method])
    client = _client_with([klass], monkeypatch)

    payload = client.disassemble(tmp_path / "app.apk", "com.example.Target", "run")

    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_smali_requires_class_and_method(tmp_path: Path, monkeypatch: Any) -> None:
    client = _client_with(
        [_FakeClass("Lcom/example/Target;", [_FakeMethod("m", "()V", [])])],
        monkeypatch,
    )

    with pytest.raises(ApkError) as class_err:
        client.disassemble(tmp_path / "app.apk", "  ", "m")
    assert class_err.value.code == "invalid_params"

    with pytest.raises(ApkError) as method_err:
        client.disassemble(tmp_path / "app.apk", "com.example.Target", "  ")
    assert method_err.value.code == "invalid_params"


def test_smali_docstring_names_shape() -> None:
    doc = ApkClient.disassemble.__doc__ or ""
    assert "per-method bytecode view" in doc
    assert "overloads" in doc
    assert "code-unit offset" in doc
