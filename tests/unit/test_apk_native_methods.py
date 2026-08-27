"""apk.native_methods lists the JNI boundary honestly and paginates it."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient
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


class _FakeEncoded:
    def __init__(self, flags: int) -> None:
        self._flags = flags

    def get_access_flags(self) -> int:
        return self._flags


class _FakeNativeMethod:
    def __init__(
        self,
        class_name: str,
        name: str,
        descriptor: str,
        *,
        native: bool = False,
        external: bool = False,
        enc_flags: int | None = None,
    ) -> None:
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self._native = native
        self._external = external
        self._enc_flags = enc_flags

    def is_external(self) -> bool:
        return self._external

    def get_access_flags_string(self) -> str:
        return "public native" if self._native else "public"

    def get_method(self) -> _FakeEncoded | None:
        if self._enc_flags is None:
            return None
        return _FakeEncoded(self._enc_flags)


class _FakeNativeParsed:
    def __init__(self, methods: list[Any]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[Any]:
        return self._methods


def test_apk_native_methods_lists_only_native_sorted(tmp_path: Path, monkeypatch: Any) -> None:
    """Only native, internal methods appear, sorted by class/method/descriptor.

    Measured: three native methods (two overloads of one, one in another
    class) plus a non-native method and an external native stub -> total 3,
    the non-native and external entries dropped, ordered so a later page is
    aimed at the same window. The field is methods, not items.
    """
    methods = [
        _FakeNativeMethod("Lcom/z/Z;", "regular", "()V", native=False),
        _FakeNativeMethod("Lcom/a/A;", "doWork", "(I)I", native=True),
        _FakeNativeMethod("Lcom/a/A;", "doWork", "()I", native=True),
        _FakeNativeMethod("Lcom/ext/E;", "stub", "()V", native=True, external=True),
        _FakeNativeMethod("Lcom/b/B;", "compute", "()J", native=True),
    ]
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeNativeParsed(methods))
    payload = client.native_methods(tmp_path / "app.apk", offset=0, limit=10)
    assert "items" not in payload
    assert payload["total"] == 3
    assert payload["count"] == 3
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False
    assert [m["class"] for m in payload["methods"]] == [
        "Lcom/a/A;",
        "Lcom/a/A;",
        "Lcom/b/B;",
    ]
    assert payload["methods"][0] == {
        "class": "Lcom/a/A;",
        "method": "doWork",
        "descriptor": "()I",
    }
    assert payload["methods"][1]["descriptor"] == "(I)I"
    doc = _tool_docstring("apk.native_methods")
    assert "has_more" in doc
    assert "scan_capped" in doc


def test_apk_native_methods_reports_no_native_as_total_zero(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """An app with no native methods answers total 0, not an error.

    An unattended agent must be able to tell "this app has no JNI" from "the
    scan failed"; an empty list with total 0 is the honest first reading.
    """
    methods = [_FakeNativeMethod("La/A;", f"f{index}", "()V") for index in range(3)]
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeNativeParsed(methods))
    payload = client.native_methods(tmp_path / "app.apk")
    assert payload["methods"] == []
    assert payload["total"] == 0
    assert payload["count"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_apk_native_methods_falls_back_to_integer_access_flags(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """When the flag string is unavailable, the integer ACC_NATIVE bit still counts.

    A method whose get_access_flags_string() raises but whose EncodedMethod
    carries 0x100 is still native; the fallback keeps one odd method from
    hiding a JNI entry point.
    """

    class _Raises(_FakeNativeMethod):
        def get_access_flags_string(self) -> str:
            raise RuntimeError("no flag string")

    method = _Raises("La/A;", "jni", "()V", enc_flags=0x100 | 0x1)
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeNativeParsed([method]))
    payload = client.native_methods(tmp_path / "app.apk")
    assert payload["total"] == 1
    assert payload["methods"][0]["method"] == "jni"


def test_apk_native_methods_paginates(tmp_path: Path, monkeypatch: Any) -> None:
    """A page that fills the limit reports has_more; a tail page does not."""
    methods = [
        _FakeNativeMethod(f"Lc/C{index:03d};", "n", "()V", native=True) for index in range(25)
    ]
    client = ApkClient()
    monkeypatch.setattr(ApkClient, "_parsed", lambda self, path: _FakeNativeParsed(methods))
    page0 = client.native_methods(tmp_path / "app.apk", offset=0, limit=10)
    assert page0["count"] == 10
    assert page0["total"] == 25
    assert page0["has_more"] is True
    tail = client.native_methods(tmp_path / "app.apk", offset=20, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False
