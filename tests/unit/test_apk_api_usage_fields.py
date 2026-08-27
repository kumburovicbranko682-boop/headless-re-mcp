"""apk.api_usage finds internal callers of a class/package prefix."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk import client as apk_client
from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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


class _FakeCallee:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _FakeMethod:
    def __init__(
        self,
        class_name: str,
        name: str,
        callees: list[tuple[str, str]],
        *,
        external: bool = False,
    ) -> None:
        self.class_name = class_name
        self.name = name
        self._callees = callees
        self._external = external

    def is_external(self) -> bool:
        return self._external

    def get_xref_to(self) -> list[tuple[object, _FakeCallee, int]]:
        return [(None, _FakeCallee(cc, cm), 0) for cc, cm in self._callees]


class _FakeParsed:
    def __init__(self, methods: list[_FakeMethod]) -> None:
        self.analysis = self
        self._methods = methods

    def get_methods(self) -> list[_FakeMethod]:
        return list(self._methods)


def _client(methods: list[_FakeMethod]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(methods)  # type: ignore[method-assign, assignment, return-value]
    return client


def test_api_usage_matches_prefix_and_records_call_sites() -> None:
    """A dotted prefix normalises and matches callees under it.

    Two methods call into javax.crypto; one only touches unrelated APIs, so
    only the crypto call sites come back, with both endpoints named.
    """
    methods = [
        _FakeMethod(
            "Lcom/example/Enc;",
            "encrypt",
            [("Ljavax/crypto/Cipher;", "doFinal"), ("Ljava/lang/String;", "getBytes")],
        ),
        _FakeMethod(
            "Lcom/example/Enc;",
            "init",
            [("Ljavax/crypto/spec/SecretKeySpec;", "<init>")],
        ),
        _FakeMethod("Lcom/example/Ui;", "draw", [("Landroid/view/View;", "invalidate")]),
    ]
    payload = _client(methods).api_usage(Path("dummy.apk"), "javax.crypto")
    assert payload["prefix"] == "Ljavax/crypto"
    assert payload["usage"] == [
        {
            "caller_class": "Lcom/example/Enc;",
            "caller_method": "encrypt",
            "callee_class": "Ljavax/crypto/Cipher;",
            "callee_method": "doFinal",
        },
        {
            "caller_class": "Lcom/example/Enc;",
            "caller_method": "init",
            "callee_class": "Ljavax/crypto/spec/SecretKeySpec;",
            "callee_method": "<init>",
        },
    ]
    assert payload["total"] == 2


def test_api_usage_accepts_smali_prefix() -> None:
    methods = [
        _FakeMethod("Lcom/a/B;", "m", [("Landroid/telephony/TelephonyManager;", "getDeviceId")]),
    ]
    payload = _client(methods).api_usage(Path("dummy.apk"), "Landroid/telephony/")
    assert payload["prefix"] == "Landroid/telephony/"
    assert payload["usage"][0]["callee_method"] == "getDeviceId"


def test_api_usage_skips_external_callers_and_dedups() -> None:
    methods = [
        _FakeMethod(
            "Landroid/Framework;",
            "x",
            [("Ljavax/crypto/Cipher;", "doFinal")],
            external=True,
        ),
        _FakeMethod(
            "Lcom/example/A;",
            "run",
            [("Ljavax/crypto/Cipher;", "doFinal"), ("Ljavax/crypto/Cipher;", "doFinal")],
        ),
    ]
    payload = _client(methods).api_usage(Path("dummy.apk"), "javax.crypto")
    assert payload["usage"] == [
        {
            "caller_class": "Lcom/example/A;",
            "caller_method": "run",
            "callee_class": "Ljavax/crypto/Cipher;",
            "callee_method": "doFinal",
        },
    ]
    assert payload["total"] == 1


def test_api_usage_no_match_is_empty() -> None:
    methods = [_FakeMethod("Lcom/a/B;", "m", [("Ljava/lang/String;", "length")])]
    payload = _client(methods).api_usage(Path("dummy.apk"), "javax.crypto")
    assert payload["usage"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_api_usage_requires_prefix() -> None:
    client = _client([_FakeMethod("Lcom/a/B;", "m", [])])
    with pytest.raises(ApkError) as excinfo:
        client.api_usage(Path("dummy.apk"), "   ")
    assert excinfo.value.code == "invalid_params"


def test_api_usage_collect_cap_sets_scan_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hitting the collect cap flags scan_capped rather than silently truncating."""
    monkeypatch.setattr(apk_client, "_MAX_API_USAGE_COLLECT", 2)
    methods = [
        _FakeMethod(f"Lcom/example/C{index};", "m", [("Ljavax/crypto/Cipher;", "doFinal")])
        for index in range(5)
    ]
    payload = _client(methods).api_usage(Path("dummy.apk"), "javax.crypto")
    assert payload["scan_capped"] is True
    assert payload["total"] == 2


def test_api_usage_edge_budget_sets_scan_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exhausting the edge budget before finding matches still terminates cleanly."""
    monkeypatch.setattr(apk_client, "_MAX_XREF_EDGES", 3)
    methods = [
        _FakeMethod(f"Lcom/example/C{index};", "m", [("Ljava/lang/String;", "length")])
        for index in range(10)
    ]
    payload = _client(methods).api_usage(Path("dummy.apk"), "javax.crypto")
    assert payload["scan_capped"] is True
    assert payload["usage"] == []


def test_api_usage_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.api_usage")
    assert "caller_class" in doc
    assert "callee_class" in doc
    assert "prefix" in doc
