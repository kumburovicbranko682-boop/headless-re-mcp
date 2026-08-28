"""apk.api_usage scans the call graph for sensitive-API usage by category.

The classifier is a pure function over (smali class, method); the roll-up is
driven through a fake analysis mimicking androguard's get_methods() and the
per-method get_xref_from() caller stream.
"""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _classify_api
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


class _Method:
    def __init__(self, class_name: str, name: str, callers: int) -> None:
        self.class_name = class_name
        self.name = name
        self._callers = callers

    def get_xref_from(self) -> list[tuple[object, object, int]]:
        # androguard yields (ClassAnalysis, MethodClassAnalysis, offset); only
        # the count matters here, so the tuple contents are placeholders.
        return [(None, None, i) for i in range(self._callers)]


class _Analysis:
    def __init__(self, methods: list[_Method]) -> None:
        self._methods = methods

    def get_methods(self) -> list[_Method]:
        return self._methods


class _Parsed:
    def __init__(self, analysis: _Analysis) -> None:
        self.analysis = analysis


def _client(methods: list[_Method]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _Parsed(_Analysis(methods))  # type: ignore[method-assign]
    return client


def test_classify_api_maps_signatures_to_categories() -> None:
    assert _classify_api("Ljava/lang/reflect/Method;", "invoke") == "reflection"
    assert _classify_api("Ljava/lang/Class;", "forName") == "reflection"
    assert _classify_api("Ldalvik/system/DexClassLoader;", "<init>") == "dynamic_code"
    assert _classify_api("Ljava/lang/Runtime;", "exec") == "process_exec"
    assert _classify_api("Ljava/lang/System;", "loadLibrary") == "native_load"
    assert _classify_api("Ljavax/crypto/Cipher;", "doFinal") == "crypto"
    assert _classify_api("Landroid/telephony/SmsManager;", "sendTextMessage") == "sms"
    assert _classify_api("Landroid/telephony/TelephonyManager;", "getDeviceId") == "device_id"
    assert _classify_api("Ljava/net/URL;", "openConnection") == "network"


def test_classify_api_ignores_unremarkable_calls() -> None:
    assert _classify_api("Ljava/lang/String;", "length") is None
    assert _classify_api("Landroid/telephony/TelephonyManager;", "getPhoneType") is None
    assert _classify_api("Ljava/lang/Class;", "getSimpleName") is None


def test_api_usage_groups_and_counts_call_sites() -> None:
    methods = [
        _Method("Ljava/lang/reflect/Method;", "invoke", 4),
        _Method("Ljava/lang/Class;", "forName", 2),
        _Method("Ldalvik/system/DexClassLoader;", "<init>", 1),
        _Method("Ljava/lang/String;", "length", 99),  # not sensitive
    ]
    payload = _client(methods).api_usage(Path("d.apk"))

    cats = {c["category"]: c for c in payload["categories"]}
    assert set(cats) == {"reflection", "dynamic_code"}
    # reflection got the most call sites (4 + 2), so it ranks first.
    assert payload["categories"][0]["category"] == "reflection"
    assert cats["reflection"]["hits"] == 6
    assert cats["dynamic_code"]["hits"] == 1
    assert payload["category_count"] == 2
    assert payload["total_call_sites"] == 7
    assert payload["scan_capped"] is False


def test_api_usage_lists_apis_with_dotted_class_and_callers() -> None:
    methods = [
        _Method("Ljavax/crypto/Cipher;", "doFinal", 3),
        _Method("Ljavax/crypto/Cipher;", "getInstance", 5),
    ]
    payload = _client(methods).api_usage(Path("d.apk"))
    crypto = payload["categories"][0]
    assert crypto["category"] == "crypto"
    apis = crypto["apis"]
    # ranked by callers: getInstance(5) before doFinal(3).
    assert apis[0] == {"class": "javax.crypto.Cipher", "method": "getInstance", "callers": 5}
    assert apis[1] == {"class": "javax.crypto.Cipher", "method": "doFinal", "callers": 3}
    assert crypto["api_count"] == 2
    assert crypto["apis_truncated"] is False


def test_api_usage_skips_apis_with_no_call_site() -> None:
    methods = [
        _Method("Ljava/lang/Runtime;", "exec", 0),  # present but never called
        _Method("Ljava/lang/reflect/Field;", "get", 2),
    ]
    payload = _client(methods).api_usage(Path("d.apk"))
    assert {c["category"] for c in payload["categories"]} == {"reflection"}
    assert payload["total_call_sites"] == 2


def test_apk_api_usage_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.api_usage")
    assert "categories" in doc
    assert "total_call_sites" in doc
    assert "reflection" in doc
