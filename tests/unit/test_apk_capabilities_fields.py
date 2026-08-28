"""apk.capabilities fingerprints DEX use of security-relevant platform APIs.

It mocks the parsed analysis with a fake find_methods that replicates
androguard's re.match semantics over a set of external methods, so the real
capability catalog regexes are exercised: detection and call-site counting, the
start/end regex anchoring (System.loadLibrary yes, arraycopy no; getImei yes,
getDeviceIdForSubscription no), the escaped Settings$Secure class, caller dedup
and the 25-caller cap, sorting, graceful degradation, the catalog invariants and
the tool docstring.
"""

from __future__ import annotations

import ast
import re
import types
from pathlib import Path

from headless_re_mcp.backends.apk.client import _APK_CAPABILITY_CATALOG, ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


class _Caller:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name


class _ExternalMethod:
    def __init__(self, class_name: str, name: str, callers: list[tuple[str, str]]) -> None:
        self.class_name = class_name
        self.name = name
        self._callers = callers

    def get_xref_from(self) -> list[tuple[object, _Caller, int]]:
        return [(None, _Caller(cls, mth), 0) for cls, mth in self._callers]


class _RaisingMethod:
    def __init__(self, class_name: str, name: str) -> None:
        self.class_name = class_name
        self.name = name

    def get_xref_from(self) -> list[tuple[object, _Caller, int]]:
        raise RuntimeError("xref lookup failed")


class _FakeAnalysis:
    def __init__(self, methods: list[object]) -> None:
        self._methods = methods

    def find_methods(
        self,
        classname: str = ".*",
        methodname: str = ".*",
        descriptor: str = ".*",
        accessflags: str = ".*",
        no_external: bool = False,
    ):
        for method in self._methods:
            if re.match(classname, method.class_name) and re.match(methodname, method.name):
                yield method


def _client(methods: list[object]) -> ApkClient:
    client = ApkClient()
    parsed = types.SimpleNamespace(analysis=_FakeAnalysis(methods))
    client._parsed = lambda _path: parsed  # type: ignore[method-assign,return-value]
    return client


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


def _row(payload: dict, api: str) -> dict:
    matches = [r for r in payload["capabilities"] if r["api"] == api]
    assert len(matches) == 1, api
    return matches[0]


def test_detects_apis_and_counts_call_sites() -> None:
    methods = [
        _ExternalMethod("Ldalvik/system/DexClassLoader;", "<init>", [("Lcom/app/Loader;", "load")]),
        _ExternalMethod(
            "Ljava/lang/Runtime;", "exec", [("Lcom/app/Sh;", "run"), ("Lcom/app/Sh;", "run2")]
        ),
    ]
    payload = _client(methods).capabilities(Path("d.apk"))
    assert payload["count"] == 2
    assert payload["categories"] == ["dynamic_code", "process_exec"]
    dex = _row(payload, "DexClassLoader")
    assert dex["category"] == "dynamic_code"
    assert dex["call_sites"] == 1
    assert dex["callers"] == [{"class": "Lcom/app/Loader;", "method": "load"}]
    exec_row = _row(payload, "Runtime.exec")
    assert exec_row["category"] == "process_exec"
    assert exec_row["call_sites"] == 2


def test_rows_sorted_by_call_sites_desc() -> None:
    methods = [
        _ExternalMethod("Ldalvik/system/DexClassLoader;", "<init>", [("La;", "m")]),
        _ExternalMethod("Ljava/lang/Runtime;", "exec", [("Lb;", "m"), ("Lc;", "m")]),
    ]
    apis = [row["api"] for row in _client(methods).capabilities(Path("d"))["capabilities"]]
    assert apis == ["Runtime.exec", "DexClassLoader"]


def test_method_regex_is_end_anchored() -> None:
    methods = [
        _ExternalMethod("Ljava/lang/System;", "arraycopy", [("La;", "m")]),
        _ExternalMethod("Ljava/lang/System;", "loadLibrary", [("La;", "m")]),
    ]
    payload = _client(methods).capabilities(Path("d"))
    # Only load/loadLibrary count; arraycopy on the same class does not.
    assert payload["count"] == 1
    assert _row(payload, "System.load")["call_sites"] == 1


def test_identifier_prefix_does_not_over_match() -> None:
    methods = [
        _ExternalMethod("Landroid/telephony/TelephonyManager;", "getImei", [("La;", "m")]),
        _ExternalMethod(
            "Landroid/telephony/TelephonyManager;",
            "getDeviceIdForSubscription",
            [("La;", "m")],
        ),
    ]
    payload = _client(methods).capabilities(Path("d"))
    # getImei matches; getDeviceIdForSubscription must not (the $ guards getDeviceId).
    assert _row(payload, "TelephonyManager.identifiers")["call_sites"] == 1


def test_escaped_inner_class_matches_settings_secure() -> None:
    methods = [
        _ExternalMethod("Landroid/provider/Settings$Secure;", "getString", [("La;", "m")]),
    ]
    payload = _client(methods).capabilities(Path("d"))
    assert _row(payload, "Settings.Secure.getString")["category"] == "device_identifiers"


def test_callers_are_deduped_and_capped() -> None:
    callers = [(f"Lc/A{i};", "m") for i in range(30)] + [("Lc/A0;", "m")] * 5
    methods = [_ExternalMethod("Ljava/lang/Runtime;", "exec", callers)]
    payload = _client(methods).capabilities(Path("d"))
    row = _row(payload, "Runtime.exec")
    assert row["call_sites"] == 35  # every call site counted
    assert len(row["callers"]) == 25  # distinct callers, capped
    assert payload["scan_capped"] is True


def test_no_matches_returns_empty() -> None:
    methods = [_ExternalMethod("Lcom/app/Harmless;", "doThing", [("La;", "m")])]
    payload = _client(methods).capabilities(Path("d"))
    assert payload["capabilities"] == []
    assert payload["categories"] == []
    assert payload["scan_capped"] is False


def test_xref_failure_is_skipped_gracefully() -> None:
    methods = [_RaisingMethod("Ljava/lang/Runtime;", "exec")]
    payload = _client(methods).capabilities(Path("d"))
    # A method whose xref lookup raises contributes nothing rather than erroring.
    assert payload["capabilities"] == []


def test_catalog_regexes_compile_and_are_well_formed() -> None:
    seen: set[tuple[str, str]] = set()
    for entry in _APK_CAPABILITY_CATALOG:
        assert len(entry) == 4
        category, label, class_re, method_re = entry
        assert category and label
        re.compile(class_re)
        re.compile(method_re)
        key = (category, label)
        assert key not in seen, key
        seen.add(key)


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.capabilities")
    assert "Answers with" in doc
    assert "capabilities" in doc and "categories" in doc
    assert "call_sites" in doc and "callers" in doc
    assert "scan_capped" in doc
