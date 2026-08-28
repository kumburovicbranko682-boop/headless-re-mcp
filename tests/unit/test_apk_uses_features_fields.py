"""apk.uses_features reports the app's declared features and libraries.

Driven through the _apk seam with a fake APK whose get_android_manifest_xml
returns a real lxml tree parsed from a manifest snippet.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from lxml import etree

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app">
  <uses-feature android:name="android.hardware.camera" android:required="true"/>
  <uses-feature android:name="android.hardware.telephony" android:required="false"/>
  <uses-feature android:glEsVersion="0x00020000" android:required="true"/>
  <uses-library android:name="org.apache.http.legacy" android:required="false"/>
  <uses-native-library android:name="libvendor.so"/>
  <application android:label="App"/>
</manifest>
"""


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


class _FakeApk:
    def __init__(self, xml: str | None) -> None:
        self._root = etree.fromstring(xml.encode("utf-8")) if xml else None

    def get_android_manifest_xml(self) -> Any:
        return self._root


def _client_with(xml: str | None) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(xml)  # type: ignore[method-assign]
    return client


def test_uses_features_reports_features_with_required_and_gl_version() -> None:
    payload = _client_with(_MANIFEST).uses_features(Path("d.apk"))
    assert payload["feature_total"] == 3
    assert payload["feature_count"] == 3
    by_name = {f["name"]: f for f in payload["features"]}
    assert by_name["android.hardware.camera"]["required"] is True
    # required=false marks an optional capability.
    assert by_name["android.hardware.telephony"]["required"] is False
    # A glEsVersion feature has no name but carries the version literal.
    gl = next(f for f in payload["features"] if f["name"] is None)
    assert gl["gl_es_version"] == "0x00020000"


def test_uses_features_reports_libraries_and_native_flag() -> None:
    payload = _client_with(_MANIFEST).uses_features(Path("d.apk"))
    assert payload["library_total"] == 2
    by_name = {lib["name"]: lib for lib in payload["libraries"]}
    http = by_name["org.apache.http.legacy"]
    assert http["required"] is False
    assert http["native"] is False
    vendor = by_name["libvendor.so"]
    # A <uses-native-library> with no android:required defaults to required=true.
    assert vendor["required"] is True
    assert vendor["native"] is True


def test_uses_features_on_a_manifest_without_declarations() -> None:
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.example"><application/></manifest>'
    )
    payload = _client_with(manifest).uses_features(Path("d.apk"))
    assert payload["features"] == []
    assert payload["libraries"] == []
    assert payload["has_more"] is False


def test_uses_features_on_a_missing_manifest() -> None:
    payload = _client_with(None).uses_features(Path("d.apk"))
    assert payload["feature_total"] == 0
    assert payload["library_total"] == 0


def test_apk_uses_features_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.uses_features")
    assert "features" in doc
    assert "libraries" in doc
    assert "gl_es_version" in doc
    assert "native" in doc
