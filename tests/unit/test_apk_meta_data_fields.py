"""apk.meta_data lifts <meta-data> from the manifest with its enclosing scope.

Driven through the _apk seam with a fake APK whose get_android_manifest_xml
returns a real lxml tree parsed from a manifest snippet, so the namespace and
parent-walk logic is exercised for real.
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
  <application android:name="com.example.App">
    <meta-data android:name="com.google.android.geo.API_KEY"
               android:value="AIzaSyABC-secret"/>
    <meta-data android:name="com.google.android.gms.version"
               android:resource="@integer/google_play_services_version"/>
    <activity android:name="com.example.LoginActivity">
      <meta-data android:name="scoped.flag" android:value="true"/>
    </activity>
    <service android:name="com.example.SyncService">
      <meta-data android:name="io.sdk.app_id" android:value="app-42"/>
    </service>
  </application>
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


def test_meta_data_lifts_entries_with_scope() -> None:
    payload = _client_with(_MANIFEST).meta_data(Path("d.apk"))
    assert payload["total"] == 4
    assert payload["count"] == 4
    assert payload["has_more"] is False

    by_name = {row["name"]: row for row in payload["meta_data"]}

    geo = by_name["com.google.android.geo.API_KEY"]
    assert geo["value"] == "AIzaSyABC-secret"
    assert geo["resource"] is None
    assert geo["scope"] == "application"
    assert geo["scope_name"] == "com.example.App"

    gms = by_name["com.google.android.gms.version"]
    assert gms["value"] is None
    assert gms["resource"] == "@integer/google_play_services_version"


def test_meta_data_records_the_enclosing_component() -> None:
    payload = _client_with(_MANIFEST).meta_data(Path("d.apk"))
    by_name = {row["name"]: row for row in payload["meta_data"]}

    flag = by_name["scoped.flag"]
    assert flag["scope"] == "activity"
    assert flag["scope_name"] == "com.example.LoginActivity"

    app_id = by_name["io.sdk.app_id"]
    assert app_id["scope"] == "service"
    assert app_id["scope_name"] == "com.example.SyncService"


def test_meta_data_handles_a_missing_manifest() -> None:
    payload = _client_with(None).meta_data(Path("d.apk"))
    assert payload == {"meta_data": [], "count": 0, "total": 0, "has_more": False}


def test_meta_data_on_a_manifest_with_no_meta_data() -> None:
    bare = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        ' package="com.x"><application/></manifest>'
    )
    payload = _client_with(bare).meta_data(Path("d.apk"))
    assert payload["total"] == 0
    assert payload["meta_data"] == []


def test_apk_meta_data_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.meta_data")
    assert "scope" in doc
    assert "resource" in doc
    assert "has_more" in doc
