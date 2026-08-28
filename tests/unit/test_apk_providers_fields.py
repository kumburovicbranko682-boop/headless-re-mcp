"""apk.providers reports content providers as an attack surface.

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
  <application android:label="App">
    <provider android:name=".LeakProvider"
              android:authorities="com.example.app.leak;com.example.app.alt"
              android:exported="true"
              android:grantUriPermissions="true">
      <grant-uri-permission android:pathPrefix="/shared"/>
      <path-permission android:pathPrefix="/admin"
                       android:readPermission="com.example.perm.READ"/>
    </provider>
    <provider android:name=".SafeProvider"
              android:authorities="com.example.app.safe"
              android:exported="true"
              android:readPermission="com.example.perm.READ"
              android:writePermission="com.example.perm.WRITE"/>
    <provider android:name=".InternalProvider"
              android:authorities="com.example.app.internal"
              android:exported="false"/>
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
    def __init__(self, xml: str | None, *, target_sdk: str | None = "30") -> None:
        self._root = etree.fromstring(xml.encode("utf-8")) if xml else None
        self._target = target_sdk

    def get_android_manifest_xml(self) -> Any:
        return self._root

    def get_target_sdk_version(self) -> str | None:
        return self._target

    def get_min_sdk_version(self) -> str | None:
        return "21"


def _client_with(xml: str | None, *, target_sdk: str | None = "30") -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(xml, target_sdk=target_sdk)  # type: ignore[method-assign]
    return client


def test_providers_report_authorities_and_grants() -> None:
    payload = _client_with(_MANIFEST).providers(Path("d.apk"))
    assert payload["total"] == 3
    by_name = {p["name"]: p for p in payload["providers"]}

    leak = by_name[".LeakProvider"]
    assert leak["authorities"] == ["com.example.app.leak", "com.example.app.alt"]
    assert leak["exported"] is True
    assert leak["effective_exported"] is True
    assert leak["grant_uri_permissions"] is True
    assert leak["grant_uris"][0]["path_prefix"] == "/shared"
    assert leak["guarded"] is False
    pp = leak["path_permissions"][0]
    assert pp["path_prefix"] == "/admin"
    assert pp["read_permission"] == "com.example.perm.READ"


def test_providers_flag_exported_unguarded() -> None:
    payload = _client_with(_MANIFEST).providers(Path("d.apk"))
    # Only LeakProvider is exported with no permission at all.
    assert payload["exported_unguarded"] == 1
    by_name = {p["name"]: p for p in payload["providers"]}
    assert by_name[".SafeProvider"]["guarded"] is True
    assert by_name[".InternalProvider"]["effective_exported"] is False


def test_providers_default_export_follows_target_sdk() -> None:
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        '<application><provider android:name=".P"'
        ' android:authorities="com.example.p"/></application></manifest>'
    )
    # No android:exported. targetSdk 16 (< 17) => default exported true.
    old = _client_with(manifest, target_sdk="16").providers(Path("d.apk"))
    assert old["providers"][0]["exported"] is None
    assert old["providers"][0]["effective_exported"] is True
    # targetSdk 17+ => default exported false.
    new = _client_with(manifest, target_sdk="19").providers(Path("d.apk"))
    assert new["providers"][0]["effective_exported"] is False


def test_providers_on_a_manifest_without_providers() -> None:
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        "<application/></manifest>"
    )
    payload = _client_with(manifest).providers(Path("d.apk"))
    assert payload["providers"] == []
    assert payload["total"] == 0
    assert payload["exported_unguarded"] == 0


def test_providers_on_a_missing_manifest() -> None:
    payload = _client_with(None).providers(Path("d.apk"))
    assert payload["total"] == 0
    assert payload["providers"] == []


def test_apk_providers_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.providers")
    assert "authorities" in doc
    assert "exported_unguarded" in doc
    assert "grant_uri_permissions" in doc
    assert "path_permissions" in doc
