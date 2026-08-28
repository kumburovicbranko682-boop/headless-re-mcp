"""apk.deep_links distills the manifest's VIEW filters into testable URIs.

Like the other apk.* field tests it mocks the cheap _apk (manifest-only) parse,
so it needs no androguard or JRE. It pins the distillation on a hand-written
manifest: the VIEW-plus-scheme qualification, the scheme/host/path cross
product, URI assembly, the browsable/auto_verify/exported flags, path_kind,
non-VIEW and scheme-less filters being dropped, the per-filter clip, pagination,
malformed-XML truncation and the decode error, plus the tool docstring.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
from headless_re_mcp.tools.apk import build_apk_tools

_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app">
  <application>
    <activity android:name=".Web" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https"/>
        <data android:host="example.com"/>
        <data android:pathPrefix="/user"/>
      </intent-filter>
    </activity>
    <activity android:name=".Custom" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="myapp" android:host="open"/>
      </intent-filter>
    </activity>
    <activity android:name=".NotView" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <data android:scheme="https" android:host="ignored.example"/>
      </intent-filter>
    </activity>
    <activity android:name=".MimeOnly" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:mimeType="image/png"/>
      </intent-filter>
    </activity>
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


class _Axml:
    def __init__(self, xml: bytes, *, raise_exc: bool = False) -> None:
        self._xml = xml
        self._raise = raise_exc

    def get_xml(self) -> bytes:
        if self._raise:
            raise RuntimeError("axml decode failed")
        return self._xml


class _FakeApk:
    def __init__(
        self, xml: bytes = _MANIFEST, *, target: str = "30", raise_axml: bool = False
    ) -> None:
        self._xml = xml
        self._target = target
        self._raise_axml = raise_axml

    def get_package(self) -> str:
        return "com.example.app"

    def get_target_sdk_version(self) -> str:
        return self._target

    def get_android_manifest_axml(self) -> _Axml:
        return _Axml(self._xml, raise_exc=self._raise_axml)


def _client(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def test_web_link_merges_data_tags_into_one_uri() -> None:
    payload = _client(_FakeApk()).deep_links(Path("dummy.apk"))
    web = [row for row in payload["deep_links"] if row["component"] == "com.example.app.Web"]
    assert len(web) == 1
    row = web[0]
    assert row["uri"] == "https://example.com/user"
    assert row["scheme"] == "https"
    assert row["host"] == "example.com"
    assert row["path"] == "/user"
    assert row["path_kind"] == "prefix"
    assert row["browsable"] is True
    assert row["auto_verify"] is True
    assert row["exported"] is True


def test_custom_scheme_link() -> None:
    rows = _client(_FakeApk()).deep_links(Path("d"))["deep_links"]
    custom = [r for r in rows if r["component"] == "com.example.app.Custom"]
    assert len(custom) == 1
    assert custom[0]["uri"] == "myapp://open"
    assert custom[0]["browsable"] is False
    assert custom[0]["auto_verify"] is False


def test_non_view_and_scheme_less_filters_are_dropped() -> None:
    components = {
        row["component"] for row in _client(_FakeApk()).deep_links(Path("d"))["deep_links"]
    }
    # A MAIN filter is not a deep link even with a data scheme.
    assert "com.example.app.NotView" not in components
    # A VIEW filter with only a mimeType (no scheme) is not a URI deep link.
    assert "com.example.app.MimeOnly" not in components
    assert components == {"com.example.app.Web", "com.example.app.Custom"}


def test_cross_product_of_schemes_and_hosts() -> None:
    xml = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.app"><application>'
        b'<activity android:name=".Multi" android:exported="true"><intent-filter>'
        b'<action android:name="android.intent.action.VIEW"/>'
        b'<data android:scheme="http"/><data android:scheme="https"/>'
        b'<data android:host="a.example"/><data android:host="b.example"/>'
        b"</intent-filter></activity></application></manifest>"
    )
    uris = {row["uri"] for row in _client(_FakeApk(xml)).deep_links(Path("d"))["deep_links"]}
    assert uris == {
        "http://a.example",
        "http://b.example",
        "https://a.example",
        "https://b.example",
    }


def test_per_filter_cross_product_is_clipped() -> None:
    schemes = "".join(f'<data android:scheme="s{i}"/>' for i in range(300))
    xml = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.app"><application>'
        b'<activity android:name=".Big" android:exported="true"><intent-filter>'
        b'<action android:name="android.intent.action.VIEW"/>' + schemes.encode() + b"<data "
        b'android:host="h.example"/></intent-filter></activity></application></manifest>'
    )
    payload = _client(_FakeApk(xml)).deep_links(Path("d"))
    assert payload["total"] == 256
    assert payload["scan_capped"] is True


def test_pagination_windows_the_links() -> None:
    xml = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.app"><application>'
        b'<activity android:name=".M" android:exported="true"><intent-filter>'
        b'<action android:name="android.intent.action.VIEW"/>'
        b'<data android:scheme="https"/>'
        b'<data android:host="a"/><data android:host="b"/><data android:host="c"/>'
        b"</intent-filter></activity></application></manifest>"
    )
    first = _client(_FakeApk(xml)).deep_links(Path("d"), offset=0, limit=2)
    assert first["count"] == 2
    assert first["total"] == 3
    assert first["has_more"] is True
    tail = _client(_FakeApk(xml)).deep_links(Path("d"), offset=2, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False


def test_malformed_manifest_sets_truncated() -> None:
    payload = _client(_FakeApk(b"<manifest><application><activity")).deep_links(Path("d"))
    assert payload["truncated"] is True
    assert payload["deep_links"] == []
    assert payload["total"] == 0


def test_manifest_decode_failure_is_backend_error() -> None:
    with pytest.raises(ApkError) as info:
        _client(_FakeApk(raise_axml=True)).deep_links(Path("d"))
    assert info.value.code == "backend_error"


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.deep_links")
    assert "Answers with deep_links" in doc
    assert "uri" in doc and "path_kind" in doc
    assert "browsable" in doc and "auto_verify" in doc
    assert "has_more" in doc
