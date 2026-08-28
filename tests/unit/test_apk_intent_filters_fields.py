"""apk.intent_filters enumerates the actions/categories/data each component routes.

Like the other apk.* field tests it mocks the cheap _apk (manifest-only) parse,
so it needs no androguard or JRE. It pins the walk on a hand-written manifest:
actions/categories/data extraction, the fixed <data> shape, the owner's
resolved exported flag, activity-alias handling, per-list clipping, pagination,
malformed-XML truncation and the manifest-decode error, plus the tool docstring.
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
    <activity android:name=".Deep" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.com" android:path="/open"/>
        <data android:scheme="app"/>
      </intent-filter>
    </activity>
    <activity android:name=".Internal" android:exported="false">
      <intent-filter>
        <action android:name="com.example.INTERNAL"/>
      </intent-filter>
    </activity>
    <activity android:name=".Plain"/>
    <activity-alias android:name=".Alias" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity-alias>
    <service android:name=".Svc">
      <intent-filter>
        <action android:name="com.example.BIND"/>
      </intent-filter>
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


def _by_component(payload: dict) -> dict[str, dict]:
    return {row["component"]: row for row in payload["filters"]}


def test_extracts_actions_categories_and_data() -> None:
    payload = _client(_FakeApk()).intent_filters(Path("dummy.apk"))
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False
    rows = _by_component(payload)

    deep = rows["com.example.app.Deep"]
    assert deep["type"] == "activity"
    assert deep["exported"] is True
    assert deep["actions"] == ["android.intent.action.VIEW"]
    assert deep["categories"] == [
        "android.intent.category.DEFAULT",
        "android.intent.category.BROWSABLE",
    ]
    assert deep["data"] == [
        {
            "scheme": "https",
            "host": "example.com",
            "port": None,
            "path": "/open",
            "pathPrefix": None,
            "pathPattern": None,
            "mimeType": None,
        },
        {
            "scheme": "app",
            "host": None,
            "port": None,
            "path": None,
            "pathPrefix": None,
            "pathPattern": None,
            "mimeType": None,
        },
    ]


def test_exported_flag_reflects_the_owner() -> None:
    rows = _by_component(_client(_FakeApk()).intent_filters(Path("d")))
    # Explicit exported="false" owner: the filter is present but not reachable.
    assert rows["com.example.app.Internal"]["exported"] is False
    # A service with a filter and no exported attr is implicitly exported.
    assert rows["com.example.app.Svc"]["exported"] is True
    # activity-alias folds into the activity type and keeps its exported flag.
    assert rows["com.example.app.Alias"]["type"] == "activity"
    assert rows["com.example.app.Alias"]["exported"] is True


def test_components_without_a_filter_are_absent() -> None:
    payload = _client(_FakeApk()).intent_filters(Path("d"))
    assert "com.example.app.Plain" not in _by_component(payload)
    # Deep, Internal, Alias, Svc each contribute exactly one filter row.
    assert payload["total"] == 4


def test_pagination_windows_the_filters() -> None:
    first = _client(_FakeApk()).intent_filters(Path("d"), offset=0, limit=2)
    assert first["count"] == 2
    assert first["total"] == 4
    assert first["has_more"] is True
    tail = _client(_FakeApk()).intent_filters(Path("d"), offset=2, limit=2)
    assert tail["count"] == 2
    assert tail["has_more"] is False


def test_long_action_list_is_clipped_with_scan_capped() -> None:
    actions = "".join(f'<action android:name="a{i}"/>' for i in range(300))
    xml = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.example.app"><application>'
        b'<activity android:name=".A" android:exported="true"><intent-filter>'
        + actions.encode()
        + b"</intent-filter></activity></application></manifest>"
    )
    payload = _client(_FakeApk(xml)).intent_filters(Path("d"))
    row = payload["filters"][0]
    assert len(row["actions"]) == 256
    assert payload["scan_capped"] is True


def test_malformed_manifest_sets_truncated() -> None:
    payload = _client(_FakeApk(b"<manifest><application><activity")).intent_filters(Path("d"))
    assert payload["truncated"] is True
    assert payload["filters"] == []
    assert payload["total"] == 0


def test_manifest_decode_failure_is_backend_error() -> None:
    with pytest.raises(ApkError) as info:
        _client(_FakeApk(raise_axml=True)).intent_filters(Path("d"))
    assert info.value.code == "backend_error"


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.intent_filters")
    assert "Answers with filters" in doc
    assert "actions" in doc and "categories" in doc and "data" in doc
    assert "exported" in doc
    assert "has_more" in doc
