"""apk.exported_components surfaces the manifest's exported attack surface.

Like the other apk.* field tests it mocks the cheap _apk (manifest-only) parse,
so it needs no androguard or JRE. It pins the exported-derivation rule on a
hand-written AndroidManifest: explicit true/false, intent-filter inference,
the provider API-17 default, activity-alias handling, name resolution, the
permission and exported_declared evidence, pagination, the malformed-XML
truncation and the manifest-decode error, plus the tool docstring.
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
    <activity android:name=".Main" android:exported="true"/>
    <activity android:name="com.example.app.Hidden" android:exported="false">
      <intent-filter/>
    </activity>
    <activity android:name="Implicit">
      <intent-filter/>
    </activity>
    <activity android:name=".Internal"/>
    <activity-alias android:name=".Alias" android:exported="true"/>
    <service android:name=".Svc" android:exported="true"
             android:permission="com.example.PERM"/>
    <receiver android:name=".Rcv">
      <intent-filter/>
    </receiver>
    <provider android:name=".Prov"/>
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
        self,
        xml: bytes = _MANIFEST,
        *,
        target: str = "14",
        package: str = "com.example.app",
        raise_axml: bool = False,
    ) -> None:
        self._xml = xml
        self._target = target
        self._package = package
        self._raise_axml = raise_axml

    def get_package(self) -> str:
        return self._package

    def get_target_sdk_version(self) -> str:
        return self._target

    def get_android_manifest_axml(self) -> _Axml:
        return _Axml(self._xml, raise_exc=self._raise_axml)


def _client(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def test_lists_exported_and_resolves_names() -> None:
    payload = _client(_FakeApk()).exported_components(Path("dummy.apk"))
    names = {row["name"] for row in payload["exported"]}
    assert names == {
        "com.example.app.Main",
        "com.example.app.Implicit",
        "com.example.app.Alias",
        "com.example.app.Svc",
        "com.example.app.Rcv",
        "com.example.app.Prov",
    }
    # Explicit exported="false" is not exported even with an intent-filter, and a
    # component with neither exported nor an intent-filter is private.
    assert "com.example.app.Hidden" not in names
    assert "com.example.app.Internal" not in names
    assert payload["total"] == 6
    assert payload["counts"] == {"activity": 3, "service": 1, "receiver": 1, "provider": 1}
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_evidence_fields_are_carried_per_row() -> None:
    rows = {
        row["name"]: row for row in _client(_FakeApk()).exported_components(Path("d"))["exported"]
    }
    main = rows["com.example.app.Main"]
    assert main["type"] == "activity"
    assert main["exported_declared"] == "true"
    assert main["has_intent_filter"] is False
    assert main["permission"] is None

    implicit = rows["com.example.app.Implicit"]
    assert implicit["exported_declared"] is None  # inferred from the intent-filter
    assert implicit["has_intent_filter"] is True

    svc = rows["com.example.app.Svc"]
    assert svc["type"] == "service"
    assert svc["permission"] == "com.example.PERM"

    # activity-alias folds into the activity type.
    assert rows["com.example.app.Alias"]["type"] == "activity"


def test_provider_default_follows_target_sdk() -> None:
    modern = _client(_FakeApk(target="30")).exported_components(Path("d"))
    names = {row["name"] for row in modern["exported"]}
    assert "com.example.app.Prov" not in names
    assert modern["counts"]["provider"] == 0
    assert modern["total"] == 5


def test_unknown_target_sdk_keeps_default_provider_private() -> None:
    payload = _client(_FakeApk(target="not-a-number")).exported_components(Path("d"))
    assert "com.example.app.Prov" not in {row["name"] for row in payload["exported"]}


def test_pagination_windows_the_surface() -> None:
    first = _client(_FakeApk()).exported_components(Path("d"), offset=0, limit=4)
    assert first["count"] == 4
    assert first["total"] == 6
    assert first["has_more"] is True
    tail = _client(_FakeApk()).exported_components(Path("d"), offset=4, limit=4)
    assert tail["count"] == 2
    assert tail["has_more"] is False


def test_malformed_manifest_sets_truncated() -> None:
    payload = _client(_FakeApk(b"<manifest><application><activity")).exported_components(Path("d"))
    assert payload["truncated"] is True
    assert payload["exported"] == []
    assert payload["total"] == 0


def test_manifest_decode_failure_is_backend_error() -> None:
    with pytest.raises(ApkError) as info:
        _client(_FakeApk(raise_axml=True)).exported_components(Path("d"))
    assert info.value.code == "backend_error"


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("apk.exported_components")
    assert "Answers with exported" in doc
    assert "counts" in doc
    assert "permission" in doc
    assert "exported_declared" in doc
    assert "has_intent_filter" in doc
    assert "has_more" in doc
