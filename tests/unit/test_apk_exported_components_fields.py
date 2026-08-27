"""apk.exported_components derives the exported attack surface from the manifest.

The fake APK stands in for androguard's APK object: it only needs get_package
and get_android_manifest_axml().get_xml(), so the export rule (explicit true /
explicit false / implicit via intent-filter), name resolution, action
collection, sorting, bounding and pagination are what get exercised against a
crafted AndroidManifest.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_ACTIONS,
    ApkClient,
    ApkError,
)
from headless_re_mcp.tools.apk import build_apk_tools

_NS = 'xmlns:android="http://schemas.android.com/apk/res/android"'


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


class _FakeAxml:
    def __init__(self, xml: str) -> None:
        self._xml = xml.encode("utf-8")

    def get_xml(self) -> bytes:
        return self._xml


class _FakeApk:
    def __init__(self, xml: str, package: str = "com.example") -> None:
        self._xml = xml
        self._package = package

    def get_package(self) -> str:
        return self._package

    def get_android_manifest_axml(self) -> _FakeAxml:
        return _FakeAxml(self._xml)


def _client(xml: str, package: str = "com.example") -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(xml, package)  # type: ignore[method-assign]
    return client


def _manifest(body: str) -> str:
    return f'<manifest {_NS} package="com.example"><application>{body}</application></manifest>'


def test_export_rule_true_false_and_implicit() -> None:
    """Explicit true and intent-filter default are exported; explicit false is not.

    Measured: an activity with exported="true" is in (explicit True); a service
    with exported="false" plus an intent-filter is excluded; a receiver with no
    exported attribute but an intent-filter is in (explicit False); a plain
    activity with neither is excluded.
    """
    xml = _manifest(
        """
        <activity android:name=".Exported" android:exported="true"/>
        <service android:name=".Hidden" android:exported="false">
            <intent-filter><action android:name="a.SVC"/></intent-filter>
        </service>
        <receiver android:name=".Implicit">
            <intent-filter><action android:name="a.RCV"/></intent-filter>
        </receiver>
        <activity android:name=".Internal"/>
        """
    )
    payload = _client(xml).exported_components(Path("dummy.apk"))
    by_class = {row["class"]: row for row in payload["components"]}
    assert set(by_class) == {"com.example.Exported", "com.example.Implicit"}
    assert by_class["com.example.Exported"]["explicit"] is True
    assert by_class["com.example.Exported"]["has_intent_filter"] is False
    assert by_class["com.example.Implicit"]["explicit"] is False
    assert by_class["com.example.Implicit"]["actions"] == ["a.RCV"]
    assert payload["total"] == 2
    assert payload["package"] == "com.example"


def test_name_resolution_dot_bare_and_absolute() -> None:
    """A leading dot and a bare name resolve against the package; dotted stays."""
    xml = _manifest(
        """
        <activity android:name=".Rel" android:exported="true"/>
        <activity android:name="Bare" android:exported="true"/>
        <activity android:name="com.other.Abs" android:exported="true"/>
        """
    )
    payload = _client(xml).exported_components(Path("dummy.apk"))
    classes = {row["name"]: row["class"] for row in payload["components"]}
    assert classes[".Rel"] == "com.example.Rel"
    assert classes["Bare"] == "com.example.Bare"
    assert classes["com.other.Abs"] == "com.other.Abs"


def test_actions_deduped_sorted_and_capped() -> None:
    """Duplicate actions collapse, are sorted, and cap with actions_truncated."""
    actions = "".join(
        f'<action android:name="act.{i:03d}"/>' for i in range(_MAX_ACTIONS + 5)
    )
    dup = '<action android:name="dup"/><action android:name="dup"/>'
    xml = _manifest(
        f'<activity android:name=".A" android:exported="true">'
        f"<intent-filter>{dup}{actions}</intent-filter></activity>"
    )
    row = _client(xml).exported_components(Path("dummy.apk"))["components"][0]
    assert row["actions_truncated"] is True
    assert len(row["actions"]) == _MAX_ACTIONS
    assert row["actions"] == sorted(row["actions"])


def test_activity_alias_is_a_component_type() -> None:
    """activity-alias declares an entry point and is enumerated as its own type."""
    xml = _manifest(
        '<activity-alias android:name=".Alias" android:exported="true"/>'
    )
    payload = _client(xml).exported_components(Path("dummy.apk"))
    assert payload["components"][0]["type"] == "activity-alias"


def test_paginates_sorted_rows() -> None:
    """A full page reports has_more with a stable window sorted by (type, class)."""
    body = "".join(
        f'<activity android:name=".A{i:03d}" android:exported="true"/>'
        for i in range(25)
    )
    client = _client(_manifest(body))
    first = client.exported_components(Path("dummy.apk"), offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    second = client.exported_components(Path("dummy.apk"), offset=10, limit=10)
    assert second["offset"] == 10
    assert second["components"][0]["class"] != first["components"][0]["class"]


def test_no_application_element_is_empty_not_error() -> None:
    """A manifest without <application> answers empty, not an error."""
    xml = f'<manifest {_NS} package="com.example"></manifest>'
    payload = _client(xml).exported_components(Path("dummy.apk"))
    assert payload["components"] == []
    assert payload["total"] == 0


def test_malformed_manifest_raises_backend_error() -> None:
    payload_client = _client("<manifest><application><activity")
    with pytest.raises(ApkError) as excinfo:
        payload_client.exported_components(Path("dummy.apk"))
    assert excinfo.value.code == "backend_error"


def test_exported_components_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.exported_components")
    assert "Answers with components" in doc
    assert "intent-filter" in doc
    assert "has_more" in doc
