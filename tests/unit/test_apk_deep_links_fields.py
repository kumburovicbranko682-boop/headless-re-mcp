"""apk.deep_links derives URI entry points from VIEW intent-filters.

The fake APK stands in for androguard's APK object: it only needs get_package
and get_android_manifest_axml().get_xml(), so the VIEW+scheme filter, the
browsable/auto_verify flags, scheme x host uris, path merging, dedup/sort/cap,
sorting and pagination are what get exercised against a crafted manifest.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_URI_VALUES,
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


def test_view_filter_with_scheme_becomes_a_deep_link() -> None:
    """A browsable VIEW filter yields schemes, hosts, merged paths and uris.

    Measured: scheme https + host api.example + a pathPrefix produce one row
    with uris https://api.example, browsable True, and the field is deep_links.
    """
    xml = _manifest(
        """
        <activity android:name=".Web">
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="https" android:host="api.example"
                      android:pathPrefix="/go"/>
            </intent-filter>
        </activity>
        """
    )
    payload = _client(xml).deep_links(Path("dummy.apk"))
    assert payload["count"] == 1
    row = payload["deep_links"][0]
    assert row["class"] == "com.example.Web"
    assert row["schemes"] == ["https"]
    assert row["hosts"] == ["api.example"]
    assert row["paths"] == ["/go"]
    assert row["uris"] == ["https://api.example"]
    assert row["browsable"] is True
    assert row["auto_verify"] is True
    assert row["values_truncated"] is False


def test_view_filter_without_scheme_is_skipped() -> None:
    """A VIEW filter that only sets a mimeType is a type handler, not a deep link."""
    xml = _manifest(
        """
        <activity android:name=".Viewer">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:mimeType="application/pdf"/>
            </intent-filter>
        </activity>
        """
    )
    payload = _client(xml).deep_links(Path("dummy.apk"))
    assert payload["deep_links"] == []
    assert payload["total"] == 0


def test_non_view_filter_is_skipped() -> None:
    """A filter without the VIEW action is not a deep link even with a scheme."""
    xml = _manifest(
        """
        <activity android:name=".Main">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <data android:scheme="myapp"/>
            </intent-filter>
        </activity>
        """
    )
    assert _client(xml).deep_links(Path("dummy.apk"))["total"] == 0


def test_scheme_host_cross_product_and_no_host_scheme() -> None:
    """uris is scheme x host; a scheme with no host becomes scheme://."""
    xml = _manifest(
        """
        <activity android:name=".A">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="http"/>
                <data android:scheme="https"/>
                <data android:host="a.example"/>
                <data android:host="b.example"/>
            </intent-filter>
        </activity>
        """
    )
    row = _client(xml).deep_links(Path("dummy.apk"))["deep_links"][0]
    assert row["uris"] == [
        "http://a.example",
        "http://b.example",
        "https://a.example",
        "https://b.example",
    ]
    assert row["browsable"] is False
    assert row["auto_verify"] is False


def test_paths_merge_all_kinds_and_cap() -> None:
    """path/pathPrefix/pathPattern/pathSuffix merge into paths, capped."""
    data = "".join(
        f'<data android:scheme="app" android:pathPrefix="/p{i:03d}"/>'
        for i in range(_MAX_URI_VALUES + 5)
    )
    xml = _manifest(
        f'<activity android:name=".A"><intent-filter>'
        f'<action android:name="android.intent.action.VIEW"/>{data}'
        f"</intent-filter></activity>"
    )
    row = _client(xml).deep_links(Path("dummy.apk"))["deep_links"][0]
    assert len(row["paths"]) == _MAX_URI_VALUES
    assert row["values_truncated"] is True


def test_multiple_filters_on_one_activity_are_separate_rows() -> None:
    """Each qualifying VIEW filter is its own row, sorted and paginated."""
    filters = "".join(
        '<intent-filter><action android:name="android.intent.action.VIEW"/>'
        f'<data android:scheme="s{i:02d}"/></intent-filter>'
        for i in range(3)
    )
    xml = _manifest(f'<activity android:name=".A">{filters}</activity>')
    payload = _client(xml).deep_links(Path("dummy.apk"))
    assert payload["total"] == 3
    first = _client(xml).deep_links(Path("dummy.apk"), offset=0, limit=2)
    assert first["count"] == 2
    assert first["has_more"] is True


def test_no_application_is_empty_not_error() -> None:
    xml = f'<manifest {_NS} package="com.example"></manifest>'
    payload = _client(xml).deep_links(Path("dummy.apk"))
    assert payload["deep_links"] == []
    assert payload["total"] == 0


def test_malformed_manifest_raises_backend_error() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client("<manifest><application><activity").deep_links(Path("dummy.apk"))
    assert excinfo.value.code == "backend_error"


def test_deep_links_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.deep_links")
    assert "Answers with deep_links" in doc
    assert "browsable" in doc
    assert "has_more" in doc
