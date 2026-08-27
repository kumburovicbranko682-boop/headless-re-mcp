"""apk.meta_data gathers <meta-data> entries and their owners from the manifest.

The fake APK stands in for androguard's APK object: it only needs get_package
and get_android_manifest_axml().get_xml(), so value/resource extraction, owner
resolution, value truncation, sorting and pagination are what get exercised
against a crafted manifest.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import (
    _MAX_STRING_LEN,
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


def test_collects_application_and_component_meta_data_with_owner() -> None:
    """meta-data under application and under a component both appear with owner.

    Measured: an application-level key resolves owner application, a component
    -level key resolves owner to the component class and owner_type activity,
    and the field is meta_data carrying name/value/resource.
    """
    xml = _manifest(
        """
        <meta-data android:name="com.google.android.geo.API_KEY" android:value="AIzaSecret"/>
        <activity android:name=".Main">
            <meta-data android:name="sdk.flag" android:resource="@0x7f010001"/>
        </activity>
        """
    )
    payload = _client(xml).meta_data(Path("dummy.apk"))
    by_name = {row["name"]: row for row in payload["meta_data"]}
    assert payload["total"] == 2
    key = by_name["com.google.android.geo.API_KEY"]
    assert key["value"] == "AIzaSecret"
    assert key["resource"] is None
    assert key["owner_type"] == "application"
    assert key["owner"] == "application"
    flag = by_name["sdk.flag"]
    assert flag["value"] is None
    assert flag["resource"] == "@0x7f010001"
    assert flag["owner_type"] == "activity"
    assert flag["owner"] == "com.example.Main"


def test_sorted_by_owner_then_name() -> None:
    """Rows sort by (owner, name) for stable paging."""
    xml = _manifest(
        """
        <meta-data android:name="z.app" android:value="1"/>
        <meta-data android:name="a.app" android:value="2"/>
        """
    )
    names = [row["name"] for row in _client(xml).meta_data(Path("dummy.apk"))["meta_data"]]
    assert names == ["a.app", "z.app"]


def test_long_value_is_truncated_with_flag() -> None:
    """A value over the cap is cut and flagged."""
    big = "x" * (_MAX_STRING_LEN + 50)
    xml = _manifest(f'<meta-data android:name="k" android:value="{big}"/>')
    row = _client(xml).meta_data(Path("dummy.apk"))["meta_data"][0]
    assert len(row["value"]) == _MAX_STRING_LEN
    assert row["value_truncated"] is True


def test_paginates() -> None:
    """A full page reports has_more with a stable window."""
    body = "".join(
        f'<meta-data android:name="k{i:03d}" android:value="{i}"/>' for i in range(25)
    )
    client = _client(_manifest(body))
    first = client.meta_data(Path("dummy.apk"), offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 25
    assert first["has_more"] is True
    second = client.meta_data(Path("dummy.apk"), offset=10, limit=10)
    assert second["offset"] == 10
    assert second["meta_data"][0]["name"] != first["meta_data"][0]["name"]


def test_no_meta_data_is_empty_not_error() -> None:
    xml = _manifest('<activity android:name=".Main"/>')
    payload = _client(xml).meta_data(Path("dummy.apk"))
    assert payload["meta_data"] == []
    assert payload["total"] == 0


def test_malformed_manifest_raises_backend_error() -> None:
    with pytest.raises(ApkError) as excinfo:
        _client("<manifest><application><meta-data").meta_data(Path("dummy.apk"))
    assert excinfo.value.code == "backend_error"


def test_meta_data_docstring_names_shape() -> None:
    doc = _tool_docstring("apk.meta_data")
    assert "Answers with meta_data" in doc
    assert "owner" in doc
    assert "has_more" in doc
