"""apk.meta_data must lift <meta-data> pairs with the element that holds them."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import _MAX_META_DATA, ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


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


_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.x">
  <application android:name="com.x.App">
    <meta-data android:name="com.google.android.geo.API_KEY"
               android:value="AIzaSyFIXTURE-key-value"/>
    <meta-data android:name="com.example.sdk.CONFIG"
               android:resource="@xml/sdk_config"/>
    <activity android:name="com.x.Main">
      <meta-data android:name="com.x.activity.flag" android:value="true"/>
    </activity>
    <!-- no android:name: must be skipped, not counted -->
    <meta-data android:value="orphan"/>
  </application>
</manifest>
"""


class _ManifestApk:
    def __init__(self, xml: str) -> None:
        self._xml = xml

    def get_android_manifest_xml(self) -> object:
        from lxml import etree

        return etree.fromstring(self._xml.encode("utf-8"))


def _client(xml: str) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _p: _ManifestApk(xml)  # type: ignore[method-assign]
    return client


def _by_name(entries: list[dict], name: str) -> dict:
    return next(e for e in entries if e["name"] == name)


def test_apk_meta_data_lifts_value_resource_and_scope() -> None:
    """The three real shapes must round-trip: a literal value, a resource ref,
    and one scoped to a component -- with the nameless element skipped."""
    payload = _client(_XML).meta_data(Path("dummy.apk"))

    # Four <meta-data> exist but the nameless one is skipped from both list and
    # total, so a caller never sees an unusable entry.
    assert payload["total"] == payload["count"] == 3
    assert payload["has_more"] is False

    geo = _by_name(payload["meta_data"], "com.google.android.geo.API_KEY")
    assert geo["value"] == "AIzaSyFIXTURE-key-value"
    assert "resource" not in geo
    assert geo["scope"] == "application"
    # Directly under <application>, so no owning component.
    assert geo["component"] is None

    cfg = _by_name(payload["meta_data"], "com.example.sdk.CONFIG")
    # A resource-referencing meta-data carries resource, not value.
    assert cfg["resource"] == "@xml/sdk_config"
    assert "value" not in cfg
    assert cfg["scope"] == "application"

    flag = _by_name(payload["meta_data"], "com.x.activity.flag")
    assert flag["value"] == "true"
    # Scoped to the activity: scope is the tag, component its android:name.
    assert flag["scope"] == "activity"
    assert flag["component"] == "com.x.Main"

    # Manifest order is preserved.
    assert [e["name"] for e in payload["meta_data"]] == [
        "com.google.android.geo.API_KEY",
        "com.example.sdk.CONFIG",
        "com.x.activity.flag",
    ]


def test_apk_meta_data_reports_a_manifest_with_none() -> None:
    bare = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application android:name="com.x.App"><activity android:name="com.x.Main"/></application>
</manifest>
"""
    payload = _client(bare).meta_data(Path("dummy.apk"))
    assert payload["meta_data"] == []
    assert payload["count"] == payload["total"] == 0
    assert payload["has_more"] is False


def test_apk_meta_data_caps_a_padded_manifest() -> None:
    entries = "".join(
        f'<meta-data android:name="k{i:04d}" android:value="v"/>'
        for i in range(_MAX_META_DATA + 5)
    )
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">'
        f"<application android:name=\"com.x.App\">{entries}</application></manifest>"
    )
    payload = _client(xml).meta_data(Path("dummy.apk"))
    assert payload["count"] == _MAX_META_DATA
    assert payload["total"] == _MAX_META_DATA + 5
    assert payload["has_more"] is True


class _UnparseableApk:
    def get_android_manifest_xml(self) -> object:
        raise ValueError("bad AXML")


def test_apk_meta_data_survives_an_unparseable_manifest() -> None:
    client = ApkClient()
    client._apk = lambda _p: _UnparseableApk()  # type: ignore[method-assign]
    payload = client.meta_data(Path("dummy.apk"))
    assert payload["meta_data"] == []
    assert payload["count"] == payload["total"] == 0


def test_apk_meta_data_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.meta_data")
    assert doc, "apk.meta_data is missing its docstring"
    assert "value" in doc
    assert "resource" in doc
    assert "scope" in doc
    assert "component" in doc
    assert "has_more" in doc
