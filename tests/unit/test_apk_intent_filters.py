"""apk.intent_filters must surface how components are reached -- the IPC surface.

Like the exported-components test, these drive ApkClient.intent_filters with a
fake APK whose get_android_manifest_xml returns a crafted lxml manifest, so the
real extraction walk (actions/categories/data plus the deep_link heuristic) runs
against a real XML tree rather than a mock of the parser.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from lxml import etree

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools

_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app">
  <application>
    <activity android:name=".DeepLink">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.com" android:path="/open"/>
      </intent-filter>
    </activity>
    <activity android:name=".CustomScheme">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp"/>
      </intent-filter>
    </activity>
    <activity android:name=".MainLauncher">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name=".Denied" android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="secret.example.com"/>
      </intent-filter>
    </activity>
    <activity android:name=".NoFilter"/>
    <receiver android:name=".BootReceiver">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
      </intent-filter>
    </receiver>
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
    def __init__(self, manifest: bytes = _MANIFEST) -> None:
        self._root = etree.fromstring(manifest)

    def get_android_manifest_xml(self) -> object:
        return self._root

    def get_package(self) -> str:
        return "com.example.app"


class _NoManifestApk(_FakeApk):
    def get_android_manifest_xml(self) -> object:
        raise RuntimeError("manifest will not decode")


def _payload(manifest: bytes = _MANIFEST) -> dict[str, Any]:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk(manifest)  # type: ignore[method-assign]
    return client.intent_filters(Path("dummy.apk"))


def _by_name(payload: dict[str, Any], fqn: str) -> dict[str, Any]:
    for component in payload["components"]:
        if component["component"] == fqn:
            return component
    raise AssertionError(f"{fqn} not in {[c['component'] for c in payload['components']]}")


def test_lists_only_components_that_declare_a_filter() -> None:
    """NoFilter has no intent-filter, so it is absent; the other five are listed.

    Measured: five filtered components (four activities + one receiver), total 5,
    and NoFilter never appears -- the tool answers "how is this reached", so a
    component with no filter has nothing to report.
    """
    payload = _payload()
    names = {component["component"] for component in payload["components"]}
    assert "com.example.app.NoFilter" not in names
    assert names == {
        "com.example.app.DeepLink",
        "com.example.app.CustomScheme",
        "com.example.app.MainLauncher",
        "com.example.app.Denied",
        "com.example.app.BootReceiver",
    }
    assert payload["total"] == 5
    assert payload["count"] == 5
    assert payload["has_more"] is False
    assert payload["scan_capped"] is False


def test_deep_link_flag_and_data_attributes_are_read() -> None:
    """A browsable VIEW filter with a scheme is flagged and its data is surfaced.

    Measured: DeepLink's one filter has deep_link True, actions include VIEW,
    categories include BROWSABLE and DEFAULT, and its data names scheme https,
    host example.com and path /open -- the exact strings the manifest declared.
    """
    deep = _by_name(_payload(), "com.example.app.DeepLink")
    assert deep["type"] == "activities"
    assert deep["exported"] is True
    assert len(deep["filters"]) == 1
    flt = deep["filters"][0]
    assert flt["deep_link"] is True
    assert "android.intent.action.VIEW" in flt["actions"]
    assert "android.intent.category.BROWSABLE" in flt["categories"]
    assert "android.intent.category.DEFAULT" in flt["categories"]
    assert flt["data"] == [{"scheme": "https", "host": "example.com", "path": "/open"}]


def test_a_launcher_filter_is_not_a_deep_link() -> None:
    """MAIN/LAUNCHER is an entry point but not a browsable deep link.

    Measured: MainLauncher's filter has deep_link False (no BROWSABLE, no data
    scheme) yet the component is still exported (a filter implies export), so the
    flag distinguishes web-reachable links from ordinary launch/IPC filters.
    """
    launcher = _by_name(_payload(), "com.example.app.MainLauncher")
    assert launcher["exported"] is True
    flt = launcher["filters"][0]
    assert flt["deep_link"] is False
    assert "android.intent.action.MAIN" in flt["actions"]
    assert "android.intent.category.LAUNCHER" in flt["categories"]
    assert flt["data"] == []


def test_exported_false_beats_the_filter_but_the_link_shape_still_shows() -> None:
    """exported="false" closes the component, yet its filter is still reported.

    Measured: Denied has exported False (the explicit attribute wins over the
    implicit-export rule) while its VIEW/BROWSABLE+scheme filter still reads
    deep_link True -- the link shape is a property of the filter, not of export.
    """
    denied = _by_name(_payload(), "com.example.app.Denied")
    assert denied["exported"] is False
    assert denied["filters"][0]["deep_link"] is True
    assert denied["filters"][0]["data"] == [
        {"scheme": "https", "host": "secret.example.com"}
    ]


def test_a_receiver_filter_is_grouped_under_its_kind() -> None:
    """The receiver's boot filter lands under type receivers, not activities."""
    receiver = _by_name(_payload(), "com.example.app.BootReceiver")
    assert receiver["type"] == "receivers"
    assert receiver["exported"] is True
    assert "android.intent.action.BOOT_COMPLETED" in receiver["filters"][0]["actions"]
    assert receiver["filters"][0]["deep_link"] is False


def test_a_manifest_with_no_filters_is_empty_not_missing() -> None:
    """A manifest that declares no intent-filter yields an empty component list."""
    manifest = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android"'
        b' package="com.example.app"><application>'
        b'<activity android:name=".Quiet"/></application></manifest>'
    )
    payload = _payload(manifest)
    assert payload["components"] == []
    assert payload["total"] == 0
    assert payload["has_more"] is False


def test_degrades_to_empty_when_the_manifest_will_not_parse() -> None:
    """A manifest that raises on decode must not fail intent_filters()."""
    client = ApkClient()
    client._apk = lambda _path: _NoManifestApk()  # type: ignore[method-assign]
    payload = client.intent_filters(Path("dummy.apk"))
    assert payload["components"] == []
    assert payload["total"] == 0
    assert payload["scan_capped"] is False


def test_intent_filters_docstring_names_the_fields() -> None:
    doc = _tool_docstring("apk.intent_filters")
    for token in ("components", "deep_link", "data", "exported", "scan_capped"):
        assert token in doc
