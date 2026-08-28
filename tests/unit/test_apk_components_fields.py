"""apk.components descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient
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


class _FakeApk:
    def get_activities(self) -> list[str]:
        return [f"A{index}" for index in range(300)]

    def get_services(self) -> list[str]:
        return ["S"]

    def get_receivers(self) -> list[str]:
        return ["R"]

    def get_providers(self) -> list[str]:
        return ["P"]

    def get_main_activity(self) -> str:
        return "A0"


_MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.comp">
  <application>
    <activity android:name=".ExplicitExported" android:exported="true"/>
    <activity android:name=".ExplicitPrivate" android:exported="false"/>
    <activity android:name=".ImplicitViaFilter">
      <intent-filter><action android:name="android.intent.action.MAIN"/></intent-filter>
    </activity>
    <activity android:name=".PlainPrivate"/>
    <activity-alias android:name=".Alias" android:exported="true"/>
    <service android:name="com.other.ExportedService" android:exported="true"/>
    <receiver android:name=".FilterReceiver">
      <intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter>
    </receiver>
    <provider android:name=".PlainProvider" android:exported="false"/>
  </application>
</manifest>
"""


class _ManifestApk(_FakeApk):
    """A fake whose manifest XML drives exported-component detection."""

    def get_package(self) -> str:
        return "com.example.comp"

    def get_android_manifest_xml(self) -> object:
        from lxml import etree

        return etree.fromstring(_MANIFEST_XML.encode("utf-8"))


def test_apk_components_names_the_four_lists_not_components() -> None:
    """The catalog never named the payload or the cap.

    Measured: 300 activities, cap 256 -> 256 activities, has_more True.
    There is no components field. Looking for components after a successful
    call reads as no UI entry points, and a full 256 list with no has_more
    reads as every activity.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    assert "components" not in payload
    assert len(payload["activities"]) == 256
    assert payload["has_more"] is True
    assert payload["main_activity"] == "A0"
    assert payload["services"] == ["S"]
    # A fake with no readable manifest degrades to an empty exported list, not
    # an error, so the field is always present.
    assert payload["exported"] == []
    assert payload["exported_count"] == 0
    doc = _tool_docstring("apk.components")
    assert "Answers with activities" in doc
    assert "has_more" in doc
    assert "main_activity" in doc


def test_apk_components_lists_exported_attack_surface() -> None:
    """exported names the components another app can reach: explicit
    exported=true and intent-filtered-without-exported=false, resolved to full
    class names; explicit false, plain-private and (here) the private provider
    are excluded."""
    client = ApkClient()
    client._apk = lambda _path: _ManifestApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    assert set(payload["exported"]) == {
        "com.example.comp.ExplicitExported",
        "com.example.comp.ImplicitViaFilter",
        "com.example.comp.Alias",
        "com.other.ExportedService",
        "com.example.comp.FilterReceiver",
    }
    assert payload["exported_count"] == 5
    # The risky ones are named; the safe ones are not.
    assert "com.example.comp.ExplicitPrivate" not in payload["exported"]
    assert "com.example.comp.PlainPrivate" not in payload["exported"]
    assert "com.example.comp.PlainProvider" not in payload["exported"]
    # exported is sorted for a stable read.
    assert payload["exported"] == sorted(payload["exported"])
    doc = _tool_docstring("apk.components")
    assert "exported" in doc
