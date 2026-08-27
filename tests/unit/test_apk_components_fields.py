"""apk.components descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from lxml import etree

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
    # A fake with no manifest accessor degrades to no exported list, not an error.
    assert payload["exported"] == []
    assert payload["exported_count"] == 0
    doc = _tool_docstring("apk.components")
    assert "Answers with activities" in doc
    assert "has_more" in doc
    assert "main_activity" in doc
    assert "exported" in doc


_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.x">
  <application>
    <activity android:name=".Main">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <activity android:name=".Internal"/>
    <activity android:name=".Explicit" android:exported="false">
      <intent-filter><action android:name="a"/></intent-filter>
    </activity>
    <service android:name=".Svc" android:exported="true"
             android:permission="com.x.PERM"/>
    <receiver android:name=".Rcv">
      <intent-filter><action android:name="b"/></intent-filter>
    </receiver>
    <provider android:name=".Prov" android:authorities="com.x.p"/>
  </application>
</manifest>
"""


class _ManifestApk(_FakeApk):
    """Like androguard: get_android_manifest_xml returns a parsed lxml tree."""

    def __init__(self, target_sdk: int) -> None:
        self._target = target_sdk

    def get_android_manifest_xml(self) -> etree._Element:
        return etree.fromstring(_MANIFEST)

    def get_target_sdk_version(self) -> int:
        return self._target


def test_apk_components_flags_the_external_attack_surface() -> None:
    """Exported = explicit true, or the implicit intent-filter rule when absent.

    Target SDK 30 so the unguarded provider is not exported by default. Main
    (intent-filter, implicit) and Rcv (intent-filter, implicit) and Svc
    (explicit true) are reachable; Internal (no filter), Explicit (exported
    false despite a filter) and Prov (provider, modern target) are not.
    """
    client = ApkClient()
    client._apk = lambda _path: _ManifestApk(30)  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    exported = payload["exported"]
    assert payload["exported_count"] == 3
    assert exported == [
        {"type": "activity", "name": ".Main", "permission": None},
        {"type": "receiver", "name": ".Rcv", "permission": None},
        {"type": "service", "name": ".Svc", "permission": "com.x.PERM"},
    ]


def test_apk_components_exports_a_provider_only_on_a_pre_api_17_target() -> None:
    """A provider with no explicit android:exported defaulted to exported < API 17."""
    client = ApkClient()
    client._apk = lambda _path: _ManifestApk(14)  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    provider = [c for c in payload["exported"] if c["type"] == "provider"]
    assert provider == [{"type": "provider", "name": ".Prov", "permission": None}]
