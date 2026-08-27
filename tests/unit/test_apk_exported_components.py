"""apk.components must surface the exported subset -- the Android attack surface.

The exported determination is computed from the decoded manifest tree, so these
drive ApkClient.components with a fake APK whose get_android_manifest_xml returns a
crafted lxml manifest and assert only the reachable components land in exported.
"""

from __future__ import annotations

from pathlib import Path

from lxml import etree

from headless_re_mcp.backends.apk.client import (
    ApkClient,
    _component_is_exported,
    _resolve_component_name,
)

_MANIFEST = b"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.example.app">
  <application>
    <activity android:name=".Explicit" android:exported="true"/>
    <activity android:name=".Implicit">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
      </intent-filter>
    </activity>
    <activity android:name=".FilteredButDenied" android:exported="false">
      <intent-filter>
        <action android:name="com.example.app.CUSTOM"/>
      </intent-filter>
    </activity>
    <activity android:name="com.example.app.Internal"/>
    <service android:name=".ExportedService" android:exported="true"/>
    <service android:name=".QuietService"/>
    <receiver android:name=".QuietReceiver"/>
    <provider android:name=".OpenProvider" android:exported="true"/>
  </application>
</manifest>
"""


class _FakeApk:
    def __init__(self, manifest: bytes = _MANIFEST) -> None:
        self._root = etree.fromstring(manifest)

    def get_android_manifest_xml(self) -> object:
        return self._root

    def get_package(self) -> str:
        return "com.example.app"

    def get_activities(self) -> list[str]:
        return [
            "com.example.app.Explicit",
            "com.example.app.Implicit",
            "com.example.app.FilteredButDenied",
            "com.example.app.Internal",
        ]

    def get_services(self) -> list[str]:
        return ["com.example.app.ExportedService", "com.example.app.QuietService"]

    def get_receivers(self) -> list[str]:
        return ["com.example.app.QuietReceiver"]

    def get_providers(self) -> list[str]:
        return ["com.example.app.OpenProvider"]

    def get_main_activity(self) -> str:
        return "com.example.app.Explicit"


class _NoManifestApk(_FakeApk):
    def get_android_manifest_xml(self) -> object:
        raise RuntimeError("manifest will not decode")


def _components() -> dict[str, object]:
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    return client.components(Path("dummy.apk"))


def test_explicit_true_and_implicit_filter_are_exported() -> None:
    exported = _components()["exported"]
    assert isinstance(exported, dict)
    # Explicit exported="true" and the unset+intent-filter activity both count;
    # the FQNs line up with the flat activities list, not the .shorthand names.
    assert exported["activities"] == [
        "com.example.app.Explicit",
        "com.example.app.Implicit",
    ]


def test_explicit_false_beats_an_intent_filter() -> None:
    exported = _components()["exported"]
    # A component that declares a filter but sets exported="false" is closed:
    # the explicit attribute wins over the implicit-export rule.
    assert "com.example.app.FilteredButDenied" not in exported["activities"]


def test_unset_without_a_filter_is_not_exported() -> None:
    exported = _components()["exported"]
    assert "com.example.app.Internal" not in exported["activities"]
    assert exported["receivers"] == []
    assert "com.example.app.QuietService" not in exported["services"]


def test_services_and_providers_are_grouped_by_kind() -> None:
    exported = _components()["exported"]
    assert exported["services"] == ["com.example.app.ExportedService"]
    assert exported["providers"] == ["com.example.app.OpenProvider"]


def test_exported_names_are_a_subset_of_the_flat_lists() -> None:
    payload = _components()
    exported = payload["exported"]
    assert isinstance(exported, dict)
    for key in ("activities", "services", "receivers", "providers"):
        assert set(exported[key]) <= set(payload[key]), key


def test_exported_degrades_to_empty_groups_when_manifest_will_not_parse() -> None:
    client = ApkClient()
    client._apk = lambda _path: _NoManifestApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    # A manifest that raises must not fail components(); the flat lists still come
    # from androguard, and exported degrades to empty groups rather than vanishing.
    assert payload["exported"] == {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    assert payload["activities"]


def test_resolve_component_name_matches_android_rules() -> None:
    assert _resolve_component_name("com.x", ".Main") == "com.x.Main"
    assert _resolve_component_name("com.x", "Main") == "com.x.Main"
    assert _resolve_component_name("com.x", "com.y.Main") == "com.y.Main"
    assert _resolve_component_name("com.x", "") == ""


def test_component_is_exported_rules() -> None:
    assert _component_is_exported("true", False) is True
    assert _component_is_exported("false", True) is False
    assert _component_is_exported(None, True) is True
    assert _component_is_exported(None, False) is False
    # Casing/whitespace on the declared attribute is tolerated.
    assert _component_is_exported(" TRUE ", False) is True
