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
    assert payload["exported_unprotected"] == []
    assert payload["exported_unprotected_count"] == 0
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
    # None of these carry a permission, so every exported one is unprotected.
    assert set(payload["exported_unprotected"]) == set(payload["exported"])
    assert payload["exported_unprotected_count"] == 5
    doc = _tool_docstring("apk.components")
    assert "exported" in doc


_GUARD_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.guard">
  <application>
    <activity android:name=".Guarded" android:exported="true"
        android:permission="com.example.guard.permission.SECRET"/>
    <activity android:name=".Open" android:exported="true"/>
    <activity android:name=".OpenViaFilter">
      <intent-filter><action android:name="android.intent.action.VIEW"/></intent-filter>
    </activity>
    <service android:name=".OpenService" android:exported="true"/>
    <provider android:name=".ReadGuardedProvider" android:exported="true"
        android:authorities="com.example.guard.r"
        android:readPermission="com.example.guard.permission.READ"/>
    <provider android:name=".OpenProvider" android:exported="true"
        android:authorities="com.example.guard.o"/>
  </application>
</manifest>
"""

_APPPERM_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.appperm">
  <application android:permission="com.example.appperm.permission.APP">
    <activity android:name=".InheritsAppPerm" android:exported="true"/>
    <activity android:name=".EmptyPerm" android:exported="true" android:permission=""/>
  </application>
</manifest>
"""

_NOAPPPERM_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.noappperm">
  <application>
    <activity android:name=".EmptyPerm" android:exported="true" android:permission=""/>
  </application>
</manifest>
"""


class _GuardApk(_FakeApk):
    """A fake whose manifest exercises per-component permission guards."""

    def __init__(self, xml: str, package: str) -> None:
        self._xml = xml
        self._package = package

    def get_package(self) -> str:
        return self._package

    def get_android_manifest_xml(self) -> object:
        from lxml import etree

        return etree.fromstring(self._xml.encode("utf-8"))


def test_apk_components_flags_unprotected_exported_components() -> None:
    """exported_unprotected is the subset with no permission guard: a
    component-level permission, or a provider read/write permission, keeps a
    component off the list; an unguarded exported one lands on it."""
    client = ApkClient()
    client._apk = lambda _path: _GuardApk(  # type: ignore[method-assign]
        _GUARD_XML, "com.example.guard"
    )
    payload = client.components(Path("dummy.apk"))
    assert set(payload["exported"]) == {
        "com.example.guard.Guarded",
        "com.example.guard.Open",
        "com.example.guard.OpenViaFilter",
        "com.example.guard.OpenService",
        "com.example.guard.ReadGuardedProvider",
        "com.example.guard.OpenProvider",
    }
    assert set(payload["exported_unprotected"]) == {
        "com.example.guard.Open",
        "com.example.guard.OpenViaFilter",
        "com.example.guard.OpenService",
        "com.example.guard.OpenProvider",
    }
    assert payload["exported_unprotected_count"] == 4
    # The permission-guarded activity and the read-guarded provider are exported
    # but protected, so they stay off the unprotected list.
    assert "com.example.guard.Guarded" not in payload["exported_unprotected"]
    assert "com.example.guard.ReadGuardedProvider" not in payload["exported_unprotected"]
    assert payload["exported_unprotected"] == sorted(payload["exported_unprotected"])


def test_apk_components_permission_inherited_from_application() -> None:
    """A component with no permission of its own inherits
    <application android:permission>, so it is guarded even with an empty
    component permission string."""
    client = ApkClient()
    client._apk = lambda _path: _GuardApk(  # type: ignore[method-assign]
        _APPPERM_XML, "com.example.appperm"
    )
    payload = client.components(Path("dummy.apk"))
    assert set(payload["exported"]) == {
        "com.example.appperm.InheritsAppPerm",
        "com.example.appperm.EmptyPerm",
    }
    # Both ride the application permission, so neither is unprotected.
    assert payload["exported_unprotected"] == []


def test_apk_components_empty_permission_is_no_guard() -> None:
    """An empty android:permission string with no application-level permission
    to inherit leaves the component unprotected."""
    client = ApkClient()
    client._apk = lambda _path: _GuardApk(  # type: ignore[method-assign]
        _NOAPPPERM_XML, "com.example.noappperm"
    )
    payload = client.components(Path("dummy.apk"))
    assert payload["exported_unprotected"] == ["com.example.noappperm.EmptyPerm"]
