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
    doc = _tool_docstring("apk.components")
    assert "Answers with activities" in doc
    assert "has_more" in doc
    assert "main_activity" in doc


def test_apk_components_fallback_leaves_export_state_unknown() -> None:
    """A manifest androguard cannot re-parse must not sink the whole call.

    The four flat name lists still populate; every per-component record falls
    back to not-exported/unset so nothing is falsely advertised as reachable.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))
    assert set(payload["details"]) == {
        "activities",
        "services",
        "receivers",
        "providers",
    }
    assert payload["exported"] == {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }
    service = payload["details"]["services"][0]
    assert service["name"] == "S"
    assert service["exported"] is False
    assert service["exported_explicit"] is None
    assert service["has_intent_filter"] is False


_MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.x">
  <application>
    <activity android:name="com.x.Main">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <activity android:name="com.x.Internal"/>
    <activity android:name="com.x.ForcedOff" android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="open"/>
      </intent-filter>
    </activity>
    <service android:name="com.x.Svc" android:exported="true"
             android:permission="com.x.PERM"/>
    <receiver android:name="com.x.Rcv"/>
    <provider android:name="com.x.Prov" android:exported="true"/>
  </application>
</manifest>
"""


class _ManifestApk:
    def get_activities(self) -> list[str]:
        return ["com.x.Main", "com.x.Internal", "com.x.ForcedOff"]

    def get_services(self) -> list[str]:
        return ["com.x.Svc"]

    def get_receivers(self) -> list[str]:
        return ["com.x.Rcv"]

    def get_providers(self) -> list[str]:
        return ["com.x.Prov"]

    def get_main_activity(self) -> str:
        return "com.x.Main"

    def get_android_manifest_xml(self) -> object:
        from lxml import etree

        return etree.fromstring(_MANIFEST_XML.encode("utf-8"))


def _detail(payload: dict, kind: str, name: str) -> dict:
    return next(row for row in payload["details"][kind] if row["name"] == name)


_LEGACY_PROVIDER_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.x">
  <application>
    <provider android:name="com.x.LegacyProvider"/>
  </application>
</manifest>
"""


class _ProviderApk:
    def __init__(self, target_sdk: int) -> None:
        self._target = target_sdk

    def get_activities(self) -> list[str]:
        return []

    def get_services(self) -> list[str]:
        return []

    def get_receivers(self) -> list[str]:
        return []

    def get_providers(self) -> list[str]:
        return ["com.x.LegacyProvider"]

    def get_main_activity(self) -> str:
        return ""

    def get_effective_target_sdk_version(self) -> int:
        return self._target

    def get_android_manifest_xml(self) -> object:
        from lxml import etree

        return etree.fromstring(_LEGACY_PROVIDER_XML.encode("utf-8"))


def test_apk_components_provider_default_flips_at_api_17() -> None:
    """A content provider with no explicit flag and no intent-filter follows
    the platform default that changed at API 17: exported below 17, private
    at or above. Getting this wrong hides (or invents) a provider attack
    surface on pre-17 apps, which are exactly the ones worth auditing.
    """
    client = ApkClient()

    client._apk = lambda _p: _ProviderApk(16)  # type: ignore[method-assign]
    legacy = client.components(Path("old.apk"))
    prov = _detail(legacy, "providers", "com.x.LegacyProvider")
    assert prov["exported"] is True
    assert prov["exported_explicit"] is None
    assert legacy["exported"]["providers"] == ["com.x.LegacyProvider"]

    client._apk = lambda _p: _ProviderApk(17)  # type: ignore[method-assign]
    modern = client.components(Path("new.apk"))
    prov = _detail(modern, "providers", "com.x.LegacyProvider")
    assert prov["exported"] is False
    assert modern["exported"]["providers"] == []


def test_apk_components_reports_effective_export_state() -> None:
    """Export state drives Android attack-surface triage.

    An intent-filter with no explicit flag reads as exported; an explicit
    android:exported="false" wins even when a filter is present; a guarding
    permission is surfaced; and the exported convenience map lists exactly the
    reachable components.
    """
    client = ApkClient()
    client._apk = lambda _path: _ManifestApk()  # type: ignore[method-assign]
    payload = client.components(Path("dummy.apk"))

    main = _detail(payload, "activities", "com.x.Main")
    assert main["exported"] is True
    assert main["exported_explicit"] is None
    assert main["has_intent_filter"] is True

    internal = _detail(payload, "activities", "com.x.Internal")
    assert internal["exported"] is False
    assert internal["has_intent_filter"] is False

    forced_off = _detail(payload, "activities", "com.x.ForcedOff")
    assert forced_off["exported"] is False
    assert forced_off["exported_explicit"] is False
    assert forced_off["has_intent_filter"] is True

    # Even a locked-down (exported=false) component's intent-filters are worth
    # surfacing: they are the deep-link shape an attacker probes for.
    main_filters = main["intent_filters"]
    assert main_filters == [
        {
            "actions": ["android.intent.action.MAIN"],
            "categories": ["android.intent.category.LAUNCHER"],
        }
    ]
    deeplink = forced_off["intent_filters"][0]
    assert deeplink["actions"] == ["android.intent.action.VIEW"]
    assert deeplink["categories"] == ["android.intent.category.BROWSABLE"]
    assert deeplink["data"] == [{"scheme": "myapp", "host": "open"}]
    assert "intent_filters" not in internal

    svc = _detail(payload, "services", "com.x.Svc")
    assert svc["exported"] is True
    assert svc["exported_explicit"] is True
    assert svc["permission"] == "com.x.PERM"

    prov = _detail(payload, "providers", "com.x.Prov")
    assert prov["exported"] is True

    assert payload["exported"]["activities"] == ["com.x.Main"]
    assert payload["exported"]["services"] == ["com.x.Svc"]
    assert payload["exported"]["receivers"] == []
    assert payload["exported"]["providers"] == ["com.x.Prov"]

    doc = _tool_docstring("apk.components")
    assert "exported" in doc
    assert "has_intent_filter" in doc
    assert "intent_filters" in doc
