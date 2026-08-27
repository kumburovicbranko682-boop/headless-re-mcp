"""apk.security must read the <application> element's triage flags as tri-state."""

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


_RISKY_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.x">
  <application android:name="com.x.App"
               android:debuggable="true"
               android:allowBackup="false"
               android:usesCleartextTraffic="true"
               android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name="com.x.Main"/>
  </application>
</manifest>
"""

# A manifest that sets none of the application security attributes: every flag
# must come back null (unset), not defaulted to a boolean.
_BARE_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.x">
  <application>
    <activity android:name="com.x.Main"/>
  </application>
</manifest>
"""


class _ManifestApk:
    def __init__(
        self, xml: str, *, min_sdk: str | None = "21", target_sdk: str | None = "33"
    ) -> None:
        self._xml = xml
        self._min = min_sdk
        self._target = target_sdk

    def get_min_sdk_version(self) -> str | None:
        return self._min

    def get_target_sdk_version(self) -> str | None:
        return self._target

    def get_android_manifest_xml(self) -> object:
        from lxml import etree

        return etree.fromstring(self._xml.encode("utf-8"))


def test_apk_security_reports_the_application_flags() -> None:
    """The <application> triage flags an analyst checks first must round-trip.

    A debuggable app, adb-backup-able data, cleartext HTTP, a custom
    network-security-config and the custom Application class are the first
    things a review flags -- and previously all of them meant hand-parsing the
    manifest XML. Assert each surfaces as a concrete value plus the SDK context.
    """
    client = ApkClient()
    client._apk = lambda _p: _ManifestApk(_RISKY_XML)  # type: ignore[method-assign]
    payload = client.security(Path("dummy.apk"))

    assert payload["debuggable"] is True
    assert payload["allow_backup"] is False
    assert payload["uses_cleartext_traffic"] is True
    assert payload["network_security_config"] == "@xml/network_security_config"
    assert payload["application_class"] == "com.x.App"
    assert payload["min_sdk"] == 21
    assert payload["target_sdk"] == 33
    # These are the raw facts, not an interpreted verdict.
    assert "findings" not in payload
    assert "score" not in payload


def test_apk_security_leaves_unset_flags_null() -> None:
    """An unset attribute must read as null, not a defaulted boolean.

    The platform default an unset value takes turns on the target SDK, so
    baking one in would mislabel a manifest that simply says nothing. A bare
    <application> must yield null for every flag while still returning the SDK
    context the caller needs to reason about those defaults.
    """
    client = ApkClient()
    client._apk = lambda _p: _ManifestApk(_BARE_XML, min_sdk="19", target_sdk="27")  # type: ignore[method-assign]
    payload = client.security(Path("dummy.apk"))

    assert payload["debuggable"] is None
    assert payload["allow_backup"] is None
    assert payload["uses_cleartext_traffic"] is None
    assert payload["network_security_config"] is None
    assert payload["application_class"] is None
    assert payload["min_sdk"] == 19
    assert payload["target_sdk"] == 27


class _UnparseableApk:
    """A manifest androguard cannot re-parse into a tree, but SDKs still read."""

    def get_min_sdk_version(self) -> str | None:
        return "24"

    def get_target_sdk_version(self) -> str | None:
        return None

    def get_android_manifest_xml(self) -> object:
        raise ValueError("bad AXML")


def test_apk_security_survives_an_unparseable_manifest() -> None:
    """A manifest that will not re-parse must not sink the whole call.

    _application_element swallows the parse failure and the flags fall back to
    null rather than raising; the SDK getters, which do not touch the tree,
    still populate. A None from get_target_sdk_version coerces to null, not a
    crash.
    """
    client = ApkClient()
    client._apk = lambda _p: _UnparseableApk()  # type: ignore[method-assign]
    payload = client.security(Path("dummy.apk"))

    assert payload["debuggable"] is None
    assert payload["allow_backup"] is None
    assert payload["uses_cleartext_traffic"] is None
    assert payload["network_security_config"] is None
    assert payload["application_class"] is None
    assert payload["min_sdk"] == 24
    assert payload["target_sdk"] is None


def test_apk_security_docstring_names_the_fields() -> None:
    doc = _tool_docstring("apk.security")
    assert doc, "apk.security is missing its docstring"
    assert "debuggable" in doc
    assert "allow_backup" in doc
    assert "uses_cleartext_traffic" in doc
    assert "network_security_config" in doc
    assert "application_class" in doc
    assert "target_sdk" in doc
