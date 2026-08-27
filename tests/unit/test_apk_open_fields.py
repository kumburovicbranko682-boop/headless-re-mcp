"""apk.open descriptions must name the fields the parser actually returns."""

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
    def get_package(self) -> str:
        return "com.x"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "1"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "33"

    def get_main_activity(self) -> str:
        return "com.x.Main"

    def get_permissions(self) -> list[str]:
        return ["A"]

    def get_files(self) -> list[str]:
        return ["lib/arm64-v8a/libx.so"]


def test_apk_open_names_version_name_and_native_abis_not_version() -> None:
    """The catalog said version and ABIs; the parser has no such fields.

    Measured: open() keys are main_activity, min_sdk, native_abis, opened,
    package, permission_count, target_sdk, version_code, version_name.
    version/sdk/abis are absent. Looking for version after a successful
    open reads as an unidentified APK, so the agent re-parses or skips ABI
    routing.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert "version" not in payload
    assert "sdk" not in payload
    assert "abis" not in payload
    assert payload["version_name"] == "1.0"
    assert payload["native_abis"] == ["arm64-v8a"]
    # No get_attribute_value on the fake -> security degrades to defaults, and
    # target_sdk 33 (>=28) means cleartext is denied by default.
    assert payload["security"] == {
        "debuggable": False,
        "allow_backup": True,
        "uses_cleartext_traffic": False,
        "network_security_config": False,
        # No manifest tree on the fake -> no sharedUserId to read.
        "shared_user_id": None,
    }
    doc = _tool_docstring("apk.open")
    assert "Answers with package" in doc
    assert "version_name" in doc
    assert "native_abis" in doc


class _SecureApk(_FakeApk):
    def __init__(self, attrs: dict[str, str], target: str = "33") -> None:
        self._attrs = attrs
        self._target = target

    def get_target_sdk_version(self) -> str:
        return self._target

    def get_attribute_value(self, tag: str, attribute: str) -> str | None:
        assert tag == "application"
        return self._attrs.get(attribute)


def test_apk_open_reports_explicit_security_flags() -> None:
    """A debuggable, backup-enabled app with a custom NSC is a triage finding.

    Measured: explicit manifest attributes win over defaults, and a legacy
    target (< 28) allows cleartext by default when the attribute is absent.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _SecureApk(  # type: ignore[method-assign]
        {
            "debuggable": "true",
            "allowBackup": "false",
            "networkSecurityConfig": "@xml/network_security_config",
        },
        target="26",
    )
    payload = client.open(Path("dummy.apk"))
    assert payload["security"] == {
        "debuggable": True,
        "allow_backup": False,
        # No usesCleartextTraffic attribute, target 26 (< 28) -> allowed default.
        "uses_cleartext_traffic": True,
        "network_security_config": True,
        "shared_user_id": None,
    }
    doc = _tool_docstring("apk.open")
    assert "security" in doc
    assert "debuggable" in doc


class _SharedUidApk(_FakeApk):
    """Declares android:sharedUserId on the root <manifest> tag."""

    def get_android_manifest_xml(self) -> etree._Element:
        return etree.fromstring(
            b"""<manifest xmlns:android="http://schemas.android.com/apk/res/android"
                          package="com.x"
                          android:sharedUserId="android.uid.system">
                  <application/>
                </manifest>"""
        )


def test_apk_open_surfaces_a_declared_shared_user_id() -> None:
    """sharedUserId lives on the manifest root and its value is the red flag."""
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _SharedUidApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["security"]["shared_user_id"] == "android.uid.system"
    doc = _tool_docstring("apk.open")
    assert "shared_user_id" in doc
