"""apk.security reports the <application> element's security posture.

The backend is exercised through the same _apk-injection seam the other apk
field tests use, so no real APK is needed. These pin the boolean-null contract
(a flag the manifest never declared is null, not false), the debuggable
fallback when androguard lacks is_debuggable(), and the SDK integer coercion.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

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
    def __init__(self, attrs: dict[str, str], *, debuggable: bool | None = None) -> None:
        self._attrs = attrs
        self._debuggable = debuggable

    def get_package(self) -> str:
        return "com.example.app"

    def get_attribute_value(self, tag: str, name: str) -> str | None:
        assert tag == "application"
        return self._attrs.get(name)

    def is_debuggable(self) -> bool:
        if self._debuggable is None:
            raise AttributeError("this androguard build has no is_debuggable")
        return self._debuggable

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> Any:
        return 33


def _client_with(apk: _FakeApk) -> ApkClient:
    client = ApkClient()
    client._apk = lambda _path: apk  # type: ignore[method-assign]
    return client


def test_security_reports_declared_flags() -> None:
    apk = _FakeApk(
        {
            "allowBackup": "true",
            "usesCleartextTraffic": "false",
            "networkSecurityConfig": "@xml/network_security_config",
            "name": "com.example.app.MyApplication",
        },
        debuggable=True,
    )
    payload = _client_with(apk).security(Path("dummy.apk"))

    assert payload["package"] == "com.example.app"
    assert payload["debuggable"] is True
    assert payload["allow_backup"] is True
    assert payload["uses_cleartext_traffic"] is False
    assert payload["network_security_config"] == "@xml/network_security_config"
    assert payload["application_class"] == "com.example.app.MyApplication"
    assert payload["min_sdk"] == 21
    assert payload["target_sdk"] == 33


def test_security_reports_undeclared_flags_as_null_not_false() -> None:
    """An absent manifest attribute is 'not set' (null), never a false claim."""
    apk = _FakeApk({}, debuggable=False)
    payload = _client_with(apk).security(Path("dummy.apk"))

    assert payload["allow_backup"] is None
    assert payload["uses_cleartext_traffic"] is None
    assert payload["network_security_config"] is None
    assert payload["application_class"] is None
    # debuggable still resolves via is_debuggable() -> False.
    assert payload["debuggable"] is False


def test_security_falls_back_when_is_debuggable_is_missing() -> None:
    """Older androguard lacks is_debuggable(); the manifest attribute is used."""
    apk = _FakeApk({"debuggable": "true"})  # debuggable=None -> is_debuggable raises
    payload = _client_with(apk).security(Path("dummy.apk"))
    assert payload["debuggable"] is True

    apk_absent = _FakeApk({})  # no attribute and no is_debuggable
    payload_absent = _client_with(apk_absent).security(Path("dummy.apk"))
    assert payload_absent["debuggable"] is None


def test_security_coerces_bad_sdk_values_to_null() -> None:
    class _WeirdSdkApk(_FakeApk):
        def get_min_sdk_version(self) -> Any:
            return None

        def get_target_sdk_version(self) -> Any:
            return "not-a-number"

    payload = _client_with(_WeirdSdkApk({}, debuggable=False)).security(Path("d.apk"))
    assert payload["min_sdk"] is None
    assert payload["target_sdk"] is None


def test_security_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.security")
    assert "debuggable" in doc
    assert "allow_backup" in doc
    assert "network_security_config" in doc
    assert "application_class" in doc
    assert "null" in doc
