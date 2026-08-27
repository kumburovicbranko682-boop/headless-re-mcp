"""apk.open descriptions must name the fields the parser actually returns."""

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
    doc = _tool_docstring("apk.open")
    assert "Answers with package" in doc
    assert "version_name" in doc
    assert "native_abis" in doc


class _ExplicitFlagsApk(_FakeApk):
    """Every posture attribute set explicitly, each away from its default."""

    def get_attribute_value(self, tag: str, attribute: str, **kwargs: str) -> str | None:
        assert tag == "application"
        return {
            "debuggable": "true",
            "allowBackup": "false",
            "usesCleartextTraffic": "true",
            "networkSecurityConfig": "@xml/network_security_config",
        }.get(attribute)

    def get_effective_target_sdk_version(self) -> int:
        return 33


class _DefaultFlagsApk(_FakeApk):
    """No posture attribute set: the platform defaults must be reported."""

    def __init__(self, effective_target: int) -> None:
        self._effective_target = effective_target

    def get_attribute_value(self, tag: str, attribute: str, **kwargs: str) -> None:
        return None

    def get_effective_target_sdk_version(self) -> int:
        return self._effective_target


class _UnreadableFlagsApk(_FakeApk):
    def get_attribute_value(self, tag: str, attribute: str, **kwargs: str) -> str | None:
        raise RuntimeError("manifest attribute lookup broke")


def test_apk_open_reports_explicit_security_posture_flags() -> None:
    """Explicit manifest attributes come back as the effective posture.

    debuggable=true, allowBackup=false, usesCleartextTraffic=true and a
    networkSecurityConfig are each the interesting (non-default) direction;
    apk.open must surface all four instead of leaving posture to a manual
    manifest read.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _ExplicitFlagsApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["debuggable"] is True
    assert payload["allow_backup"] is False
    assert payload["uses_cleartext_traffic"] is True
    assert payload["network_security_config"] is True
    doc = _tool_docstring("apk.open")
    assert "debuggable" in doc
    assert "allow_backup" in doc
    assert "uses_cleartext_traffic" in doc
    assert "network_security_config" in doc


def test_apk_open_applies_platform_defaults_when_flags_are_absent() -> None:
    """Absent attributes report the platform default, keyed on targetSdk.

    Debug is off and backup is on by default; cleartext defaults on below an
    effective targetSdk of 28 and off from 28 up.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _DefaultFlagsApk(27)  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["debuggable"] is False
    assert payload["allow_backup"] is True
    assert payload["uses_cleartext_traffic"] is True
    assert payload["network_security_config"] is False

    client._apk = lambda _path: _DefaultFlagsApk(28)  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["uses_cleartext_traffic"] is False


def test_apk_open_omits_posture_flags_when_the_manifest_cannot_be_read() -> None:
    """A failed attribute read omits all four flags rather than defaulting.

    Reporting a hostile APK as not-debuggable / no-cleartext after a failed
    read is the dangerous direction to be wrong in; identity fields must
    still come back.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _UnreadableFlagsApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert "debuggable" not in payload
    assert "allow_backup" not in payload
    assert "uses_cleartext_traffic" not in payload
    assert "network_security_config" not in payload
    assert payload["package"] == "com.x"
