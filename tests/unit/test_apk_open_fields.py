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

    def get_attribute_value(self, tag: str, attribute: str) -> str | None:
        return None


class _FlaggedApk(_FakeApk):
    """A manifest that explicitly declares the two security flags."""

    def get_attribute_value(self, tag: str, attribute: str) -> str | None:
        if tag == "application" and attribute == "debuggable":
            return "true"
        if tag == "application" and attribute == "allowBackup":
            return "false"
        return None


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


def test_apk_open_reports_effective_security_flags_with_defaults() -> None:
    """A manifest that omits the flags takes Android's defaults: not
    debuggable, backup allowed."""
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["debuggable"] is False
    assert payload["allow_backup"] is True
    doc = _tool_docstring("apk.open")
    assert "debuggable" in doc
    assert "allow_backup" in doc


def test_apk_open_reports_explicit_security_flags() -> None:
    """debuggable=true and allowBackup=false in the manifest are surfaced as
    the risky booleans, not the defaults."""
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _FlaggedApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["debuggable"] is True
    assert payload["allow_backup"] is False
