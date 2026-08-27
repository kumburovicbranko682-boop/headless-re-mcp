"""apk.open descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.apk.client import ApkClient, ApkError
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


class _BrokenApk:
    """androguard returns one of these for a malformed manifest: constructed
    fine, but the getters raise when actually read."""

    def get_package(self) -> str:
        raise ValueError("this does not look like an AXML file")


def test_apk_open_wraps_a_throwing_getter_as_backend_error() -> None:
    """A malformed APK must read as backend_error, never internal_error.

    androguard's APK() does not raise on a broken manifest, so _apk succeeds and
    the failure only appears when open() reads a getter. Without wrapping, that
    androguard exception escapes to the service's BaseException handler and
    becomes internal_error with a logged incident -- bad input misreported as a
    server defect. This pins the wrapping without needing androguard installed.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _BrokenApk()  # type: ignore[method-assign,return-value]
    with pytest.raises(ApkError) as info:
        client.open(Path("dummy.apk"))
    assert info.value.code == "backend_error"


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
