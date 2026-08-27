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


class _MalformedManifestApk:
    """Mimics androguard on a ZIP-valid APK with an unparseable manifest.

    Measured against androguard 4.1.4: most getters swallow the parse failure
    and return None/[], but get_androidversion_name/get_androidversion_code
    raise KeyError('Name')/KeyError('Code'). The files are still readable, so
    native_abis and permission_count parse fine.
    """

    def get_package(self) -> str:
        return ""

    def get_androidversion_name(self) -> str:
        raise KeyError("Name")

    def get_androidversion_code(self) -> str:
        raise KeyError("Code")

    def get_min_sdk_version(self) -> None:
        return None

    def get_target_sdk_version(self) -> None:
        return None

    def get_main_activity(self) -> None:
        return None

    def get_permissions(self) -> list[str]:
        return []

    def get_files(self) -> list[str]:
        return ["lib/arm64-v8a/libx.so", "lib/x86_64/libx.so", "classes.dex"]


def test_apk_open_degrades_when_the_manifest_will_not_parse() -> None:
    """A malformed-but-openable APK must not escape as a bare KeyError.

    androguard opens a ZIP-valid APK whose AndroidManifest.xml cannot be
    decoded, then raises KeyError('Name') from the version getter. Unwrapped
    that left the backend as a bare exception, and the service's catch-all
    filed it as internal_error with a logged incident -- reporting our code as
    broken for a merely malformed input and hiding the fields that did parse.
    open() now reads those getters tolerantly (None), the same way androguard
    already treats its sibling getters, so the readable facts still come back.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _MalformedManifestApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["opened"] is True
    assert payload["version_name"] is None
    assert payload["version_code"] is None
    assert payload["native_abis"] == ["arm64-v8a", "x86_64"]
    assert payload["permission_count"] == 0
