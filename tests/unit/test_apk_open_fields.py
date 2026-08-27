"""apk.open descriptions must name the fields the parser actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.apk.client import ApkClient, _int_or_original
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


def test_int_or_original_coerces_numeric_strings_only() -> None:
    """androguard hands back strings; the numeric ones become ints, cleanly.

    A lexicographic SDK comparison is the trap: as strings, "9" > "34" and
    "100" < "99". Ints compare correctly; non-numeric values (a resource ref,
    a dotted version name, None) are left exactly as androguard gave them.
    """
    assert _int_or_original("34") == 34
    assert isinstance(_int_or_original("34"), int)
    assert _int_or_original("0") == 0
    assert _int_or_original(21) == 21
    # Not a plain integer -> passed through untouched.
    assert _int_or_original("1.4") == "1.4"
    assert _int_or_original("@0x7f010000") == "@0x7f010000"
    assert _int_or_original("") == ""
    assert _int_or_original(None) is None
    # bool is an int subclass but never a version; must not become 1/0.
    assert _int_or_original(True) is True


def test_apk_open_returns_numeric_sdk_fields_as_ints_not_strings() -> None:
    """version_code/min_sdk/target_sdk come back as ints; version_name stays str.

    The fake mirrors androguard, which returns every manifest value as a string.
    Before the fix an agent comparing target_sdk numerically hit str-vs-int; the
    lexicographic fallback ("33" < "9") is exactly the silent wrong answer.
    """
    client = ApkClient()
    client._available = True
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.open(Path("dummy.apk"))
    assert payload["version_code"] == 1
    assert payload["min_sdk"] == 21
    assert payload["target_sdk"] == 33
    for field in ("version_code", "min_sdk", "target_sdk"):
        assert isinstance(payload[field], int), (field, payload[field])
    # version_name is a genuine string and must not be coerced.
    assert payload["version_name"] == "1.0"
    assert isinstance(payload["version_name"], str)
    doc = " ".join(_tool_docstring("apk.open").split())
    assert "version_code, min_sdk and target_sdk are integers" in doc
