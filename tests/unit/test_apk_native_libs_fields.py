"""apk.native_libs descriptions must name the fields the parser actually returns."""

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
    def get_files(self) -> list[str]:
        return [f"lib/arm64-v8a/l{index}.so" for index in range(300)] + ["classes.dex"]


def test_apk_native_libs_names_native_libs_not_libraries() -> None:
    """The catalog said libraries and ABIs; the parser has no such fields.

    Measured: 300 lib paths, cap 256 -> count 256, has_more True, field is
    native_libs not libs or libraries, and the ABI list is abis. Looking
    for libraries after a successful call reads as no native code, and a
    full 256 list with no has_more reads as every .so.
    """
    client = ApkClient()
    client._apk = lambda _path: _FakeApk()  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert "libs" not in payload
    assert "libraries" not in payload
    assert "native_libraries" not in payload
    assert payload["count"] == 256
    assert len(payload["native_libs"]) == 256
    assert payload["has_more"] is True
    assert payload["abis"] == ["arm64-v8a"]
    doc = _tool_docstring("apk.native_libs")
    assert "Answers with native_libs" in doc
    assert "abis" in doc
    assert "has_more" in doc
