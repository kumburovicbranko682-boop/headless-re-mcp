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


class _ReverseLibsApk:
    """300 .so under arm64-v8a in reverse-sorted order, plus one x86 .so last.

    Names are zero-padded so lexicographic order matches numeric order. The
    reverse order puts the alphabetically-early libs past the 256 cap in
    get_files() order, and the trailing x86 entry sits past the cap too -- so the
    fixture exercises both the sort-before-cap fix and that abis is collected from
    every entry, not just the returned page.
    """

    def get_files(self) -> list[str]:
        libs = [f"lib/arm64-v8a/l{index:03d}.so" for index in range(299, -1, -1)]
        return [*libs, "classes.dex", "lib/x86/late.so"]


def test_apk_native_libs_returns_the_alphabetical_head_and_all_abis() -> None:
    """A tree past the cap returns the alphabetically-first .so, not zip order.

    get_files() yields zip-entry order. The old code capped to the first 256 in
    that order and sorted only those, so a multi-ABI APK (>256 lib/ entries)
    returned the zip-order-first 256 alphabetized -- silently dropping
    alphabetically-early .so paths sitting past the cap. Here the entries arrive
    reverse-sorted, so the 256-item page must start at l000.so (the true head),
    not l044.so (the head of the reverse-order prefix alphabetized). abis must
    still include x86 even though its only .so sits past the lib cap.
    """
    client = ApkClient()
    client._apk = lambda _path: _ReverseLibsApk()  # type: ignore[method-assign]
    payload = client.native_libs(Path("dummy.apk"))
    assert payload["count"] == 256
    assert payload["has_more"] is True
    assert payload["native_libs"] == [
        f"lib/arm64-v8a/l{index:03d}.so" for index in range(256)
    ]
    assert payload["abis"] == ["arm64-v8a", "x86"]


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
