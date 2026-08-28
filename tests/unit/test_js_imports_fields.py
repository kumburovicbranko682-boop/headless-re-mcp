"""js.imports: a node-free extractor of a JS file's module dependencies.

It tokenizes the source comment- and string-aware and reads the specifier off
ESM import / export ... from, dynamic import() and CommonJS require() forms.
These tests pin the contract on hand-written JS: each syntax form, kind
classification (bare / relative / absolute / url), that an import word inside a
comment or string is not miscounted, computed template specifiers are skipped,
dedup/order, the caps and paging, truncated, and the not_found guard, plus the
tool docstring naming the returned fields.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, scan_js_imports
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(text, encoding="utf-8")
    return target


def _rows(payload: dict) -> dict[str, dict[str, str]]:
    return {row["spec"]: row for row in payload["imports"]}


def test_all_syntax_forms(tmp_path: Path) -> None:
    src = (
        "import def from 'default-pkg';\n"
        "import { a, b as c } from 'named-pkg';\n"
        "import * as ns from 'ns-pkg';\n"
        "import 'side-effect-pkg';\n"
        "export { x } from 're-export-pkg';\n"
        "export * from 'star-export-pkg';\n"
        "const d = await import('dynamic-pkg');\n"
        "const e = require('cjs-pkg');\n"
    )
    rows = _rows(scan_js_imports(_write(tmp_path, src)))
    assert rows["default-pkg"]["syntax"] == "import"
    assert rows["named-pkg"]["syntax"] == "import"
    assert rows["ns-pkg"]["syntax"] == "import"
    assert rows["side-effect-pkg"]["syntax"] == "import"
    assert rows["re-export-pkg"]["syntax"] == "export"
    assert rows["star-export-pkg"]["syntax"] == "export"
    assert rows["dynamic-pkg"]["syntax"] == "dynamic"
    assert rows["cjs-pkg"]["syntax"] == "require"


def test_specifier_kinds(tmp_path: Path) -> None:
    src = (
        "import 'react';\n"
        "import '@scope/pkg';\n"
        "import './local/util';\n"
        "import '../parent';\n"
        "import '/rooted/abs';\n"
        "import 'https://cdn.example.com/lib.js';\n"
        "import '//cdn.example.com/proto-rel.js';\n"
    )
    rows = _rows(scan_js_imports(_write(tmp_path, src)))
    assert rows["react"]["kind"] == "bare"
    assert rows["@scope/pkg"]["kind"] == "bare"
    assert rows["./local/util"]["kind"] == "relative"
    assert rows["../parent"]["kind"] == "relative"
    assert rows["/rooted/abs"]["kind"] == "absolute"
    assert rows["https://cdn.example.com/lib.js"]["kind"] == "url"
    assert rows["//cdn.example.com/proto-rel.js"]["kind"] == "url"


def test_multiline_import_clause(tmp_path: Path) -> None:
    src = "import {\n  one,\n  two,\n  three as t\n} from 'multiline-pkg';\n"
    rows = _rows(scan_js_imports(_write(tmp_path, src)))
    assert "multiline-pkg" in rows
    assert rows["multiline-pkg"]["syntax"] == "import"


def test_import_word_in_comment_or_string_is_not_counted(tmp_path: Path) -> None:
    src = (
        "// import 'commented-out';\n"
        "/* require('block-comment') */\n"
        "var s = \"please require('inside-string')\";\n"
        "var t = 'import x from \\'nested\\'';\n"
        "import 'real-pkg';\n"
    )
    rows = _rows(scan_js_imports(_write(tmp_path, src)))
    assert set(rows) == {"real-pkg"}


def test_computed_template_specifier_is_skipped(tmp_path: Path) -> None:
    src = "const m = await import(`./locales/${lang}.js`); import 'static-pkg';"
    rows = _rows(scan_js_imports(_write(tmp_path, src)))
    assert "static-pkg" in rows
    assert not any("${" in spec for spec in rows)


def test_export_without_from_is_not_an_import(tmp_path: Path) -> None:
    src = (
        "export const foo = 1;\n"
        "export default function () {}\n"
        "export { bar };\n"
        "import 'only-real';\n"
    )
    rows = _rows(scan_js_imports(_write(tmp_path, src)))
    assert set(rows) == {"only-real"}


def test_dedup_first_seen_syntax_and_order(tmp_path: Path) -> None:
    src = "import x from 'dup';\nconst y = require('dup');\nimport 'second';\n"
    payload = scan_js_imports(_write(tmp_path, src))
    specs = [row["spec"] for row in payload["imports"]]
    assert specs == ["dup", "second"]
    assert payload["imports"][0]["syntax"] == "import"


def test_collect_cap_sets_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_IMPORTS_COLLECT", 2)
    src = ";".join(f"import 'pkg{i}'" for i in range(6))
    payload = scan_js_imports(_write(tmp_path, src))
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


def test_token_cap_sets_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A tiny token ceiling stops lexing before the import is reached.
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_TOKENS", 3)
    src = "a; b; c; d; import 'never-reached';"
    payload = scan_js_imports(_write(tmp_path, src))
    assert payload["scan_capped"] is True


def test_page_window_and_has_more(tmp_path: Path) -> None:
    src = ";".join(f"import 'pkg{i:02d}'" for i in range(15))
    first = scan_js_imports(_write(tmp_path, src), offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 15
    assert first["has_more"] is True

    tail = scan_js_imports(_write(tmp_path, src), offset=10, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def test_unterminated_block_comment_sets_truncated(tmp_path: Path) -> None:
    src = "import 'ok'; /* dangling"
    payload = scan_js_imports(_write(tmp_path, src))
    assert "ok" in {row["spec"] for row in payload["imports"]}
    assert payload["truncated"] is True


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        scan_js_imports(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def _tool_docstring(name: str) -> str:
    source = Path(build_js_wasm_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_docstring_names_returned_fields() -> None:
    doc = _tool_docstring("js.imports")
    assert "Answers with" in doc
    assert "imports" in doc
    assert "spec" in doc and "kind" in doc and "syntax" in doc
    assert "has_more" in doc
