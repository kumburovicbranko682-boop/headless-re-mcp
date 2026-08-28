"""js.imports must extract a module's dependency edges straight from JS source.

Pure-Python scanner: no webcrack, so every case runs on a bare machine. Covers
static import forms (side-effect / default / namespace / named / combined),
export-from re-exports, dynamic import() and CommonJS require(), the skip of
computed specifiers and of keywords hiding in strings / comments / regex, plus
dedup, kind_counts, filters, paging and the scan ceiling.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, JsReError, _scan_js_imports
from headless_re_mcp.config import Settings
from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


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


def _edges(text: str) -> list[dict]:
    edges, _capped = _scan_js_imports(text, max_edges=10_000)
    return edges


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "module.js"
    p.write_text(body, encoding="utf-8")
    return p


# --- the scanner: static import forms ---------------------------------------


def test_default_import() -> None:
    (edge,) = _edges('import foo from "bar";')
    assert edge["kind"] == "import"
    assert edge["specifier"] == "bar"
    assert edge["default"] == "foo"
    assert "names" not in edge and "namespace" not in edge


def test_named_imports_capture_the_imported_names() -> None:
    (edge,) = _edges('import { a, b as c } from "x";')
    assert edge["specifier"] == "x"
    # The imported (left-of-`as`) names, not the local aliases.
    assert edge["names"] == ["a", "b"]
    assert "default" not in edge


def test_namespace_import() -> None:
    (edge,) = _edges('import * as ns from "y";')
    assert edge["namespace"] == "ns"
    assert edge["specifier"] == "y"


def test_side_effect_import_has_only_a_specifier() -> None:
    (edge,) = _edges('import "./polyfill.js";')
    assert edge["kind"] == "import"
    assert edge["specifier"] == "./polyfill.js"
    assert "default" not in edge and "names" not in edge


def test_combined_default_and_named() -> None:
    (edge,) = _edges('import def, { a, b } from "z";')
    assert edge["default"] == "def"
    assert edge["names"] == ["a", "b"]
    assert edge["specifier"] == "z"


def test_combined_default_and_namespace() -> None:
    (edge,) = _edges('import def, * as ns from "z";')
    assert edge["default"] == "def"
    assert edge["namespace"] == "ns"


def test_from_used_as_a_binding_name_is_not_the_module_keyword() -> None:
    # `from` inside the braces is an imported name; the real module keyword is
    # the one at brace-depth 0.
    (edge,) = _edges('import { from } from "real";')
    assert edge["specifier"] == "real"
    assert edge["names"] == ["from"]


def test_typescript_type_only_import_is_still_an_edge() -> None:
    (edge,) = _edges('import type { T } from "types";')
    assert edge["specifier"] == "types"
    assert edge["names"] == ["T"]
    assert "default" not in edge


# --- dynamic import / require -----------------------------------------------


def test_dynamic_import() -> None:
    (edge,) = _edges('const m = await import("./lazy.js");')
    assert edge["kind"] == "dynamic_import"
    assert edge["specifier"] == "./lazy.js"


def test_computed_dynamic_import_is_skipped() -> None:
    assert _edges("const m = await import(path);") == []


def test_import_meta_is_not_a_dependency() -> None:
    assert _edges("const u = import.meta.url;") == []


def test_require() -> None:
    (edge,) = _edges('const fs = require("fs");')
    assert edge["kind"] == "require"
    assert edge["specifier"] == "fs"


def test_member_require_is_still_captured() -> None:
    # module.require("x") is CommonJS too; the ("literal") call is the signal.
    (edge,) = _edges('const x = module.require("dep");')
    assert edge["kind"] == "require"
    assert edge["specifier"] == "dep"


def test_computed_require_is_skipped() -> None:
    assert _edges("const x = require(name);") == []


# --- export ... from --------------------------------------------------------


def test_export_named_from() -> None:
    (edge,) = _edges('export { a, b } from "reexport";')
    assert edge["kind"] == "export_from"
    assert edge["specifier"] == "reexport"
    assert edge["names"] == ["a", "b"]


def test_export_star_from() -> None:
    (edge,) = _edges('export * from "star";')
    assert edge["kind"] == "export_from"
    assert edge["specifier"] == "star"
    assert "names" not in edge and "namespace" not in edge


def test_export_star_as_namespace_from() -> None:
    (edge,) = _edges('export * as ns from "starns";')
    assert edge["kind"] == "export_from"
    assert edge["namespace"] == "ns"


def test_local_exports_are_not_dependency_edges() -> None:
    src = (
        "export default function () {}\n"
        "export const answer = 42;\n"
        "export { a, b };\n"
        "export function f() {}\n"
    )
    assert _edges(src) == []


# --- keywords that only look like imports ------------------------------------


def test_keyword_inside_a_string_is_not_read_as_code() -> None:
    assert _edges("""var s = "import x from 'y'"; var t = 'require(\\'z\\')';""") == []


def test_keyword_inside_a_comment_is_ignored() -> None:
    src = "// import x from 'y'\n/* require('z') */\nvar real = 1;"
    assert _edges(src) == []


def test_import_like_text_in_a_regex_is_ignored() -> None:
    src = "var re = /import x from \"y\"/g; var a = 1;"
    assert _edges(src) == []


def test_property_named_import_is_not_the_keyword() -> None:
    # a.import(...) is a method call on a, not a dynamic import.
    assert _edges('a.import("nope");') == []


def test_longer_identifier_is_not_the_keyword() -> None:
    assert _edges('const imported = load("nope"); function requires() {}') == []


# --- line numbers -----------------------------------------------------------


def test_line_numbers_point_at_the_keyword() -> None:
    src = 'const a = 1;\nimport foo from "bar";\n\nrequire("baz");'
    edges = _edges(src)
    by_spec = {e["specifier"]: e for e in edges}
    assert by_spec["bar"]["line"] == 2
    assert by_spec["baz"]["line"] == 4


# --- the JsClient.imports contract ------------------------------------------


def test_dedup_specifiers_distinct_and_kind_counts(tmp_path: Path) -> None:
    body = (
        'import a from "dup";\n'
        'import { b } from "dup";\n'
        'export * from "reexport";\n'
        'const c = require("cjs");\n'
        'const d = import("./lazy.js");\n'
    )
    out = JsClient().imports(_write(tmp_path, body))
    assert out["kind_counts"] == {
        "dynamic_import": 1,
        "export_from": 1,
        "import": 2,
        "require": 1,
    }
    # "dup" appears twice but is one distinct specifier.
    assert out["distinct"] == 4
    assert out["specifiers"] == ["./lazy.js", "cjs", "dup", "reexport"]
    assert out["total"] == 5
    assert out["scan_capped"] is False


def test_kind_filter(tmp_path: Path) -> None:
    body = 'import a from "x";\nconst b = require("y");\nexport * from "z";'
    out = JsClient().imports(_write(tmp_path, body), kind="require")
    assert [e["specifier"] for e in out["imports"]] == ["y"]
    assert out["kind"] == "require"
    # kind_counts still describes the whole file, not just the filtered view.
    assert out["kind_counts"]["import"] == 1
    assert out["kind_counts"]["export_from"] == 1


def test_contains_filter(tmp_path: Path) -> None:
    body = 'import a from "./api/client";\nimport b from "react";\nimport c from "./api/auth";'
    out = JsClient().imports(_write(tmp_path, body), contains="API")
    specs = {e["specifier"] for e in out["imports"]}
    assert specs == {"./api/client", "./api/auth"}
    assert out["contains"] == "API"


def test_paging(tmp_path: Path) -> None:
    body = "\n".join(f'import x{i} from "mod-{i:03d}";' for i in range(10))
    src = _write(tmp_path, body)
    first = JsClient().imports(src, offset=0, limit=4)
    assert first["count"] == 4
    assert first["total"] == 10
    assert first["has_more"] is True
    last = JsClient().imports(src, offset=8, limit=4)
    assert last["count"] == 2
    assert last["has_more"] is False


def test_scan_cap_is_reported() -> None:
    src = ";".join(f'import x{i} from "m{i}"' for i in range(20))
    edges, capped = _scan_js_imports(src, max_edges=5)
    assert len(edges) == 5
    assert capped is True


def test_bad_kind_is_invalid_params(tmp_path: Path) -> None:
    src = _write(tmp_path, 'import a from "x";')
    with pytest.raises(JsReError) as info:
        JsClient().imports(src, kind="sideload")
    assert info.value.code == "invalid_params"


def test_oversized_contains_is_invalid_params(tmp_path: Path) -> None:
    src = _write(tmp_path, 'import a from "x";')
    with pytest.raises(JsReError) as info:
        JsClient().imports(src, contains="y" * (jsre_client._MAX_JS_STRINGS_CONTAINS + 1))
    assert info.value.code == "invalid_params"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        JsClient().imports(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_works_without_webcrack(tmp_path: Path) -> None:
    """imports must run even when no webcrack is configured (unlike deobfuscate)."""
    src = _write(tmp_path, 'import { render } from "./ui.js";')
    client = JsClient(executable=None)
    assert client.available is False
    out = client.imports(src)
    assert out["specifiers"] == ["./ui.js"]


def test_service_wiring_tags_the_jsre_backend(tmp_path: Path) -> None:
    service = AnalysisService(Settings.load())
    src = _write(tmp_path, 'import a from "x"; const b = require("y");')
    result = service.js_imports(str(src))
    assert result.ok, result.error
    assert result.data is not None
    assert result.meta.get("backend") == "jsre"
    assert result.data["distinct"] == 2


def test_docstring_names_the_fields() -> None:
    doc = _tool_docstring("js.imports")
    for token in ("imports", "specifier", "kind", "export_from", "specifiers", "scan_capped"):
        assert token in doc, token
