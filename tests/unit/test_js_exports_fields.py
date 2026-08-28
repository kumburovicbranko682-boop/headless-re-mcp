"""js.exports must inventory a module's export surface straight from JS source.

Pure-Python scanner, mirror of js.imports: no webcrack, so every case runs on a
bare machine. Covers ES exports (default / declaration / named list / re-export
/ star) and CommonJS (module.exports / exports.x), the skip of keywords hiding
in strings, comments and regex, plus dedup, kind_counts, has_default, filters,
paging and the scan ceiling.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, JsReError, _scan_js_exports
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
    edges, _capped = _scan_js_exports(text, max_edges=10_000)
    return edges


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "module.js"
    p.write_text(body, encoding="utf-8")
    return p


# --- ES default -------------------------------------------------------------


def test_default_expression() -> None:
    (edge,) = _edges("export default 42;")
    assert edge["kind"] == "default"
    assert edge["name"] == "default"


def test_default_named_function() -> None:
    (edge,) = _edges("export default function foo() {}")
    assert edge["kind"] == "default"
    assert edge["name"] == "foo"


def test_default_named_class() -> None:
    (edge,) = _edges("export default class Widget {}")
    assert edge["name"] == "Widget"


def test_default_anonymous_function_falls_back_to_default() -> None:
    (edge,) = _edges("export default function () {}")
    assert edge["name"] == "default"


# --- ES declaration exports -------------------------------------------------


def test_const_export() -> None:
    (edge,) = _edges("export const answer = 42;")
    assert edge["kind"] == "named"
    assert edge["name"] == "answer"


def test_function_and_class_and_async_and_generator() -> None:
    names = {e["name"] for e in _edges(
        "export function f() {}\n"
        "export class C {}\n"
        "export async function g() {}\n"
        "export function* gen() {}\n"
    )}
    assert names == {"f", "C", "g", "gen"}


def test_destructuring_export_best_effort() -> None:
    names = {e["name"] for e in _edges("export const { foo, bar: baz } = config;")}
    assert names == {"foo", "baz"}  # baz is the local binding of bar: baz


# --- ES named list ----------------------------------------------------------


def test_named_list_uses_the_exposed_alias() -> None:
    edges = _edges("const a = 1, b = 2; export { a, b as c };")
    got = {e["name"]: e["kind"] for e in edges}
    assert got == {"a": "named", "c": "named"}  # `b as c` exposes c


def test_empty_export_list_is_no_edge() -> None:
    assert _edges("export {};") == []


# --- re-exports / star ------------------------------------------------------


def test_named_re_export_carries_from() -> None:
    edges = _edges('export { Button, Icon as Glyph } from "./ui.js";')
    assert all(e["kind"] == "re_export" for e in edges)
    assert all(e["from"] == "./ui.js" for e in edges)
    # Two names -> two edges; the `as` alias is what gets exposed.
    assert {e["name"] for e in edges} == {"Button", "Glyph"}


def test_star_re_export_has_no_name() -> None:
    (edge,) = _edges('export * from "./everything.js";')
    assert edge["kind"] == "star"
    assert edge["from"] == "./everything.js"
    assert "name" not in edge


def test_star_as_namespace_re_export() -> None:
    (edge,) = _edges('export * as utils from "./utils.js";')
    assert edge["kind"] == "star"
    assert edge["name"] == "utils"
    assert edge["from"] == "./utils.js"


# --- CommonJS ---------------------------------------------------------------


def test_module_exports_assignment_is_default() -> None:
    (edge,) = _edges("module.exports = function () {};")
    assert edge["kind"] == "commonjs"
    assert edge["name"] == "default"


def test_module_exports_member() -> None:
    (edge,) = _edges("module.exports.parse = parse;")
    assert edge["kind"] == "commonjs"
    assert edge["name"] == "parse"


def test_exports_member_dot_and_bracket() -> None:
    dot = _edges("exports.foo = 1;")
    assert dot[0]["name"] == "foo"
    bracket = _edges('exports["bar"] = 2;')
    assert bracket[0]["name"] == "bar"


def test_reading_module_exports_is_not_an_export() -> None:
    assert _edges("const api = module.exports;") == []
    assert _edges("if (exports.foo === bar) {}") == []  # comparison, not assignment


def test_unrelated_module_variable_is_not_commonjs() -> None:
    assert _edges("const module = {}; module.foo = 1;") == []


# --- keywords that only look like exports ------------------------------------


def test_local_declarations_without_export_are_ignored() -> None:
    assert _edges("const a = 1; function f() {} class C {}") == []


def test_export_inside_string_or_comment_or_regex_is_ignored() -> None:
    assert _edges('var s = "export default x"; // export const y = 1') == []
    assert _edges("var re = /export const z = 1/g; var a = 1;") == []


def test_property_named_export_is_not_the_keyword() -> None:
    assert _edges('obj.export = 1; obj.exports = 2;') == []


# --- line numbers -----------------------------------------------------------


def test_line_numbers_point_at_the_keyword() -> None:
    src = "const x = 1;\nexport const y = 2;\n\nmodule.exports.z = z;"
    by_name = {e["name"]: e for e in _edges(src)}
    assert by_name["y"]["line"] == 2
    assert by_name["z"]["line"] == 4


# --- the JsClient.exports contract ------------------------------------------


def test_kind_counts_distinct_names_and_has_default(tmp_path: Path) -> None:
    body = (
        "export default {};\n"  # anonymous default -> name "default"
        "export const version = '1.0';\n"
        "export { helper } from './helpers.js';\n"
        "export * from './reexport-all.js';\n"
        "export function version() {}\n"  # duplicate name 'version'
    )
    out = JsClient().exports(_write(tmp_path, body))
    assert out["kind_counts"] == {
        "commonjs": 0,
        "default": 1,
        "named": 2,
        "re_export": 1,
        "star": 1,
    }
    assert out["has_default"] is True
    # 'version' appears twice but is one distinct name; star has no name.
    assert out["names"] == ["default", "helper", "version"]
    assert out["distinct"] == 3
    assert out["total"] == 5
    assert out["scan_capped"] is False


def test_has_default_false_without_a_default(tmp_path: Path) -> None:
    out = JsClient().exports(_write(tmp_path, "export const only = 1;"))
    assert out["has_default"] is False


def test_kind_filter(tmp_path: Path) -> None:
    body = (
        "export const a = 1;\n"
        "export { b } from './x.js';\n"
        "module.exports.c = c;\n"
    )
    out = JsClient().exports(_write(tmp_path, body), kind="re_export")
    assert [e["name"] for e in out["exports"]] == ["b"]
    assert out["kind"] == "re_export"
    # kind_counts still describes the whole file.
    assert out["kind_counts"]["named"] == 1
    assert out["kind_counts"]["commonjs"] == 1


def test_contains_filter(tmp_path: Path) -> None:
    body = "export const parseUser = 1; export const parseOrder = 2; export const render = 3;"
    out = JsClient().exports(_write(tmp_path, body), contains="PARSE")
    assert {e["name"] for e in out["exports"]} == {"parseUser", "parseOrder"}
    assert out["contains"] == "PARSE"


def test_paging(tmp_path: Path) -> None:
    body = "\n".join(f"export const name{i:03d} = {i};" for i in range(10))
    src = _write(tmp_path, body)
    first = JsClient().exports(src, offset=0, limit=4)
    assert first["count"] == 4
    assert first["total"] == 10
    assert first["has_more"] is True
    last = JsClient().exports(src, offset=8, limit=4)
    assert last["count"] == 2
    assert last["has_more"] is False


def test_scan_cap_is_reported() -> None:
    src = "\n".join(f"export const n{i} = {i};" for i in range(20))
    edges, capped = _scan_js_exports(src, max_edges=5)
    assert len(edges) == 5
    assert capped is True


def test_bad_kind_is_invalid_params(tmp_path: Path) -> None:
    src = _write(tmp_path, "export const a = 1;")
    with pytest.raises(JsReError) as info:
        JsClient().exports(src, kind="proxied")
    assert info.value.code == "invalid_params"


def test_oversized_contains_is_invalid_params(tmp_path: Path) -> None:
    src = _write(tmp_path, "export const a = 1;")
    with pytest.raises(JsReError) as info:
        JsClient().exports(src, contains="y" * (jsre_client._MAX_JS_STRINGS_CONTAINS + 1))
    assert info.value.code == "invalid_params"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        JsClient().exports(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_works_without_webcrack(tmp_path: Path) -> None:
    src = _write(tmp_path, "export function render() {}")
    client = JsClient(executable=None)
    assert client.available is False
    out = client.exports(src)
    assert out["names"] == ["render"]


def test_service_wiring_tags_the_jsre_backend(tmp_path: Path) -> None:
    service = AnalysisService(Settings.load())
    src = _write(tmp_path, "export default 1; export const two = 2;")
    result = service.js_exports(str(src))
    assert result.ok, result.error
    assert result.data is not None
    assert result.meta.get("backend") == "jsre"
    assert result.data["distinct"] == 2
    assert result.data["has_default"] is True


def test_docstring_names_the_fields() -> None:
    doc = _tool_docstring("js.exports")
    for token in ("exports", "kind", "re_export", "has_default", "names", "scan_capped"):
        assert token in doc, token
