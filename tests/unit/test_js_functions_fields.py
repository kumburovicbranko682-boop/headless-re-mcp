"""js.functions maps the function and class definitions a script declares.

The core is extract_js_functions, pure over the source text, so most of this
drives it directly; a few tests wire it through JsClient/AnalysisService.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as client_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_static import extract_js_functions
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


def _by_name(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(e["name"]): e for e in payload["items"]}  # type: ignore[index,union-attr]


def test_function_declaration_with_params() -> None:
    payload = extract_js_functions("function add(a, b) { return a + b; }")
    fn = _by_name(payload)["add"]
    assert fn["kind"] == "function"
    assert fn["params"] == ["a", "b"]
    assert fn["param_count"] == 2
    assert fn["async"] is False
    assert fn["generator"] is False
    assert fn["line"] == 1
    assert payload["kinds"] == {"function": 1}


def test_async_generator_declaration_flags() -> None:
    payload = extract_js_functions("async function* stream(x) { yield x; }")
    fn = _by_name(payload)["stream"]
    assert fn["async"] is True
    assert fn["generator"] is True


def test_named_function_expression_binding_is_captured() -> None:
    payload = extract_js_functions("const handler = function inner(evt) {};")
    names = _by_name(payload)
    # The binding name wins; the internal name is not double-counted.
    assert "handler" in names
    assert "inner" not in names
    assert names["handler"]["kind"] == "function"
    assert names["handler"]["params"] == ["evt"]


def test_arrow_functions_paren_and_single_param() -> None:
    payload = extract_js_functions("const f = (a, b) => a; const g = x => x * 2;")
    names = _by_name(payload)
    assert names["f"]["kind"] == "arrow"
    assert names["f"]["params"] == ["a", "b"]
    assert names["g"]["params"] == ["x"]
    assert names["g"]["async"] is False


def test_async_arrow_and_no_param_arrow() -> None:
    payload = extract_js_functions("const load = async () => { await q(); };")
    fn = _by_name(payload)["load"]
    assert fn["kind"] == "arrow"
    assert fn["async"] is True
    assert fn["params"] == []
    assert fn["param_count"] == 0


def test_param_default_reduced_to_name() -> None:
    payload = extract_js_functions("function h(a, b = 2, ...rest) {}")
    assert _by_name(payload)["h"]["params"] == ["a", "b", "...rest"]


def test_class_with_methods_and_superclass() -> None:
    src = (
        "class Widget extends Base {\n"
        "  constructor(opts) { super(); this.o = opts; }\n"
        "  render(x) { return x; }\n"
        "  static make() { return new Widget(); }\n"
        "  async load() { await fetch('/x'); }\n"
        "  get size() { return 1; }\n"
        "}\n"
    )
    payload = extract_js_functions(src)
    names = _by_name(payload)
    cls = names["Widget"]
    assert cls["kind"] == "class"
    assert cls["superclass"] == "Base"
    assert cls["method_count"] == 5

    ctor = names["constructor"]
    assert ctor["kind"] == "method"
    assert ctor["parent"] == "Widget"
    assert ctor["constructor"] is True
    assert ctor["params"] == ["opts"]

    assert names["make"]["static"] is True
    assert names["load"]["async"] is True
    assert names["size"]["accessor"] == "get"
    assert names["render"]["static"] is False


def test_method_shaped_token_inside_a_method_body_is_not_a_member() -> None:
    # foo() inside render's body is a call, at brace depth > 0, not a member.
    src = "class C {\n  render() {\n    helper();\n    if (x) { y(); }\n  }\n}\n"
    payload = extract_js_functions(src)
    names = _by_name(payload)
    assert names["C"]["method_count"] == 1
    assert "render" in names
    assert "helper" not in names
    assert "if" not in names


def test_nested_arrow_inside_a_method_is_still_found() -> None:
    src = "class C {\n  go() {\n    const inner = (z) => z + 1;\n    return inner;\n  }\n}\n"
    payload = extract_js_functions(src)
    names = _by_name(payload)
    assert names["go"]["kind"] == "method"
    assert names["inner"]["kind"] == "arrow"
    assert names["inner"]["params"] == ["z"]


def test_keyword_inside_string_or_comment_is_not_a_definition() -> None:
    src = (
        "const s = 'function fake(a){}';\n"
        "// function alsoFake(b){}\n"
        "/* class GhostClass {} */\n"
        "function real() {}\n"
    )
    payload = extract_js_functions(src)
    names = _by_name(payload)
    assert set(names) == {"real"}


def test_exported_flag_for_top_level_definitions() -> None:
    src = (
        "export function pub() {}\n"
        "export default class Main {}\n"
        "function priv() {}\n"
        "export const arrow = () => 1;\n"
    )
    payload = extract_js_functions(src)
    names = _by_name(payload)
    assert names["pub"]["exported"] is True
    assert names["Main"]["exported"] is True
    assert names["priv"]["exported"] is False
    assert names["arrow"]["exported"] is True


def test_items_are_ordered_by_source_line() -> None:
    src = "function a() {}\nfunction b() {}\nclass C {\n  m() {}\n}\n"
    payload = extract_js_functions(src)
    order = [str(item["name"]) for item in payload["items"]]
    assert order == ["a", "b", "C", "m"]


def test_kinds_tally_and_class_count() -> None:
    src = "function a(){}\nconst b=()=>1;\nclass C{ m(){} n(){} }\n"
    payload = extract_js_functions(src)
    assert payload["kinds"] == {"function": 1, "arrow": 1, "class": 1, "method": 2}
    assert payload["class_count"] == 1
    assert payload["total"] == 5


def test_paging() -> None:
    src = "\n".join(f"function f{i}() {{}}" for i in range(5))
    page = extract_js_functions(src, offset=0, limit=2)
    assert page["count"] == 2
    assert page["total"] == 5
    assert page["has_more"] is True
    assert page["offset"] == 0
    tail = extract_js_functions(src, offset=4, limit=2)
    assert tail["count"] == 1
    assert tail["has_more"] is False


def test_no_definitions_is_empty() -> None:
    payload = extract_js_functions("const x = 1 + 2; console.log(x);")
    assert payload["items"] == []
    assert payload["total"] == 0
    assert payload["kinds"] == {}
    assert payload["class_count"] == 0


# --- client + service integration -------------------------------------------


def test_client_functions_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text("function ping() {}", encoding="utf-8")
    payload = JsClient(None).functions(js)
    assert _by_name(payload)["ping"]["kind"] == "function"


def test_client_functions_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        JsClient(None).functions(tmp_path / "nope.js")
    assert caught.value.code == "not_found"


def test_client_functions_oversized_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_mod, "_MAX_INPUT_BYTES", 8)
    js = tmp_path / "big.js"
    js.write_text("function ping() {}" * 4, encoding="utf-8")
    with pytest.raises(JsReError) as caught:
        JsClient(None).functions(js)
    assert caught.value.code == "too_large"


def test_service_js_functions_dispatch(tmp_path: Path) -> None:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    js = tmp_path / "s.js"
    js.write_text("export class Api { get() {} }", encoding="utf-8")
    result = service.js_functions(str(js))
    assert result.ok, result.error
    assert result.data is not None
    names = _by_name(result.data)
    assert names["Api"]["kind"] == "class"
    assert names["get"]["parent"] == "Api"


def test_js_functions_tool_is_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_js_wasm_tools(service)}
    assert "js.functions" in names


def test_js_functions_docstring_names_its_shape() -> None:
    doc = " ".join(_tool_docstring("js.functions").split())
    assert "items" in doc
    assert "kinds" in doc
    assert "method_count" in doc
    assert "superclass" in doc
    assert "exported" in doc
    assert "too_large" in doc
