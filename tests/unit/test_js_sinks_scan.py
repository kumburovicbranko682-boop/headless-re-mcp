"""js.sinks must flag eval-like and DOM-injection shapes, with honest counts."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import scan_sinks
from headless_re_mcp.backends.jsre.client import _MAX_SINKS, JsReError
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


def _write(tmp_path: Path, body: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(body, encoding="utf-8")
    return target


def test_flags_each_sink_kind_with_position(tmp_path: Path) -> None:
    """One hit per risky shape, located by line, in document order."""
    js = (
        "var x = 1;\n"
        "eval(userInput);\n"
        "var f = new Function('a', 'return a');\n"
        "setTimeout('doThing()', 100);\n"
        "document.write(payload);\n"
        "el.innerHTML = markup;\n"
        "el.insertAdjacentHTML('beforeend', markup);\n"
        "execScript(code);\n"
    )
    result = scan_sinks(_write(tmp_path, js))
    kinds = [item["kind"] for item in result["items"]]
    assert kinds == [
        "eval",
        "function_constructor",
        "settimeout_string",
        "document_write",
        "inner_html_assignment",
        "insert_adjacent_html",
        "exec_script",
    ]
    assert result["count"] == 7
    assert result["by_kind"]["eval"] == 1
    # Positions: eval is on line 2, column 1; offset is document order.
    eval_hit = result["items"][0]
    assert eval_hit["line"] == 2 and eval_hit["column"] == 1
    assert eval_hit["snippet"] == "eval(userInput);"
    assert result["items"] == sorted(result["items"], key=lambda i: i["offset"])
    assert "items_truncated" not in result


def test_precise_shapes_do_not_overmatch(tmp_path: Path) -> None:
    """The name alone is not a hit -- only the risky call/assignment form is."""
    js = (
        "medieval(x);\n"  # not eval
        "var r = el.innerHTML;\n"  # a read, not an assignment
        "if (a === b) {}\n"  # === is not an innerHTML assign
        "setTimeout(handler, 100);\n"  # function arg, not a string
        "myFunction(y);\n"  # not the Function constructor
        "retrieval(z);\n"  # not eval
    )
    result = scan_sinks(_write(tmp_path, js))
    assert result["count"] == 0
    assert result["by_kind"] == {}
    assert result["items"] == []


def test_settimeout_string_but_not_function(tmp_path: Path) -> None:
    js = 'setInterval("tick()", 50);\nsetInterval(tick, 50);\n'
    result = scan_sinks(_write(tmp_path, js))
    assert result["count"] == 1
    assert result["items"][0]["kind"] == "settimeout_string"
    assert result["items"][0]["line"] == 1


def test_by_kind_counts_all_but_items_are_capped(tmp_path: Path) -> None:
    """by_kind is the true histogram; items is capped and says so."""
    js = "eval(a);\n" * (_MAX_SINKS + 25)
    result = scan_sinks(_write(tmp_path, js))
    assert result["by_kind"]["eval"] == _MAX_SINKS + 25
    assert result["count"] == _MAX_SINKS
    assert len(result["items"]) == _MAX_SINKS
    assert result["items_truncated"] is True
    assert result["items_total"] == _MAX_SINKS + 25
    assert result["items_limit"] == _MAX_SINKS


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as excinfo:
        scan_sinks(tmp_path / "nope.js")
    assert excinfo.value.code == "not_found"


def test_bytes_and_path_reported(tmp_path: Path) -> None:
    target = _write(tmp_path, "eval(x);\n")
    result = scan_sinks(target)
    assert result["path"] == str(target)
    assert result["bytes"] == len(b"eval(x);\n")


def test_sinks_docstring_contract() -> None:
    doc = _tool_docstring("js.sinks")
    assert "by_kind" in doc
    assert "js.deobfuscate" in doc
    assert "items_truncated" in doc
    assert "heuristic" in doc
