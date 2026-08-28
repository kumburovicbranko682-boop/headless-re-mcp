"""js.capabilities: a node-free fingerprint of a script's security-relevant APIs.

It counts references to a fixed API table over the js.imports token stream, so a
name only counts in the syntactic shape that makes it meaningful. These tests pin
that contract on hand-written JS: the call/ref/member/timer match shapes, the
property-vs-global disambiguation (x.eval is not eval), string and comment
immunity, occurrence counting and the count-then-name ordering, the empty
fingerprint, truncation on an open literal, the token cap, the not_found and
too_large guards, plus the tool docstring naming the returned fields.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, scan_js_capabilities
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(text, encoding="utf-8")
    return target


def _by_api(payload: dict) -> dict[str, dict]:
    return {row["api"]: row for row in payload["capabilities"]}


def test_each_category_is_detected(tmp_path: Path) -> None:
    src = """
eval(code);
const f = new Function("return 1");
fetch(url);
const ws = new WebSocket(target);
localStorage.setItem(key, atob(blob));
node.innerHTML = markup;
worker.postMessage(payload);
document.cookie = pair;
WebAssembly.instantiate(bytes);
"""
    payload = scan_js_capabilities(_write(tmp_path, src))
    rows = _by_api(payload)
    assert rows["eval"]["category"] == "code_execution"
    assert rows["Function"]["category"] == "code_execution"
    assert rows["fetch"]["category"] == "network"
    assert rows["WebSocket"]["category"] == "network"
    assert rows["localStorage"]["category"] == "storage"
    assert rows["atob"]["category"] == "encoding"
    assert rows["innerHTML"]["category"] == "dom_injection"
    assert rows["postMessage"]["category"] == "messaging"
    assert rows["cookie"]["category"] == "storage"
    assert rows["WebAssembly"]["category"] == "wasm"
    assert payload["categories"] == sorted(
        {"code_execution", "network", "storage", "encoding", "dom_injection", "messaging", "wasm"}
    )
    assert payload["scan_capped"] is False
    assert payload["truncated"] is False


def test_names_in_strings_and_comments_never_count(tmp_path: Path) -> None:
    src = """
// eval(payload) is what the sample used to do
/* fetch('https://example.com') */
var note = "eval(x) atob(y) innerHTML";
var tpl = `WebSocket localStorage`;
"""
    payload = scan_js_capabilities(_write(tmp_path, src))
    assert payload["capabilities"] == []
    assert payload["categories"] == []


def test_property_access_is_not_the_global(tmp_path: Path) -> None:
    src = "sandbox.eval(code);\nwrapper.fetch(url);\nshim.WebSocket = null;\nns.WebAssembly;\n"
    payload = scan_js_capabilities(_write(tmp_path, src))
    assert payload["capabilities"] == []


def test_member_names_only_count_behind_a_dot(tmp_path: Path) -> None:
    src = "var innerHTML = compute();\nvar cookie = jar;\npostMessage(data);\n"
    payload = scan_js_capabilities(_write(tmp_path, src))
    assert payload["capabilities"] == []


def test_optional_chaining_reaches_the_member_table(tmp_path: Path) -> None:
    payload = scan_js_capabilities(_write(tmp_path, "target?.postMessage(msg);\n"))
    rows = _by_api(payload)
    assert rows["postMessage"]["category"] == "messaging"
    assert rows["postMessage"]["count"] == 1


def test_timers_only_count_with_a_string_first_argument(tmp_path: Path) -> None:
    src = 'setTimeout(tick, 100);\nsetTimeout("run()", 100);\nsetInterval(`poll()`, 50);\n'
    payload = scan_js_capabilities(_write(tmp_path, src))
    rows = _by_api(payload)
    assert set(rows) == {"setTimeout", "setInterval"}
    assert rows["setTimeout"]["count"] == 1
    assert rows["setTimeout"]["category"] == "code_execution"
    assert rows["setInterval"]["count"] == 1


def test_call_table_names_need_a_call(tmp_path: Path) -> None:
    # Aliasing (var e = eval) is not counted: the table encodes the call shape.
    payload = scan_js_capabilities(_write(tmp_path, "var e = eval;\nvar g = fetch;\n"))
    assert payload["capabilities"] == []


def test_occurrences_are_counted_and_ordered(tmp_path: Path) -> None:
    src = "eval(a);\neval(b);\neval(c);\natob(x);\nbtoa(y);\n"
    payload = scan_js_capabilities(_write(tmp_path, src))
    assert [(row["api"], row["count"]) for row in payload["capabilities"]] == [
        ("eval", 3),
        ("atob", 1),
        ("btoa", 1),
    ]


def test_benign_source_yields_an_empty_fingerprint(tmp_path: Path) -> None:
    payload = scan_js_capabilities(_write(tmp_path, "const total = items.reduce(sum, 0);\n"))
    assert payload["capabilities"] == []
    assert payload["categories"] == []
    assert payload["input_bytes"] > 0


def test_open_literal_sets_truncated_but_keeps_earlier_hits(tmp_path: Path) -> None:
    payload = scan_js_capabilities(_write(tmp_path, "eval(x);\nvar s = 'no end\n"))
    rows = _by_api(payload)
    assert rows["eval"]["count"] == 1
    assert payload["truncated"] is True


def test_token_cap_sets_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_TOKENS", 4)
    payload = scan_js_capabilities(_write(tmp_path, "var a = 1;\neval(late);\n"))
    assert payload["scan_capped"] is True
    assert "eval" not in _by_api(payload)


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        scan_js_capabilities(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_oversized_input_is_too_large(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    with pytest.raises(JsReError) as info:
        scan_js_capabilities(_write(tmp_path, "eval(payload);\n"))
    assert info.value.code == "too_large"


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
    doc = _tool_docstring("js.capabilities")
    assert "Answers with capabilities" in doc
    assert "category" in doc
    assert "scan_capped" in doc and "truncated" in doc
    assert "verdict" in doc
