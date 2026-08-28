"""js.strings: a node-free JavaScript string-literal extractor.

Unlike js.deobfuscate / js.beautify / js.unpack_bundle, which shell out to
webcrack (Node), js.strings scans the source in pure Python. These tests pin
the scanner's contract on hand-written JavaScript -- quote kinds, escape
decoding, comment skipping, the min_length filter, dedup/order, the collect and
page caps, the truncated flag for an unterminated literal, and the not_found /
too_large guards -- plus the tool docstring naming the returned fields.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, scan_js_strings
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(text, encoding="utf-8")
    return target


def test_extracts_all_three_quote_kinds(tmp_path: Path) -> None:
    src = "const a = 'single'; let b = \"double\"; const c = `template-literal`;"
    payload = scan_js_strings(_write(tmp_path, src))
    assert set(payload["strings"]) == {"single", "double", "template-literal"}
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False
    assert payload["count"] == payload["total"] == 3


def test_decodes_hex_and_unicode_escapes(tmp_path: Path) -> None:
    # \x and \u escapes are the classic string-obfuscation trick.
    src = r"""var u = "\x68\x74\x74\x70\x73"; var s = "a\u002fb"; var c = "\u{1f600}";"""
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert "https" in payload["strings"]
    assert "a/b" in payload["strings"]
    assert "\U0001f600" in payload["strings"]


def test_skips_line_and_block_comments(tmp_path: Path) -> None:
    src = (
        "// this 'commented' string must not appear\n"
        "/* nor \"this block\" one */\n"
        "var real = 'kept';\n"
    )
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert payload["strings"] == ["kept"]


def test_min_length_filters_short_literals(tmp_path: Path) -> None:
    src = "var a='ab'; var b='abcd'; var c='abcdef';"
    payload = scan_js_strings(_write(tmp_path, src), min_length=4)
    assert payload["strings"] == ["abcd", "abcdef"]
    assert payload["min_length"] == 4


def test_dedup_keeps_first_appearance_order(tmp_path: Path) -> None:
    src = "f('alpha'); g('beta'); h('alpha'); k('gamma');"
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert payload["strings"] == ["alpha", "beta", "gamma"]


def test_escaped_quote_does_not_end_the_literal(tmp_path: Path) -> None:
    src = r"""var a = 'it\'s here'; var b = "say \"hi\"";"""
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert "it's here" in payload["strings"]
    assert 'say "hi"' in payload["strings"]


def test_unterminated_literal_sets_truncated(tmp_path: Path) -> None:
    src = "var ok = 'closed'; var bad = 'never ends"
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert "closed" in payload["strings"]
    assert payload["truncated"] is True


def test_unterminated_block_comment_sets_truncated(tmp_path: Path) -> None:
    src = "var ok = 'closed'; /* open comment to EOF"
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert payload["truncated"] is True


def test_collect_cap_sets_scan_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.backends.jsre.client._MAX_JS_STRINGS_COLLECT", 3
    )
    src = ";".join(f"f('str{i}')" for i in range(10))
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert payload["total"] == 3
    assert payload["scan_capped"] is True


def test_page_window_and_has_more(tmp_path: Path) -> None:
    src = ";".join(f"f('unique{i:03d}')" for i in range(25))
    payload = scan_js_strings(_write(tmp_path, src), offset=0, limit=10, min_length=1)
    assert payload["count"] == 10
    assert payload["total"] == 25
    assert payload["offset"] == 0
    assert payload["has_more"] is True

    tail = scan_js_strings(_write(tmp_path, src), offset=20, limit=10, min_length=1)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def test_per_string_clip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_STRING_LEN", 8)
    src = "var a = '" + ("A" * 50) + "';"
    payload = scan_js_strings(_write(tmp_path, src), min_length=1)
    assert payload["strings"] == ["A" * 8]


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        scan_js_strings(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_oversized_input_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Shrink the byte cap instead of writing a 16 MiB file: _require_existing_file
    # reads the module global at call time, so a small file now trips too_large.
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_INPUT_BYTES", 8)
    target = _write(tmp_path, "var a = 'x';")  # well over eight bytes
    with pytest.raises(JsReError) as info:
        scan_js_strings(target)
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
    doc = _tool_docstring("js.strings")
    assert "Answers with" in doc
    assert "input_bytes" in doc
    assert "has_more" in doc
    assert "scan_capped" in doc
