"""js.strings extracts string literals from JavaScript, dependency-free.

js.deobfuscate/beautify/unpack_bundle all need webcrack (Node); js.strings reads
and lexes the source in-process, so it stays available without webcrack, and
pulls out the URLs/endpoints/messages/keys that live in string literals. These
cover the lexer (comments, regex vs. division, the three literal forms, template
chunks and interpolation skipping), escape decoding, the min_length/name_filter,
the collect cap and text clip, the client paging and errors, the webcrack-free
path, service routing, and the read-only classification.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre import js_strings as js_strings_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_strings import _MAX_STRING_TEXT, extract_strings
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


def _texts(source: str, **kwargs: Any) -> list[str]:
    rows, _capped = extract_strings(source, **kwargs)
    return [row["text"] for row in rows]


def test_extracts_single_and_double_with_kinds_and_order() -> None:
    src = "var a = 'first-str'; var b = \"second-str\";"
    rows, capped = extract_strings(src)
    assert capped is False
    assert [(r["text"], r["kind"]) for r in rows] == [
        ("first-str", "single"),
        ("second-str", "double"),
    ]
    assert [r["offset"] for r in rows] == sorted(r["offset"] for r in rows)
    # offset points at the opening quote.
    assert src[rows[0]["offset"]] == "'"
    assert rows[0]["size"] == len("first-str")


def test_skips_line_and_block_comments() -> None:
    src = "// 'not-a-string' here\n/* \"also-not\" */ var s = 'real-one';"
    assert _texts(src) == ["real-one"]


def test_regex_literal_quotes_are_not_strings() -> None:
    # The /['"]/ is a regex (prev significant token is '='), so its quotes must
    # not be read as a string literal that swallows the rest of the line.
    src = "var re = /['\"]/g; var s = \"kept-value\";"
    assert _texts(src) == ["kept-value"]


def test_division_is_not_mistaken_for_regex() -> None:
    src = "var x = 100 / 4 / 2; var s = \"after-div\";"
    assert _texts(src) == ["after-div"]


def test_decodes_hex_and_unicode_escapes() -> None:
    src = r'var u = "\x68\x74\x74\x70://ex.test"; var c = "\u0041\u0042C";'
    texts = _texts(src)
    assert "http://ex.test" in texts
    assert "ABC" in texts


def test_decodes_unicode_code_point_escape() -> None:
    rows, _ = extract_strings(r'var e = "smile\u{1F600}end";', min_length=1)
    assert rows[0]["text"] == "smile\U0001f600end"


def test_template_static_chunks_split_on_interpolation() -> None:
    src = "const u = `https://api.test/${id}/v2`;"
    rows, _ = extract_strings(src)
    assert [(r["text"], r["kind"]) for r in rows] == [
        ("https://api.test/", "template"),
        ("/v2", "template"),
    ]


def test_template_interpolation_expression_is_skipped() -> None:
    # The nested "inner" lives inside ${...} and is not separately extracted;
    # only the static chunks "a" and "b" are.
    rows, _ = extract_strings('`a${f("inner")}b`', min_length=1)
    assert [r["text"] for r in rows] == ["a", "b"]


def test_template_interpolation_brace_in_nested_string_is_respected() -> None:
    # A '}' inside a string within ${...} must not end the interpolation early.
    rows, _ = extract_strings('`x${f("}")}y`', min_length=1)
    assert [r["text"] for r in rows] == ["x", "y"]


def test_min_length_drops_shorter_literals() -> None:
    src = "var a = 'ok'; var b = 'longer-value';"
    assert _texts(src, min_length=3) == ["longer-value"]
    assert set(_texts(src, min_length=1)) == {"ok", "longer-value"}


def test_name_filter_is_case_insensitive_and_sets_total() -> None:
    src = "var a = 'https://c2.test/beacon'; var b = 'nothing-here';"
    rows, _ = extract_strings(src, name_filter="HTTPS")
    assert [r["text"] for r in rows] == ["https://c2.test/beacon"]


def test_unterminated_string_at_eof_is_best_effort() -> None:
    rows, _ = extract_strings('var s = "no-close-quote', min_length=1)
    assert rows[0]["text"] == "no-close-quote"


def test_collect_cap_sets_scan_capped(monkeypatch: Any) -> None:
    monkeypatch.setattr(js_strings_mod, "_MAX_STRINGS_COLLECT", 2)
    src = "'one-str';'two-str';'three-str';'four-str';"
    rows, capped = extract_strings(src)
    assert capped is True
    assert len(rows) == 2


def test_huge_literal_is_clipped_and_flagged() -> None:
    src = '"' + "A" * (_MAX_STRING_TEXT + 10) + '"'
    rows, _ = extract_strings(src)
    assert len(rows) == 1
    assert len(rows[0]["text"]) == _MAX_STRING_TEXT
    assert rows[0]["text_truncated"] is True
    assert rows[0]["size"] == _MAX_STRING_TEXT + 10


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bundle.js"
    p.write_text(text, encoding="utf-8")
    return p


def test_client_strings_pages_and_totals(tmp_path: Path) -> None:
    src = ";".join(f"var v{i} = 'endpoint-{i:02d}'" for i in range(10))
    out = JsClient().strings(_write(tmp_path, src), limit=3)
    assert out["count"] == 3
    assert out["total"] == 10
    assert out["offset"] == 0
    assert out["has_more"] is True
    assert out["scan_capped"] is False
    page2 = JsClient().strings(_write(tmp_path, src), offset=9, limit=3)
    assert page2["count"] == 1
    assert page2["has_more"] is False


def test_client_strings_works_without_webcrack(tmp_path: Path) -> None:
    # No executable configured: js.strings is dependency-free and must still run
    # (unlike deobfuscate/beautify/unpack_bundle, which need webcrack).
    client = JsClient(executable=None)
    assert client.available is False
    out = client.strings(_write(tmp_path, "var a = 'still-works';"))
    assert [r["text"] for r in out["strings"]] == ["still-works"]


def test_client_strings_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        JsClient().strings(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_client_strings_page_limit_is_capped(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_JS_STRINGS_PAGE", 2)
    src = ";".join(f"'value-{i:02d}'" for i in range(6))
    out = JsClient().strings(_write(tmp_path, src), limit=1000)
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_service_js_strings_routes_to_client(tmp_path: Path) -> None:
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService()
    try:
        src = "var a = 'https://api.example.com/token'; var b = 'noise';"
        p = _write(tmp_path, src)
        result = service.js_strings(str(p), name_filter="api.example")
        assert result.ok and result.data is not None
        assert [r["text"] for r in result.data["strings"]] == [
            "https://api.example.com/token"
        ]
        assert result.data["total"] == 1
    finally:
        service.close_all()


def test_js_strings_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("js.strings").split())
    assert "string literals" in doc
    assert "min_length" in doc
    assert "name_filter" in doc
    assert "scan_capped" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "js.strings" in _READ_ONLY_NAMES
