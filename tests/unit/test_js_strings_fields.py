"""js.strings must extract and classify string literals straight from JS source.

Pure-Python scanner: no webcrack, so every case runs on a bare machine. Covers
quote/template/comment/regex handling, categorisation, dedup+count, filters,
paging and the scan ceiling.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre import client as jsre_client
from headless_re_mcp.backends.jsre.client import (
    JsClient,
    JsReError,
    _classify_js_string,
    _scan_js_string_literals,
    _unescape_js,
)
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


def _values(text: str) -> list[str]:
    literals, _capped = _scan_js_string_literals(text, max_literals=10_000)
    return literals


# --- the scanner itself -----------------------------------------------------


def test_reads_single_and_double_quoted_strings() -> None:
    assert _values("var a='hello', b=\"world\";") == ["hello", "world"]


def test_escapes_are_resolved() -> None:
    assert _values(r'''x="a\tb\n\u0041\x42\\end";''') == ["a\tb\nAB\\end"]


def test_a_quote_inside_the_other_quote_is_literal() -> None:
    assert _values(r"""var s = "it's a test";""") == ["it's a test"]
    assert _values(r'''var s = 'say "hi"';''') == ['say "hi"']


def test_line_and_block_comments_are_skipped() -> None:
    src = """
    // a comment with an apostrophe: don't capture this
    var real = 'kept';
    /* block "not a string" */
    var other = 'also-kept';
    """
    assert _values(src) == ["kept", "also-kept"]


def test_regex_literal_contents_are_not_mistaken_for_strings() -> None:
    # The quote inside the regex char class must not open a bogus string that
    # would then swallow the following real literal.
    src = "var re = /['\"]/g; var real = 'after-regex';"
    assert _values(src) == ["after-regex"]


def test_division_is_not_treated_as_a_regex() -> None:
    # After an identifier, '/' is division; the two real strings survive.
    src = "var a='x'; var y = count / 2; var b='y';"
    assert _values(src) == ["x", "y"]


def test_template_quasis_and_interpolated_strings() -> None:
    src = "var t = `pre ${fn('inner')} post ${'q'}`;"
    got = _values(src)
    assert "pre " in got
    assert " post " in got
    assert "inner" in got
    assert "q" in got


def test_nested_template_in_interpolation() -> None:
    src = "var t = `a${ `b${'deep'}c` }d`;"
    got = _values(src)
    assert "deep" in got
    assert "a" in got and "d" in got and "b" in got and "c" in got


def test_scan_cap_is_reported() -> None:
    src = ";".join(f"var v{i}='s{i}'" for i in range(20))
    literals, capped = _scan_js_string_literals(src, max_literals=5)
    assert len(literals) == 5
    assert capped is True


def test_unescape_handles_unicode_brace_and_unknown() -> None:
    assert _unescape_js(r"\u{1F600}") == "\U0001f600"
    assert _unescape_js(r"\q") == "q"  # unknown escape keeps the char
    assert _unescape_js("no escapes") == "no escapes"


# --- categorisation ---------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://api.example.com/v1", "url"),
        ("wss://socket.example.com/ws", "url"),
        ("//cdn.example.com/lib.js", "url"),
        ("/api/v1/users", "path"),
        ("/", "text"),
        ("hello world", "text"),
        ("plaintext", "text"),
    ],
)
def test_classification(value: str, expected: str) -> None:
    assert _classify_js_string(value) == expected


# --- the JsClient.strings contract ------------------------------------------


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "bundle.js"
    p.write_text(body, encoding="utf-8")
    return p


def test_dedup_counts_and_category_counts(tmp_path: Path) -> None:
    body = (
        "fetch('https://api.example.com/login');"
        "fetch('https://api.example.com/login');"
        "fetch('/api/v1/orders');"
        "console.log('just a message here');"
    )
    src = _write(tmp_path, body)
    out = JsClient().strings(src, min_length=1)

    by_value = {s["value"]: s for s in out["strings"]}
    assert by_value["https://api.example.com/login"]["count"] == 2
    assert by_value["https://api.example.com/login"]["category"] == "url"
    assert by_value["/api/v1/orders"]["category"] == "path"
    assert out["category_counts"]["url"] == 1
    assert out["category_counts"]["path"] == 1
    assert out["category_counts"]["text"] >= 1
    # distinct counts every unique literal, dups collapsed.
    assert out["distinct"] == 3


def test_category_filter(tmp_path: Path) -> None:
    body = "a='https://x.example/y'; b='/api/z'; c='plain text value';"
    src = _write(tmp_path, body)
    urls = JsClient().strings(src, min_length=1, category="url")
    assert [s["value"] for s in urls["strings"]] == ["https://x.example/y"]
    assert urls["category"] == "url"
    # category_counts still describes the whole (length/contains-filtered) set.
    assert urls["category_counts"]["path"] == 1
    assert urls["category_counts"]["text"] == 1


def test_contains_and_min_length_filters(tmp_path: Path) -> None:
    body = "a='short'; b='a-longer-token-value'; c='another-token';"
    src = _write(tmp_path, body)
    hits = JsClient().strings(src, min_length=1, contains="TOKEN")
    values = {s["value"] for s in hits["strings"]}
    assert values == {"a-longer-token-value", "another-token"}
    assert hits["contains"] == "TOKEN"

    long_only = JsClient().strings(src, min_length=15)
    assert [s["value"] for s in long_only["strings"]] == ["a-longer-token-value"]


def test_paging(tmp_path: Path) -> None:
    body = ";".join(f"v{i}='value-number-{i:03d}'" for i in range(10))
    src = _write(tmp_path, body)
    first = JsClient().strings(src, min_length=1, offset=0, limit=4)
    assert first["count"] == 4
    assert first["total"] == 10
    assert first["has_more"] is True
    last = JsClient().strings(src, min_length=1, offset=8, limit=4)
    assert last["count"] == 2
    assert last["has_more"] is False


def test_long_value_is_truncated_and_flagged(tmp_path: Path) -> None:
    huge = "x" * (jsre_client._MAX_JS_STRING_LEN + 50)
    src = _write(tmp_path, f"var s='{huge}';")
    out = JsClient().strings(src, min_length=1)
    row = out["strings"][0]
    assert len(row["value"]) == jsre_client._MAX_JS_STRING_LEN
    assert row["truncated"] is True


def test_bad_category_is_invalid_params(tmp_path: Path) -> None:
    src = _write(tmp_path, "a='x';")
    with pytest.raises(JsReError) as info:
        JsClient().strings(src, category="secret")
    assert info.value.code == "invalid_params"


def test_oversized_contains_is_invalid_params(tmp_path: Path) -> None:
    src = _write(tmp_path, "a='x';")
    with pytest.raises(JsReError) as info:
        JsClient().strings(src, contains="y" * (jsre_client._MAX_JS_STRINGS_CONTAINS + 1))
    assert info.value.code == "invalid_params"


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        JsClient().strings(tmp_path / "nope.js")
    assert info.value.code == "not_found"


def test_works_without_webcrack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """strings must run even when no webcrack is configured (unlike deobfuscate)."""
    src = _write(tmp_path, "fetch('/api/health');")
    client = JsClient(executable=None)
    assert client.available is False
    out = client.strings(src, min_length=1)
    assert any(s["value"] == "/api/health" for s in out["strings"])


def test_docstring_names_the_fields() -> None:
    doc = _tool_docstring("js.strings")
    for token in ("strings", "category", "category_counts", "distinct", "scan_capped"):
        assert token in doc, token
