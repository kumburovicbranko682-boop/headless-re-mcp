"""js.strings / js.urls: pure-Python JS literal and IOC extraction.

These fill the JavaScript line's extraction gap (it had only webcrack-backed
transforms). The tokenizer must skip comments, decode escapes and -- the hard
part -- not mistake a quote inside a regex literal for a string. The indicator
scan mirrors apk.urls. All of it runs without Node/webcrack.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as client_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_static import (
    extract_js_indicators,
    extract_js_strings,
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


def _values(payload: dict[str, object]) -> list[str]:
    return [str(row["value"]) for row in payload["items"]]  # type: ignore[index]


# --- extract_js_strings -----------------------------------------------------


def test_extracts_single_double_and_template_literals() -> None:
    src = "const a='alpha'; let b=\"beta\"; const c=`gamma`;"
    payload = extract_js_strings(src, min_length=1)
    rows = {row["value"]: row["quote"] for row in payload["items"]}
    assert rows == {"alpha": "single", "beta": "double", "gamma": "template"}
    assert payload["total"] == 3


def test_skips_line_and_block_comments() -> None:
    src = "// 'not a string'\n/* \"also not\" */\nconst x = 'real';"
    assert _values(extract_js_strings(src, min_length=1)) == ["real"]


def test_a_quote_inside_a_regex_is_not_a_string() -> None:
    # The classic false positive: /["']/ carries quote characters that must
    # stay inside the regex literal, not open a string that eats the file.
    src = "const re = /[\"']/g; const after = 'kept';"
    assert _values(extract_js_strings(src, min_length=1)) == ["kept"]


def test_division_is_not_mistaken_for_a_regex() -> None:
    # A '/' after a value is division; the following quote still opens a string.
    src = "let n = size / 2; const s = 'tail';"
    assert _values(extract_js_strings(src, min_length=1)) == ["tail"]


def test_regex_after_return_keyword_is_skipped() -> None:
    src = "function f(){ return /a'b/; } const s = \"end\";"
    assert _values(extract_js_strings(src, min_length=1)) == ["end"]


def test_decodes_escape_sequences() -> None:
    src = (
        r"const a = 'tab\there'; const b = " + '"\\x41\\x42";'
        + r" const c = 'u\u0041'; const d = '\u{1F600}';"
    )
    values = _values(extract_js_strings(src, min_length=1))
    assert "tab\there" in values
    assert "AB" in values
    assert "uA" in values
    assert "\U0001f600" in values


def test_min_length_filters_short_values() -> None:
    src = "const a='ab'; const b='abcd';"
    assert _values(extract_js_strings(src, min_length=4)) == ["abcd"]


def test_reports_line_numbers_at_the_literal_start() -> None:
    src = "\n\nconst a = 'first';\nconst b = 'second';"
    rows = {row["value"]: row["line"] for row in extract_js_strings(src, min_length=1)["items"]}
    assert rows == {"first": 3, "second": 4}


def test_unterminated_single_quote_stops_at_newline() -> None:
    src = "const a = 'runaway\nconst b = 'safe';"
    payload = extract_js_strings(src, min_length=1)
    runaway = next(row for row in payload["items"] if row["value"] == "runaway")
    assert runaway["unterminated"] is True
    # The stray quote did not swallow the rest of the file.
    assert "safe" in _values(payload)


def test_pages_the_string_listing() -> None:
    src = "".join(f"var v{i}='value{i}';" for i in range(5))
    payload = extract_js_strings(src, min_length=1, offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True
    assert payload["offset"] == 0


def test_long_value_is_truncated_and_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.js_static as js_static

    monkeypatch.setattr(js_static, "_MAX_JS_STRING_LEN", 8)
    src = "const a = '" + "A" * 40 + "';"
    row = extract_js_strings(src, min_length=1)["items"][0]
    assert row["length"] == 8
    assert row["truncated"] is True


def test_scan_capped_when_collection_cap_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.js_static as js_static

    monkeypatch.setattr(js_static, "_MAX_JS_STRINGS_COLLECT", 2)
    src = "'a1';'b2';'c3';'d4';"
    payload = extract_js_strings(src, min_length=1)
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


def test_template_keeps_its_interpolation_raw() -> None:
    src = "const t = `pre ${a + `${b}`} post`;"
    values = _values(extract_js_strings(src, min_length=1))
    assert values == ["pre ${a + `${b}`} post"]


# --- extract_js_indicators --------------------------------------------------


def test_indicators_collect_dedup_and_rollup_hosts() -> None:
    src = (
        "fetch('https://api.evil.test/a');"
        "fetch('https://api.evil.test/b');"
        "ws = 'wss://api.evil.test/live';"
    )
    payload = extract_js_indicators(src)
    assert payload["total"] == 3
    hosts = {row["host"]: row["count"] for row in payload["hosts"]}
    assert hosts == {"api.evil.test": 3}


def test_indicators_catch_urls_in_comments() -> None:
    src = "// beacon http://tracker.test/px.gif\nconst x = 1;"
    payload = extract_js_indicators(src)
    assert [row["url"] for row in payload["urls"]] == ["http://tracker.test/px.gif"]


def test_indicators_strip_trailing_punctuation() -> None:
    src = "const s = 'see https://host.test/path).';"
    payload = extract_js_indicators(src)
    assert payload["urls"][0]["url"] == "https://host.test/path"


def test_indicators_validate_ipv4_octets() -> None:
    src = "hosts = ['10.0.0.5', '256.1.1.1', '192.168.1.1'];"
    payload = extract_js_indicators(src)
    assert payload["ips"] == ["10.0.0.5", "192.168.1.1"]


def test_indicators_page_the_url_listing() -> None:
    src = "".join(f"u='https://h{i}.test/x';" for i in range(4))
    payload = extract_js_indicators(src, offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 4
    assert payload["has_more"] is True


# --- client integration -----------------------------------------------------


def test_client_strings_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text("const key = 'AKIA1234567890';", encoding="utf-8")
    payload = JsClient(None).strings(js, min_length=4)
    assert "AKIA1234567890" in _values(payload)


def test_client_urls_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text("fetch('https://c2.test/beacon');", encoding="utf-8")
    payload = JsClient(None).urls(js)
    assert payload["urls"][0]["host"] == "c2.test"


def test_client_strings_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        JsClient(None).strings(tmp_path / "nope.js")
    assert caught.value.code == "not_found"


def test_client_urls_oversized_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_mod, "_MAX_INPUT_BYTES", 16)
    js = tmp_path / "big.js"
    js.write_text("fetch('https://a.test/');" * 10, encoding="utf-8")
    with pytest.raises(JsReError) as caught:
        JsClient(None).urls(js)
    assert caught.value.code == "too_large"


# --- service + tool registration --------------------------------------------


def test_service_js_strings_and_urls_dispatch(tmp_path: Path) -> None:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    js = tmp_path / "s.js"
    js.write_text("const u = 'https://svc.test/api'; const s = 'hello';", encoding="utf-8")

    strings = service.js_strings(str(js), min_length=4)
    assert strings.ok, strings.error
    assert strings.data is not None
    assert "hello" in _values(strings.data)

    urls = service.js_urls(str(js))
    assert urls.ok, urls.error
    assert urls.data is not None
    assert urls.data["urls"][0]["host"] == "svc.test"


def test_new_js_tools_are_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_js_wasm_tools(service)}
    assert {"js.strings", "js.urls"}.issubset(names)


def test_js_strings_docstring_names_its_shape() -> None:
    doc = _tool_docstring("js.strings")
    assert "value" in doc
    assert "quote" in doc
    assert "unterminated" in doc
    assert "has_more" in doc
    assert "too_large" in doc


def test_js_urls_docstring_names_its_shape() -> None:
    doc = _tool_docstring("js.urls")
    assert "scheme" in doc
    assert "host" in doc
    assert "ips" in doc
    assert "has_more" in doc
