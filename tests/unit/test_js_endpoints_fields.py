"""js.endpoints: a node-free extractor of the URLs a JS file talks to.

It reuses js.strings' literal scan and then matches scheme://host URLs, so a
URL obfuscated with \\x / \\u escapes is caught once decoded, and URLs sitting
in comments are skipped. These tests pin the contract on hand-written JS:
scheme filtering, host parsing (userinfo/port/path), escape decoding, trailing
punctuation trimming, dedup/order, comment skipping, the caps and paging, and
the not_found guard, plus the tool docstring naming the returned fields.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, scan_js_endpoints
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(text, encoding="utf-8")
    return target


def _urls(payload: dict) -> list[str]:
    return [row["url"] for row in payload["endpoints"]]


def test_extracts_schemed_urls_with_host(tmp_path: Path) -> None:
    src = (
        "const a = 'https://api.example.com/v1/users';\n"
        'const b = "wss://socket.example.org:8443/live";\n'
    )
    payload = scan_js_endpoints(_write(tmp_path, src))
    rows = {row["url"]: row["host"] for row in payload["endpoints"]}
    assert rows == {
        "https://api.example.com/v1/users": "api.example.com",
        "wss://socket.example.org:8443/live": "socket.example.org:8443",
    }
    assert payload["truncated"] is False
    assert payload["scan_capped"] is False


def test_host_strips_userinfo(tmp_path: Path) -> None:
    src = "var u = 'https://user:pass@secret.example.net/path';"
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert payload["endpoints"] == [
        {"url": "https://user:pass@secret.example.net/path", "host": "secret.example.net"}
    ]


def test_schemeless_relative_paths_are_ignored(tmp_path: Path) -> None:
    src = "fetch('/api/v1/login'); fetch('./rel'); var s = 'plain string';"
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert payload["endpoints"] == []
    assert payload["total"] == 0


def test_obfuscated_url_is_decoded_then_matched(tmp_path: Path) -> None:
    # "https://evil.example.com/beacon" with the scheme hex-escaped.
    src = r"""var c2 = "\x68\x74\x74\x70\x73://evil.example.com/beacon";"""
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert _urls(payload) == ["https://evil.example.com/beacon"]
    assert payload["endpoints"][0]["host"] == "evil.example.com"


def test_urls_in_comments_are_skipped(tmp_path: Path) -> None:
    src = (
        "// see https://docs.example.com/ignored\n"
        "/* also http://blocked.example.com/x */\n"
        "var real = 'https://live.example.com/api';\n"
    )
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert _urls(payload) == ["https://live.example.com/api"]


def test_trailing_punctuation_is_trimmed(tmp_path: Path) -> None:
    src = "var m = 'go to https://example.com/page.';"
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert _urls(payload) == ["https://example.com/page"]


def test_dedup_first_seen_order(tmp_path: Path) -> None:
    src = (
        "a('https://one.example.com/'); b('https://two.example.com/');"
        "c('https://one.example.com/');"
    )
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert _urls(payload) == [
        "https://one.example.com/",
        "https://two.example.com/",
    ]


def test_collect_cap_sets_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_ENDPOINTS_COLLECT", 2)
    src = ";".join(f"f('https://h{i}.example.com/')" for i in range(6))
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


def test_literal_scan_cap_also_sets_scan_capped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If the underlying literal scan is capped, more URLs may exist beyond it.
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_STRINGS_COLLECT", 1)
    src = "a('nope'); b('https://reached.example.com/');"
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert payload["scan_capped"] is True


def test_page_window_and_has_more(tmp_path: Path) -> None:
    src = ";".join(f"f('https://h{i:02d}.example.com/')" for i in range(15))
    first = scan_js_endpoints(_write(tmp_path, src), offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 15
    assert first["has_more"] is True

    tail = scan_js_endpoints(_write(tmp_path, src), offset=10, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def test_unterminated_literal_sets_truncated(tmp_path: Path) -> None:
    src = "var ok = 'https://ok.example.com/'; var bad = 'https://cut.example.com"
    payload = scan_js_endpoints(_write(tmp_path, src))
    assert payload["truncated"] is True


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        scan_js_endpoints(tmp_path / "nope.js")
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
    doc = _tool_docstring("js.endpoints")
    assert "Answers with" in doc
    assert "endpoints" in doc
    assert "host" in doc
    assert "has_more" in doc
