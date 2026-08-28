"""js.comments: a node-free extractor of a JS file's // and /* */ comments.

It reuses the string-aware pass the other scanners use, this time collecting
comments rather than skipping them. These tests pin the contract on hand-written
JS: line and block comments, body stripping and clipping, 1-based start line,
that a // inside a string is not mistaken for a comment, min_length filtering,
dedup of repeated banners, truncation on an open block comment or string, the
caps and paging, and the not_found guard, plus the tool docstring naming the
returned fields.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from headless_re_mcp.backends.jsre.client import JsReError, scan_js_comments
from headless_re_mcp.tools.js_wasm import build_js_wasm_tools


def _write(tmp_path: Path, text: str) -> Path:
    target = tmp_path / "app.js"
    target.write_text(text, encoding="utf-8")
    return target


def _texts(payload: dict) -> list[str]:
    return [row["text"] for row in payload["comments"]]


def test_line_and_block_comments(tmp_path: Path) -> None:
    src = "var a = 1; // trailing note\n/* a block\n   comment */\nvar b = 2;\n"
    payload = scan_js_comments(_write(tmp_path, src))
    rows = {row["text"]: row for row in payload["comments"]}
    assert rows["trailing note"]["kind"] == "line"
    assert rows["trailing note"]["line"] == 1
    block = rows["a block\n   comment"]
    assert block["kind"] == "block"
    assert block["line"] == 2


def test_source_mapping_url_is_captured(tmp_path: Path) -> None:
    src = "console.log(1);\n//# sourceMappingURL=app.js.map\n"
    payload = scan_js_comments(_write(tmp_path, src))
    assert _texts(payload) == ["# sourceMappingURL=app.js.map"]


def test_comment_markers_inside_strings_are_not_comments(tmp_path: Path) -> None:
    src = "var a = 'not // a comment';\nvar b = \"nor /* this */ one\";\n// real one\n"
    payload = scan_js_comments(_write(tmp_path, src))
    assert _texts(payload) == ["real one"]


def test_start_line_is_one_based_after_multiline_block(tmp_path: Path) -> None:
    src = "/* header\nspanning\nthree */\nvar x = 1;\n// after\n"
    payload = scan_js_comments(_write(tmp_path, src))
    rows = {row["text"]: row["line"] for row in payload["comments"]}
    assert rows["header\nspanning\nthree"] == 1
    # The block spans lines 1-3, so the following // sits on line 5.
    assert rows["after"] == 5


def test_min_length_drops_empty_and_short(tmp_path: Path) -> None:
    src = "//\n/**/\n// hi\n// a longer note\n"
    payload = scan_js_comments(_write(tmp_path, src), min_length=5)
    assert _texts(payload) == ["a longer note"]


def test_dedup_repeated_banner(tmp_path: Path) -> None:
    banner = "/*! (c) ACME Corp - MIT licensed */"
    src = f"{banner}\nvar a=1;\n{banner}\nvar b=2;\n{banner}\n"
    payload = scan_js_comments(_write(tmp_path, src))
    assert _texts(payload) == ["! (c) ACME Corp - MIT licensed"]
    assert payload["total"] == 1


def test_unterminated_block_comment_sets_truncated(tmp_path: Path) -> None:
    src = "// ok\nvar a = 1; /* dangling block"
    payload = scan_js_comments(_write(tmp_path, src))
    assert "ok" in _texts(payload)
    assert payload["truncated"] is True


def test_unterminated_string_sets_truncated(tmp_path: Path) -> None:
    src = "// before\nvar s = 'never closed"
    payload = scan_js_comments(_write(tmp_path, src))
    assert "before" in _texts(payload)
    assert payload["truncated"] is True


def test_body_is_clipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_COMMENT_LEN", 8)
    src = "/* " + "x" * 100 + " */\n"
    payload = scan_js_comments(_write(tmp_path, src))
    assert payload["comments"][0]["text"] == "x" * 8


def test_collect_cap_sets_scan_capped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("headless_re_mcp.backends.jsre.client._MAX_JS_COMMENTS_COLLECT", 2)
    src = "\n".join(f"// note {i}" for i in range(6))
    payload = scan_js_comments(_write(tmp_path, src))
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


def test_page_window_and_has_more(tmp_path: Path) -> None:
    src = "\n".join(f"// note {i:02d}" for i in range(15))
    first = scan_js_comments(_write(tmp_path, src), offset=0, limit=10)
    assert first["count"] == 10
    assert first["total"] == 15
    assert first["has_more"] is True

    tail = scan_js_comments(_write(tmp_path, src), offset=10, limit=10)
    assert tail["count"] == 5
    assert tail["has_more"] is False


def test_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as info:
        scan_js_comments(tmp_path / "nope.js")
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
    doc = _tool_docstring("js.comments")
    assert "Answers with" in doc
    assert "comments" in doc
    assert "kind" in doc and "line" in doc
    assert "has_more" in doc
