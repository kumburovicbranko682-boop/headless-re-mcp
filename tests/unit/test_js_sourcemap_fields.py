"""js.sourcemap recovers original sources from a Source Map v3 document.

Dependency-free (no Node/webcrack), so these run the real backend end-to-end
over crafted files: flat maps, index maps (sections), sourceRoot, list vs
extract modes, inline data: URIs, adjacent-file references, the remote-URL
refusal, filtering/paging, content truncation, service routing, and the tool
docstring / read-only classification.
"""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.jsre.client as jsre_client
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
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


def _flat_map(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "version": 3,
        "file": "app.min.js",
        "sourceRoot": "",
        "sources": ["src/a.ts", "src/b.ts", "vendor/c.js"],
        "sourcesContent": ["export const a = 1;\n", "export const b = 2;\n", None],
        "names": [],
        "mappings": "AAAA",
    }
    data.update(overrides)
    return data


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_sourcemap_lists_sources_of_a_flat_map(tmp_path: Path) -> None:
    map_path = _write(tmp_path, "app.min.js.map", json.dumps(_flat_map()))
    payload = JsClient().sourcemap(map_path)
    assert payload["origin"] == "file"
    assert payload["sources_total"] == 3
    assert payload["with_content"] == 2
    assert payload["total"] == 3
    rows = {row["source"]: row for row in payload["sources"]}
    assert rows["src/a.ts"]["has_content"] is True
    assert rows["src/a.ts"]["length"] == len("export const a = 1;\n")
    # A source the map listed but did not embed reports has_content False.
    assert rows["vendor/c.js"]["has_content"] is False
    assert rows["vendor/c.js"]["length"] == 0
    assert payload["map"]["version"] == 3
    assert payload["map"]["file"] == "app.min.js"
    assert payload["map"]["index_map"] is False


def test_sourcemap_extract_returns_original_text(tmp_path: Path) -> None:
    map_path = _write(tmp_path, "app.min.js.map", json.dumps(_flat_map()))
    payload = JsClient().sourcemap(map_path, extract="src/b.ts")
    assert payload["matched"] is True
    assert payload["source"] == "src/b.ts"
    assert payload["content"] == "export const b = 2;\n"
    assert payload["has_content"] is True
    assert payload.get("content_truncated") is False


def test_sourcemap_extract_matches_by_substring_then_reports_miss(tmp_path: Path) -> None:
    map_path = _write(tmp_path, "app.min.js.map", json.dumps(_flat_map()))
    # Substring fallback finds src/a.ts from "a.ts".
    hit = JsClient().sourcemap(map_path, extract="a.ts")
    assert hit["matched"] is True
    assert hit["source"] == "src/a.ts"
    # A source that is listed but has no embedded text: matched, has_content False.
    empty = JsClient().sourcemap(map_path, extract="vendor/c.js")
    assert empty["matched"] is True
    assert empty["has_content"] is False
    assert empty["content"] == ""
    # No such source at all: a soft miss, not an error.
    miss = JsClient().sourcemap(map_path, extract="does/not/exist.ts")
    assert miss["matched"] is False
    assert miss["sources_total"] == 3


def test_sourcemap_applies_source_root(tmp_path: Path) -> None:
    data = _flat_map(sourceRoot="webpack://app/")
    map_path = _write(tmp_path, "b.js.map", json.dumps(data))
    payload = JsClient().sourcemap(map_path)
    names = {row["source"] for row in payload["sources"]}
    assert "webpack://app/src/a.ts" in names
    assert payload["map"]["source_root"] == "webpack://app/"


def test_sourcemap_flattens_index_map_sections(tmp_path: Path) -> None:
    index = {
        "version": 3,
        "file": "bundle.js",
        "sections": [
            {"offset": {"line": 0, "column": 0},
             "map": {"version": 3, "sources": ["a.ts"], "sourcesContent": ["A\n"]}},
            {"offset": {"line": 10, "column": 0},
             "map": {"version": 3, "sources": ["b.ts"], "sourcesContent": ["B\n"]}},
        ],
    }
    map_path = _write(tmp_path, "bundle.js.map", json.dumps(index))
    payload = JsClient().sourcemap(map_path)
    assert payload["map"]["index_map"] is True
    assert payload["sources_total"] == 2
    assert {row["source"] for row in payload["sources"]} == {"a.ts", "b.ts"}


def test_sourcemap_from_inline_data_uri(tmp_path: Path) -> None:
    encoded = base64.b64encode(json.dumps(_flat_map()).encode("utf-8")).decode("ascii")
    js = "console.log(1)\n//# sourceMappingURL=data:application/json;base64," + encoded + "\n"
    js_path = _write(tmp_path, "app.min.js", js)
    payload = JsClient().sourcemap(js_path)
    assert payload["origin"] == "inline"
    assert payload["sources_total"] == 3


def test_sourcemap_from_adjacent_file_reference(tmp_path: Path) -> None:
    _write(tmp_path, "app.min.js.map", json.dumps(_flat_map()))
    js_path = _write(
        tmp_path, "app.min.js", "console.log(1)\n//# sourceMappingURL=app.min.js.map\n"
    )
    payload = JsClient().sourcemap(js_path)
    assert payload["origin"] == "external:app.min.js.map"
    assert payload["sources_total"] == 3


def test_sourcemap_refuses_remote_reference(tmp_path: Path) -> None:
    js_path = _write(
        tmp_path,
        "app.min.js",
        "console.log(1)\n//# sourceMappingURL=https://cdn.example.com/app.js.map\n",
    )
    with pytest.raises(JsReError) as caught:
        JsClient().sourcemap(js_path)
    assert caught.value.code == "capability_unavailable"
    assert caught.value.details.get("url") == "https://cdn.example.com/app.js.map"


def test_sourcemap_js_without_pragma_is_not_found(tmp_path: Path) -> None:
    js_path = _write(tmp_path, "plain.js", "var x = 1;\nfunction f(){return x;}\n")
    with pytest.raises(JsReError) as caught:
        JsClient().sourcemap(js_path)
    assert caught.value.code == "not_found"


def test_sourcemap_name_filter_and_paging(tmp_path: Path) -> None:
    data = _flat_map(
        sources=["src/a.ts", "src/b.ts", "src/c.ts", "lib/d.js"],
        sourcesContent=["a", "b", "c", "d"],
    )
    map_path = _write(tmp_path, "m.js.map", json.dumps(data))
    filtered = JsClient().sourcemap(map_path, name_filter="src/")
    assert filtered["total"] == 3
    paged = JsClient().sourcemap(map_path, name_filter="src/", offset=0, limit=2)
    assert paged["count"] == 2
    assert paged["total"] == 3
    assert paged["has_more"] is True


def test_sourcemap_clips_extracted_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jsre_client, "_MAX_SOURCEMAP_CONTENT_BYTES", 8)
    data = _flat_map(sources=["big.ts"], sourcesContent=["0123456789ABCDEF"])
    map_path = _write(tmp_path, "big.js.map", json.dumps(data))
    payload = JsClient().sourcemap(map_path, extract="big.ts")
    assert payload["content"] == "01234567"
    assert payload["length"] == 16
    assert payload["content_truncated"] is True


def test_sourcemap_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        JsClient().sourcemap(tmp_path / "nope.map")
    assert caught.value.code == "not_found"


def test_service_js_sourcemap_routes_and_wraps(tmp_path: Path) -> None:
    from headless_re_mcp.core.service import AnalysisService

    map_path = _write(tmp_path, "app.min.js.map", json.dumps(_flat_map()))
    service = AnalysisService()
    try:
        result = service.js_sourcemap(str(map_path), extract="src/a.ts")
        assert result.ok and result.data is not None
        assert result.data["matched"] is True
        assert result.data["content"] == "export const a = 1;\n"
    finally:
        service.close_all()


def test_js_sourcemap_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("js.sourcemap").split())
    assert "sourcesContent" in doc
    assert "extract" in doc
    assert "origin" in doc
    assert "index map" in doc.lower()
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "js.sourcemap" in _READ_ONLY_NAMES
