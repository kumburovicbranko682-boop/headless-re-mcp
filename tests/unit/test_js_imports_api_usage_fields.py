"""js.imports / js.api_usage: module graph and sensitive-API sink scan.

Both parallel the mature APK line (apk.urls + apk.api_usage) for JavaScript,
pure Python. The load-bearing property is precision: a require() or eval(
sitting inside a string, a comment or a regex literal must not be counted, and
the tests pin that on every axis.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import headless_re_mcp.backends.jsre.client as client_mod
from headless_re_mcp.backends.jsre.client import JsClient, JsReError
from headless_re_mcp.backends.jsre.js_static import (
    extract_js_api_usage,
    extract_js_imports,
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


def _by_spec(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(row["specifier"]): row for row in payload["imports"]}  # type: ignore[index,union-attr]


def _cats(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(c["category"]): c for c in payload["categories"]}  # type: ignore[index,union-attr]


# --- extract_js_imports -----------------------------------------------------


def test_imports_cover_every_kind() -> None:
    src = (
        "import a from 'react';\n"
        "export { z } from '@scope/pkg/sub';\n"
        "const l = require('lodash');\n"
        "const m = import('https://cdn.test/x.js');\n"
        "importScripts('worker.js');\n"
        "import './side-effect.css';\n"
    )
    rows = _by_spec(extract_js_imports(src))
    assert rows["react"]["kind"] == "esm_import"
    assert rows["@scope/pkg/sub"]["kind"] == "esm_export"
    assert rows["lodash"]["kind"] == "require"
    assert rows["https://cdn.test/x.js"]["kind"] == "dynamic_import"
    assert rows["worker.js"]["kind"] == "import_scripts"
    assert rows["./side-effect.css"]["kind"] == "esm_import"


def test_imports_classify_specifier_and_package() -> None:
    src = (
        "require('./local');"
        "require('https://cdn.test/a.js');"
        "require('@org/tool/deep');"
        "require('express');"
    )
    rows = _by_spec(extract_js_imports(src))
    assert rows["./local"]["category"] == "relative"
    assert rows["./local"]["package"] is None
    assert rows["https://cdn.test/a.js"]["category"] == "url"
    assert rows["@org/tool/deep"]["category"] == "bare"
    assert rows["@org/tool/deep"]["package"] == "@org/tool"
    assert rows["express"]["package"] == "express"


def test_imports_ignore_string_comment_and_regex_occurrences() -> None:
    src = (
        "// require('in-comment')\n"
        "const s = \"require('in-string')\";\n"
        "const re = /require\\('in-regex'\\)/;\n"
        "const real = require('actually-used');\n"
    )
    rows = _by_spec(extract_js_imports(src))
    assert set(rows) == {"actually-used"}


def test_imports_count_occurrences_and_sample_lines() -> None:
    src = "require('x');\nrequire('x');\nrequire('x');\n"
    row = _by_spec(extract_js_imports(src))["x"]
    assert row["count"] == 3
    assert row["lines"] == [1, 2, 3]


def test_imports_roll_up_packages_and_tally_kinds() -> None:
    src = "require('a');require('a');import b from 'b';"
    payload = extract_js_imports(src)
    assert payload["kinds"] == {"require": 2, "esm_import": 1}
    packages = {row["package"]: row["count"] for row in payload["packages"]}
    assert packages == {"a": 1, "b": 1}


def test_imports_page_the_listing() -> None:
    src = "".join(f"import x from 'm{i}';" for i in range(5))
    payload = extract_js_imports(src, offset=0, limit=2)
    assert payload["count"] == 2
    assert payload["total"] == 5
    assert payload["has_more"] is True


def test_imports_scan_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.js_static as js_static

    monkeypatch.setattr(js_static, "_MAX_IMPORTS_COLLECT", 2)
    src = "require('a');require('b');require('c');require('d');"
    payload = extract_js_imports(src)
    assert payload["total"] == 2
    assert payload["scan_capped"] is True


# --- extract_js_api_usage ---------------------------------------------------


def test_api_usage_groups_sinks_by_category() -> None:
    src = (
        "eval(x);\n"
        "el.innerHTML = y;\n"
        "document.write(z);\n"
        "fetch('/a');\n"
        "localStorage.getItem('k');\n"
        "atob(s);\n"
    )
    cats = _cats(extract_js_api_usage(src))
    assert "eval" in {a["api"] for a in cats["code_execution"]["apis"]}
    assert {a["api"] for a in cats["dom_injection"]["apis"]} == {"innerHTML", "document.write"}
    assert "fetch" in {a["api"] for a in cats["network"]["apis"]}
    assert "localStorage" in {a["api"] for a in cats["storage"]["apis"]}
    assert "atob" in {a["api"] for a in cats["encoding"]["apis"]}


def test_api_usage_ignores_strings_comments_and_regex() -> None:
    src = (
        "// eval(evil)\n"
        "const s = 'eval(also-evil)';\n"
        "const re = /eval\\(/;\n"
        "const real = eval(payload);\n"
    )
    payload = extract_js_api_usage(src)
    assert payload["total_hits"] == 1
    cats = _cats(payload)
    row = next(a for a in cats["code_execution"]["apis"] if a["api"] == "eval")
    assert row["count"] == 1
    assert row["lines"] == [4]


def test_api_usage_counts_and_ranks_within_a_category() -> None:
    src = "fetch(1);fetch(2);fetch(3);new WebSocket('x');"
    cats = _cats(extract_js_api_usage(src))
    apis = cats["network"]["apis"]
    assert apis[0] == {"api": "fetch", "count": 3, "lines": [1, 1, 1]}
    assert cats["network"]["hits"] == 4


def test_api_usage_empty_when_no_sinks() -> None:
    payload = extract_js_api_usage("const a = 1 + 2; let b = a / 2;")
    assert payload["categories"] == []
    assert payload["total_hits"] == 0


def test_api_usage_scan_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    import headless_re_mcp.backends.jsre.js_static as js_static

    monkeypatch.setattr(js_static, "_MAX_API_MATCHES", 2)
    src = "eval(1);eval(2);eval(3);eval(4);"
    payload = extract_js_api_usage(src)
    assert payload["scan_capped"] is True
    assert payload["total_hits"] == 2


# --- client + service integration -------------------------------------------


def test_client_imports_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text("import x from 'left-pad';", encoding="utf-8")
    payload = JsClient(None).imports(js)
    assert _by_spec(payload)["left-pad"]["package"] == "left-pad"


def test_client_api_usage_needs_no_webcrack(tmp_path: Path) -> None:
    js = tmp_path / "a.js"
    js.write_text("eval(atob('x'));", encoding="utf-8")
    cats = _cats(JsClient(None).api_usage(js))
    assert "code_execution" in cats
    assert "encoding" in cats


def test_client_imports_missing_file_is_not_found(tmp_path: Path) -> None:
    with pytest.raises(JsReError) as caught:
        JsClient(None).imports(tmp_path / "nope.js")
    assert caught.value.code == "not_found"


def test_client_api_usage_oversized_is_too_large(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_mod, "_MAX_INPUT_BYTES", 16)
    js = tmp_path / "big.js"
    js.write_text("eval(x);" * 10, encoding="utf-8")
    with pytest.raises(JsReError) as caught:
        JsClient(None).api_usage(js)
    assert caught.value.code == "too_large"


def test_service_js_imports_and_api_usage_dispatch(tmp_path: Path) -> None:
    from dataclasses import replace

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    settings = replace(Settings.load(), artifact_root=tmp_path / "artifacts")
    service = AnalysisService(settings)
    js = tmp_path / "s.js"
    js.write_text("const l = require('lodash'); eval(x);", encoding="utf-8")

    imports = service.js_imports(str(js))
    assert imports.ok, imports.error
    assert imports.data is not None
    assert _by_spec(imports.data)["lodash"]["kind"] == "require"

    api = service.js_api_usage(str(js))
    assert api.ok, api.error
    assert api.data is not None
    assert api.data["total_hits"] >= 1


def test_new_js_tools_are_registered() -> None:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import AnalysisService

    service = AnalysisService(Settings.load())
    names = {tool.name for tool in build_js_wasm_tools(service)}
    assert {"js.imports", "js.api_usage"}.issubset(names)


def test_js_imports_docstring_names_its_shape() -> None:
    doc = _tool_docstring("js.imports")
    assert "specifier" in doc
    assert "kind" in doc
    assert "packages" in doc
    assert "has_more" in doc
    assert "too_large" in doc


def test_js_api_usage_docstring_names_its_shape() -> None:
    doc = _tool_docstring("js.api_usage")
    assert "categories" in doc
    assert "code_execution" in doc
    assert "total_hits" in doc
    assert "too_large" in doc
