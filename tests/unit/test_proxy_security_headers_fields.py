"""proxy.security_headers audits each served document's response headers.

The core is fold_security_headers, pure over the recorder's summary rows plus
a flow_id -> raw-flow lookup, so these drive it with fake rows and minimal
response stand-ins whose headers support items(multi=True).
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import _OMITTED_BODY, fold_security_headers
from headless_re_mcp.tools.proxy import build_proxy_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_proxy_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _Headers:
    def __init__(self, items: list[tuple[str, str]]) -> None:
        self._items = items

    def items(self, multi: bool = False) -> list[tuple[str, str]]:
        del multi
        return list(self._items)


def _flow(response_headers: list[tuple[str, str]] | None = None) -> Any:
    response = SimpleNamespace(headers=_Headers(response_headers or []))
    return SimpleNamespace(request=SimpleNamespace(headers=_Headers([])), response=response)


def _row(
    flow_id: str,
    *,
    host: str = "example.com",
    url: str = "https://example.com/",
    content_type: str = "text/html",
    status: int = 200,
) -> dict[str, Any]:
    return {
        "id": flow_id,
        "host": host,
        "url": url,
        "content_type": content_type,
        "status": status,
    }


def test_security_headers_report_present_and_missing() -> None:
    raw = {
        "1": _flow(
            response_headers=[
                ("Content-Security-Policy", "default-src 'self'"),
                ("X-Content-Type-Options", "nosniff"),
            ]
        )
    }
    result = fold_security_headers([_row("1")], lambda fid: raw.get(fid))
    assert result["total"] == 1
    doc = result["documents"][0]
    assert doc["host"] == "example.com"
    assert doc["path"] == "/"
    assert doc["present"] == ["csp", "x_content_type_options"]
    assert doc["headers"]["csp"] == "default-src 'self'"
    # HSTS, X-Frame-Options and the rest are all absent.
    assert "hsts" in doc["missing"]
    assert "x_frame_options" in doc["missing"]


def test_security_headers_flag_a_bare_document() -> None:
    raw = {"1": _flow(response_headers=[])}
    result = fold_security_headers([_row("1")], lambda fid: raw.get(fid))
    doc = result["documents"][0]
    assert doc["present"] == []
    assert set(doc["missing"]) == set(result["tracked_headers"])
    # A page with no protective headers pushes every missing_count to 1.
    assert result["missing_counts"]["csp"] == 1
    assert result["missing_counts"]["hsts"] == 1


def test_security_headers_include_non_html_carrying_a_header() -> None:
    raw = {
        "1": _flow(response_headers=[("Strict-Transport-Security", "max-age=31536000")]),
    }
    rows = [
        _row("1", url="https://api.example.com/v1", content_type="application/json"),
    ]
    result = fold_security_headers(rows, lambda fid: raw.get(fid))
    # Not html, but it carries HSTS, so it is audited.
    assert result["total"] == 1
    assert result["documents"][0]["headers"]["hsts"] == "max-age=31536000"


def test_security_headers_skip_plain_non_document_responses() -> None:
    raw = {"1": _flow(response_headers=[("Content-Type", "image/png")])}
    rows = [_row("1", url="https://example.com/logo.png", content_type="image/png")]
    result = fold_security_headers(rows, lambda fid: raw.get(fid))
    # No security header and not a document: nothing to audit.
    assert result["total"] == 0
    assert result["documents"] == []


def test_security_headers_fold_by_host_and_path() -> None:
    raw = {
        "1": _flow(response_headers=[("Content-Security-Policy", "a")]),
        "2": _flow(response_headers=[("X-Frame-Options", "DENY")]),
    }
    rows = [
        _row("1", url="https://example.com/app?x=1"),
        _row("2", url="https://example.com/app?x=2"),
    ]
    result = fold_security_headers(rows, lambda fid: raw.get(fid))
    # Same host+path (query stripped) collapses to one document that unions
    # the headers seen across both flows.
    assert result["total"] == 1
    doc = result["documents"][0]
    assert set(doc["present"]) == {"csp", "x_frame_options"}


def test_security_headers_count_evicted_documents() -> None:
    result = fold_security_headers([_row("1")], lambda fid: _OMITTED_BODY)
    assert result["total"] == 0
    assert result["body_unavailable"] == 1


def test_security_headers_on_an_empty_capture() -> None:
    result = fold_security_headers([], lambda fid: None)
    assert result["total"] == 0
    assert result["documents"] == []
    assert result["body_unavailable"] == 0
    assert result["missing_counts"]["csp"] == 0


def test_proxy_security_headers_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.security_headers")
    assert "missing_counts" in doc
    assert "tracked_headers" in doc
    assert "body_unavailable" in doc
    assert "csp" in doc
