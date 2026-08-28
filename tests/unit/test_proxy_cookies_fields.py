"""proxy.cookies folds Set-Cookie/Cookie headers into a distinct inventory.

The core is fold_cookies, pure over the recorder's summary rows plus a
flow_id -> raw-flow lookup, so these drive it with fake rows and minimal
request/response stand-ins whose headers support items(multi=True).
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import _OMITTED_BODY, fold_cookies
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


def _flow(
    *,
    request_headers: list[tuple[str, str]] | None = None,
    response_headers: list[tuple[str, str]] | None = None,
) -> Any:
    request = SimpleNamespace(headers=_Headers(request_headers or []))
    response = SimpleNamespace(headers=_Headers(response_headers or []))
    return SimpleNamespace(request=request, response=response)


def _row(flow_id: str, host: str) -> dict[str, Any]:
    return {"id": flow_id, "host": host}


def test_cookies_fold_set_cookie_attributes() -> None:
    raw = {
        "1": _flow(
            response_headers=[
                (
                    "Set-Cookie",
                    "sid=abc; Domain=example.com; Path=/; HttpOnly; Secure; SameSite=Lax",
                ),
                ("Set-Cookie", "theme=dark; Path=/"),
            ]
        )
    }
    result = fold_cookies([_row("1", "example.com")], lambda fid: raw.get(fid))
    assert result["total"] == 2
    by_name = {c["name"]: c for c in result["cookies"]}

    sid = by_name["sid"]
    assert sid["domain"] == "example.com"
    assert sid["value"] == "abc"
    assert sid["http_only"] is True
    assert sid["secure"] is True
    assert sid["same_site"] == "Lax"
    assert sid["path"] == "/"
    assert sid["set_count"] == 1
    assert sid["sources"] == ["set-cookie"]

    theme = by_name["theme"]
    assert theme["http_only"] is False
    assert theme["secure"] is False


def test_cookies_capture_multiple_set_cookie_headers() -> None:
    """A dict-collapsing header read would lose all but the last Set-Cookie."""
    raw = {
        "1": _flow(
            response_headers=[
                ("set-cookie", "a=1"),
                ("set-cookie", "b=2"),
                ("set-cookie", "c=3"),
            ]
        )
    }
    result = fold_cookies([_row("1", "h")], lambda fid: raw.get(fid))
    assert result["total"] == 3


def test_cookies_fold_request_cookie_header() -> None:
    raw = {"1": _flow(request_headers=[("Cookie", "sid=abc; csrf=xyz")])}
    result = fold_cookies([_row("1", "example.com")], lambda fid: raw.get(fid))
    by_name = {c["name"]: c for c in result["cookies"]}
    assert by_name["sid"]["sent_count"] == 1
    assert by_name["sid"]["sources"] == ["cookie"]
    assert by_name["csrf"]["value"] == "xyz"


def test_cookies_merge_set_and_sent_sources() -> None:
    raw = {
        "1": _flow(response_headers=[("Set-Cookie", "sid=abc; Domain=h")]),
        "2": _flow(request_headers=[("Cookie", "sid=abc")]),
    }
    rows = [_row("1", "h"), _row("2", "h")]
    result = fold_cookies(rows, lambda fid: raw.get(fid))
    assert result["total"] == 1
    cookie = result["cookies"][0]
    assert cookie["set_count"] == 1
    assert cookie["sent_count"] == 1
    assert cookie["sources"] == ["set-cookie", "cookie"]


def test_cookies_key_by_name_and_domain() -> None:
    raw = {
        "1": _flow(response_headers=[("Set-Cookie", "id=1; Domain=a.com")]),
        "2": _flow(response_headers=[("Set-Cookie", "id=2; Domain=b.com")]),
    }
    rows = [_row("1", "a.com"), _row("2", "b.com")]
    result = fold_cookies(rows, lambda fid: raw.get(fid))
    # Same name on two domains stays distinct.
    assert result["total"] == 2


def test_cookies_count_evicted_flows() -> None:
    result = fold_cookies(
        [_row("1", "h")], lambda fid: _OMITTED_BODY
    )
    assert result["total"] == 0
    assert result["body_unavailable"] == 1


def test_cookies_on_an_empty_capture() -> None:
    result = fold_cookies([], lambda fid: None)
    assert result["total"] == 0
    assert result["cookies"] == []
    assert result["body_unavailable"] == 0


def test_proxy_cookies_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.cookies")
    assert "set_count" in doc
    assert "sent_count" in doc
    assert "sources" in doc
    assert "body_unavailable" in doc
