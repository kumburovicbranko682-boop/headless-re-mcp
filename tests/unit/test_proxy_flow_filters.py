"""proxy.flows must narrow a busy capture by method, host, url and status range.

The filters exist so an agent can triage a large capture without paging the
whole ring. Each test measures a concrete capture and asserts what the filter
keeps, that total counts only matches, and that the reply flags the narrowing
(filtered/captured) so a filtered page is never mistaken for the whole log.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend, _FlowRecorder
from headless_re_mcp.tools.proxy import build_proxy_tools

_ROWS = [
    ("GET", "http://api.example.com/users", "api.example.com", 200, "application/json"),
    ("POST", "http://api.example.com/login", "api.example.com", 401, "application/json"),
    ("GET", "http://cdn.other.com/logo.png", "cdn.other.com", 200, "image/png"),
    ("POST", "http://api.example.com/pay", "api.example.com", 500, "text/html"),
    ("GET", "http://api.example.com/health", "api.example.com", None, ""),
]


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


def _backend(rows: list[tuple[str, str, str, int | None, str]]) -> ProxyBackend:
    recorder = _FlowRecorder(capacity=50)
    for index, (method, url, host, status, content_type) in enumerate(rows):
        request = SimpleNamespace(method=method, pretty_url=url, host=host)
        response = (
            SimpleNamespace(status_code=status, headers={"content-type": content_type})
            if status is not None
            else None
        )
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._get = lambda session_id: SimpleNamespace(recorder=recorder)  # type: ignore[method-assign]
    return backend


def _urls(payload: dict[str, Any]) -> list[str]:
    return [row["url"] for row in payload["flows"]]


def test_no_filter_leaves_total_at_the_ring_and_omits_the_flags() -> None:
    """Without a filter, total is the whole ring and no filtered/captured appears.

    Measured: 5 captured -> total 5, and neither filtered nor captured is set, so
    an unfiltered reply is byte-for-byte what it always was.
    """
    payload = _backend(_ROWS).flows("s")
    assert payload["total"] == 5
    assert payload["count"] == 5
    assert "filtered" not in payload
    assert "captured" not in payload


def test_method_filter_is_exact_and_case_insensitive() -> None:
    """method matches the verb exactly, ignoring case, not as a substring.

    Measured: method 'post' (lowercase) -> the two POSTs, total 2, captured 5,
    filtered True. 'GE' matches nothing because the match is exact, not prefix.
    """
    backend = _backend(_ROWS)
    payload = backend.flows("s", method="post")
    assert _urls(payload) == [
        "http://api.example.com/login",
        "http://api.example.com/pay",
    ]
    assert payload["total"] == 2
    assert payload["captured"] == 5
    assert payload["filtered"] is True
    assert backend.flows("s", method="GE")["total"] == 0


def test_host_and_url_filters_are_case_insensitive_substrings() -> None:
    """host_contains and url_contains match anywhere in the field, any case.

    Measured: host_contains 'API' -> the four api.example.com rows (not the cdn
    row), total 4; url_contains 'LOGIN' -> the single login row.
    """
    backend = _backend(_ROWS)
    by_host = backend.flows("s", host_contains="API")
    assert _urls(by_host) == [
        "http://api.example.com/users",
        "http://api.example.com/login",
        "http://api.example.com/pay",
        "http://api.example.com/health",
    ]
    assert by_host["total"] == 4
    by_url = backend.flows("s", url_contains="LOGIN")
    assert _urls(by_url) == ["http://api.example.com/login"]
    assert by_url["total"] == 1


def test_status_range_selects_errors_and_exact_codes() -> None:
    """status_min/status_max bound the code inclusively for error triage.

    Measured: status_min 400 -> the 401 and 500 (every error), total 2;
    status_min 400 status_max 499 -> only the 401; status_min 404 status_max 404
    -> nothing, since no row is exactly 404.
    """
    backend = _backend(_ROWS)
    errors = backend.flows("s", status_min=400)
    assert _urls(errors) == [
        "http://api.example.com/login",
        "http://api.example.com/pay",
    ]
    assert errors["total"] == 2
    assert backend.flows("s", status_min=400, status_max=499)["total"] == 1
    assert backend.flows("s", status_min=404, status_max=404)["total"] == 0


def test_status_bound_excludes_a_flow_with_no_response() -> None:
    """A status range drops rows that never got a response (status None).

    Measured: the health row has status None; a 100..599 range keeps the other
    four and excludes it, because you asked for a status and it has none.
    """
    backend = _backend(_ROWS)
    payload = backend.flows("s", status_min=100, status_max=599)
    assert "http://api.example.com/health" not in _urls(payload)
    assert payload["total"] == 4


def test_filters_are_anded_together() -> None:
    """Combining filters keeps only rows that satisfy all of them.

    Measured: method POST and host_contains api and status_min 500 -> only the
    pay row (login is a POST to api but 401), total 1.
    """
    backend = _backend(_ROWS)
    payload = backend.flows("s", method="POST", host_contains="api", status_min=500)
    assert _urls(payload) == ["http://api.example.com/pay"]
    assert payload["total"] == 1


def test_empty_filter_string_is_ignored_not_matched() -> None:
    """A whitespace-only filter behaves as no filter, not match-all/none.

    Measured: method '   ' and url_contains '' -> total 5 and no filtered flag,
    so an accidentally-blank argument does not silently drop or keep everything.
    """
    backend = _backend(_ROWS)
    payload = backend.flows("s", method="   ", url_contains="")
    assert payload["total"] == 5
    assert "filtered" not in payload


def test_filtered_total_and_has_more_page_the_matches_not_the_ring() -> None:
    """Pagination runs over the filtered set: has_more and total follow matches.

    Measured: 6 GETs to /keep plus 4 POSTs mixed in; method GET, limit 4 ->
    count 4, total 6, has_more True, captured 10; offset 4 -> the last 2 GETs,
    has_more False.
    """
    rows: list[tuple[str, str, str, int | None, str]] = []
    for index in range(6):
        rows.append(("GET", f"http://h/keep/{index}", "h", 200, "text/plain"))
    for index in range(4):
        rows.append(("POST", f"http://h/skip/{index}", "h", 200, "text/plain"))
    backend = _backend(rows)
    first = backend.flows("s", method="GET", offset=0, limit=4)
    assert first["count"] == 4
    assert first["total"] == 6
    assert first["captured"] == 10
    assert first["has_more"] is True
    second = backend.flows("s", method="GET", offset=4, limit=4)
    assert second["count"] == 2
    assert second["has_more"] is False


def test_dropped_reflects_the_ring_not_the_filter() -> None:
    """dropped stays the count the capture ring evicted, independent of filters.

    Measured: capacity 5 with 12 responses -> dropped 7 whether or not a filter
    is applied; a filter narrows total, it does not change what was evicted.
    """
    recorder = _FlowRecorder(capacity=5)
    for index in range(12):
        request = SimpleNamespace(method="GET", pretty_url=f"http://x/{index}", host="x")
        response = SimpleNamespace(status_code=200, headers={"content-type": "text/plain"})
        recorder.response(
            SimpleNamespace(id=str(index), request=request, response=response)
        )
    backend = ProxyBackend()
    backend._get = lambda session_id: SimpleNamespace(recorder=recorder)  # type: ignore[method-assign]
    unfiltered = backend.flows("s")
    filtered = backend.flows("s", method="GET")
    assert unfiltered["dropped"] == 7
    assert filtered["dropped"] == 7


def test_proxy_flows_docstring_names_the_filters() -> None:
    """The catalog must describe the filters and the filtered/captured contract."""
    doc = _tool_docstring("proxy.flows")
    for token in (
        "method",
        "host_contains",
        "url_contains",
        "status_min",
        "status_max",
        "filtered",
        "captured",
    ):
        assert token in doc
