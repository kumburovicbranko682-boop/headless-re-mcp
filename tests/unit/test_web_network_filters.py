"""web.network.list must narrow a busy capture by method, url, type and status.

These mirror the proxy.flows filter tests, adapted to the CDP request shape
(url/method/resourceType/status): an agent triaging a page that fired dozens of
requests should not have to page the whole ring. Each test measures a concrete
capture and asserts what the filter keeps, that total counts only matches, and
that the reply flags the narrowing (filtered/captured) so a filtered page is
never mistaken for the whole capture.
"""

from __future__ import annotations

import ast
from collections import OrderedDict
from pathlib import Path
from threading import Lock
from typing import Any

from headless_re_mcp.backends.web.client import WebBackend
from headless_re_mcp.tools.web import build_web_tools

# (method, url, resourceType, status)
_ROWS = [
    ("GET", "https://api.example.com/users", "XHR", 200),
    ("POST", "https://api.example.com/login", "Fetch", 401),
    ("GET", "https://cdn.other.com/logo.png", "Image", 200),
    ("POST", "https://api.example.com/pay", "Fetch", 500),
    ("GET", "https://api.example.com/health", "XHR", None),
]


def _tool_docstring(name: str) -> str:
    source = Path(build_web_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _FakeHandle:
    def __init__(
        self,
        rows: list[tuple[str, str, str, int | None]],
        *,
        dropped: int = 0,
    ) -> None:
        self.lock = Lock()
        self.requests: OrderedDict[str, dict[str, Any]] = OrderedDict()
        for index, (method, url, resource_type, status) in enumerate(rows):
            self.requests[str(index)] = {
                "requestId": str(index),
                "url": url,
                "method": method,
                "resourceType": resource_type,
                "status": status,
                "mimeType": "application/json",
            }
        self.requests_dropped = dropped


def _backend(rows: list[tuple[str, str, str, int | None]], **kwargs: Any) -> WebBackend:
    handle = _FakeHandle(rows, **kwargs)
    backend = WebBackend()
    backend._get = lambda session_id: handle  # type: ignore[method-assign]
    return backend


def _urls(payload: dict[str, Any]) -> list[str]:
    return [row["url"] for row in payload["requests"]]


def test_no_filter_leaves_total_at_the_ring_and_omits_the_flags() -> None:
    """Without a filter, total is the whole ring and no filtered/captured appears.

    Measured: 5 captured -> total 5, and neither filtered nor captured is set, so
    an unfiltered reply is byte-for-byte what it always was.
    """
    payload = _backend(_ROWS).network_list("s")
    assert payload["total"] == 5
    assert payload["count"] == 5
    assert "filtered" not in payload
    assert "captured" not in payload


def test_method_filter_is_exact_and_case_insensitive() -> None:
    """method matches the verb exactly, ignoring case, not as a substring.

    Measured: method 'get' (lowercase) -> the three GETs, total 3, captured 5,
    filtered True. 'GE' matches nothing because the match is exact, not prefix.
    """
    backend = _backend(_ROWS)
    payload = backend.network_list("s", method="get")
    assert _urls(payload) == [
        "https://api.example.com/users",
        "https://cdn.other.com/logo.png",
        "https://api.example.com/health",
    ]
    assert payload["total"] == 3
    assert payload["captured"] == 5
    assert payload["filtered"] is True
    assert backend.network_list("s", method="GE")["total"] == 0


def test_url_contains_is_a_case_insensitive_substring() -> None:
    """url_contains matches anywhere in the url, any case.

    Measured: url_contains 'API' -> the four api.example.com rows (not the cdn
    row), total 4; url_contains 'LOGIN' -> the single login row.
    """
    backend = _backend(_ROWS)
    by_host = backend.network_list("s", url_contains="API.EXAMPLE")
    assert _urls(by_host) == [
        "https://api.example.com/users",
        "https://api.example.com/login",
        "https://api.example.com/pay",
        "https://api.example.com/health",
    ]
    assert by_host["total"] == 4
    by_url = backend.network_list("s", url_contains="LOGIN")
    assert _urls(by_url) == ["https://api.example.com/login"]
    assert by_url["total"] == 1


def test_resource_type_filter_is_exact_and_case_insensitive() -> None:
    """resource_type matches the CDP resourceType exactly, ignoring case.

    Measured: resource_type 'fetch' -> the two Fetch rows (login, pay), total 2;
    'XH' matches nothing because the match is exact, not a prefix.
    """
    backend = _backend(_ROWS)
    payload = backend.network_list("s", resource_type="fetch")
    assert _urls(payload) == [
        "https://api.example.com/login",
        "https://api.example.com/pay",
    ]
    assert payload["total"] == 2
    assert backend.network_list("s", resource_type="XH")["total"] == 0


def test_status_range_selects_errors_and_exact_codes() -> None:
    """status_min/status_max bound the code inclusively for error triage.

    Measured: status_min 400 -> the 401 and 500 (every error), total 2;
    status_min 400 status_max 499 -> only the 401; status_min 404 status_max 404
    -> nothing, since no row is exactly 404.
    """
    backend = _backend(_ROWS)
    errors = backend.network_list("s", status_min=400)
    assert _urls(errors) == [
        "https://api.example.com/login",
        "https://api.example.com/pay",
    ]
    assert errors["total"] == 2
    assert backend.network_list("s", status_min=400, status_max=499)["total"] == 1
    assert backend.network_list("s", status_min=404, status_max=404)["total"] == 0


def test_status_bound_excludes_a_request_with_no_response() -> None:
    """A status range drops rows that never got a response (status None).

    Measured: the health row has status None; a 100..599 range keeps the other
    four and excludes it, because you asked for a status and it has none.
    """
    backend = _backend(_ROWS)
    payload = backend.network_list("s", status_min=100, status_max=599)
    assert "https://api.example.com/health" not in _urls(payload)
    assert payload["total"] == 4


def test_filters_are_anded_together() -> None:
    """Combining filters keeps only rows that satisfy all of them.

    Measured: method POST and resource_type Fetch and status_min 500 -> only the
    pay row (login is a POST Fetch but 401), total 1.
    """
    backend = _backend(_ROWS)
    payload = backend.network_list(
        "s", method="POST", resource_type="Fetch", status_min=500
    )
    assert _urls(payload) == ["https://api.example.com/pay"]
    assert payload["total"] == 1


def test_empty_filter_string_is_ignored_not_matched() -> None:
    """A whitespace-only filter behaves as no filter, not match-all/none.

    Measured: method '   ' and url_contains '' -> total 5 and no filtered flag,
    so an accidentally-blank argument does not silently drop or keep everything.
    """
    backend = _backend(_ROWS)
    payload = backend.network_list("s", method="   ", url_contains="")
    assert payload["total"] == 5
    assert "filtered" not in payload


def test_filtered_total_and_has_more_page_the_matches_not_the_ring() -> None:
    """Pagination runs over the filtered set: has_more and total follow matches.

    Measured: 6 GETs to /keep plus 4 POSTs mixed in; method GET, limit 4 ->
    count 4, total 6, has_more True, captured 10; offset 4 -> the last 2 GETs,
    has_more False.
    """
    rows: list[tuple[str, str, str, int | None]] = []
    for index in range(6):
        rows.append(("GET", f"https://h/keep/{index}", "Document", 200))
    for index in range(4):
        rows.append(("POST", f"https://h/skip/{index}", "Fetch", 200))
    backend = _backend(rows)
    first = backend.network_list("s", method="GET", offset=0, limit=4)
    assert first["count"] == 4
    assert first["total"] == 6
    assert first["captured"] == 10
    assert first["has_more"] is True
    second = backend.network_list("s", method="GET", offset=4, limit=4)
    assert second["count"] == 2
    assert second["has_more"] is False


def test_dropped_reflects_the_ring_not_the_filter() -> None:
    """dropped stays the count the capture ring evicted, independent of filters.

    Measured: a ring that already evicted 7 -> dropped 7 whether or not a filter
    is applied; a filter narrows total, it does not change what was evicted.
    """
    backend = _backend(_ROWS, dropped=7)
    unfiltered = backend.network_list("s")
    filtered = backend.network_list("s", method="GET")
    assert unfiltered["dropped"] == 7
    assert filtered["dropped"] == 7


def test_web_network_list_docstring_names_the_filters() -> None:
    """The catalog must describe the filters and the filtered/captured contract."""
    doc = _tool_docstring("web.network.list")
    for token in (
        "method",
        "url_contains",
        "resource_type",
        "status_min",
        "status_max",
        "filtered",
        "captured",
    ):
        assert token in doc
