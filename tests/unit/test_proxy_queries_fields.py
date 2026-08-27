"""proxy.queries must aggregate URL query parameters honestly and bounded.

The tool rolls the query string of every captured flow into a per-parameter
view (occurrence count, the hosts a name appears on, a few distinct sample
values). It has to count occurrences rather than distinct URLs, sort most-used
first, and disclose every bound it hits -- an over-cap parameter list, an
over-cap sample-value or host list, and a clipped oversized value -- so a
bounded view is never read as the whole capture.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy.client import ProxyBackend
from headless_re_mcp.tools.proxy import build_proxy_tools


class _FakeRecorder:
    def __init__(self, flows: list[dict[str, Any]]) -> None:
        self._flows = flows

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._flows)


class _FakeInstance:
    def __init__(self, flows: list[dict[str, Any]]) -> None:
        self.recorder = _FakeRecorder(flows)


def _backend_returning(flows: list[dict[str, Any]]) -> ProxyBackend:
    backend = ProxyBackend()
    backend._get = lambda _session_id: _FakeInstance(flows)  # type: ignore[method-assign]
    return backend


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


def test_queries_counts_occurrences_hosts_and_distinct_values() -> None:
    """count is occurrences across flows, hosts merge, values dedupe, sort by count.

    Measured intent: api_key reused across three requests (two hosts) counts 3
    with one sample value and both hosts; id appearing once then twice counts 3
    with three distinct values; a flow with no query and an empty URL are
    scanned but do not inflate flows_with_query; ties in count sort by name.
    """
    host = "api.example.com"
    flows = [
        {"url": "https://api.example.com/v1/user?api_key=SECRET&id=1", "host": host},
        {"url": "https://api.example.com/v1/list?api_key=SECRET&id=2&id=3", "host": host},
        {"url": "https://cdn.other.com/t?api_key=SECRET&utm=abc", "host": "cdn.other.com"},
        {"url": "https://api.example.com/v1/nofquery", "host": host},
        {"url": "", "host": ""},
    ]
    payload = _backend_returning(flows).queries("s")

    assert payload["flows_scanned"] == 5
    assert payload["flows_with_query"] == 3
    assert payload["param_count"] == 3
    assert payload["has_more"] is False
    assert [p["name"] for p in payload["params"]] == ["api_key", "id", "utm"]

    api_key = payload["params"][0]
    assert api_key["count"] == 3
    assert api_key["hosts"] == ["api.example.com", "cdn.other.com"]
    assert api_key["sample_values"] == ["SECRET"]
    assert api_key["truncated"] is False

    id_param = payload["params"][1]
    assert id_param["count"] == 3
    assert id_param["hosts"] == ["api.example.com"]
    assert id_param["sample_values"] == ["1", "2", "3"]

    doc = _tool_docstring("proxy.queries")
    assert "params" in doc
    assert "has_more" in doc
    assert "count" in doc


def test_queries_keeps_blank_values() -> None:
    """A bare flag (?debug) and an empty assignment (x=) are real parameters."""
    payload = _backend_returning(
        [{"url": "https://h/p?debug&x=", "host": "h"}]
    ).queries("s")
    by_name = {p["name"]: p for p in payload["params"]}
    assert set(by_name) == {"debug", "x"}
    assert by_name["debug"]["sample_values"] == [""]
    assert by_name["x"]["sample_values"] == [""]


def test_queries_caps_param_names_and_discloses_has_more() -> None:
    """More than 256 distinct names caps the list and sets has_more."""
    query = "&".join(f"p{index:04d}=v" for index in range(300))
    payload = _backend_returning(
        [{"url": f"https://h/x?{query}", "host": "h"}]
    ).queries("s")
    assert payload["param_count"] == 300
    assert len(payload["params"]) == 256
    assert payload["has_more"] is True


def test_queries_truncates_long_value_and_extra_samples() -> None:
    """A clipped oversized value and an over-cap sample list both set truncated."""
    long_value = "A" * 600
    flows = [
        {"url": f"https://h/a?big={long_value}", "host": "h"},
        {"url": "https://h/b?x=1&x=2&x=3&x=4&x=5&x=6", "host": "h"},
    ]
    payload = _backend_returning(flows).queries("s")
    by_name = {p["name"]: p for p in payload["params"]}

    assert by_name["big"]["truncated"] is True
    assert len(by_name["big"]["sample_values"][0]) == 512

    assert by_name["x"]["truncated"] is True
    assert by_name["x"]["sample_values"] == ["1", "2", "3", "4", "5"]
    assert by_name["x"]["count"] == 6
