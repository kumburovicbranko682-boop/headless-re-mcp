"""apk.endpoints extracts the network surface (URLs, hosts, paths) from the DEX pool.

The mobile analogue of js.endpoints, running the shared URL/path recogniser over
each DEX string constant. These cover URL and path extraction, the source pivot
field, dedup/aggregation, the host summary, the include_paths toggle, the filter,
trailing-punctuation trimming, the websocket scheme, sorting, value/source
clipping, the findings cap and the scan budget, paging, and the read-only
classification. The fake parsed object mirrors androguard's get_strings() surface.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient
from headless_re_mcp.tools.apk import build_apk_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_apk_tools.__code__.co_filename).read_text(encoding="utf-8")
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


class _FakeString:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeParsed:
    def __init__(self, values: list[str]) -> None:
        self.analysis = self
        self._values = values

    def get_strings(self) -> list[_FakeString]:
        return [_FakeString(v) for v in self._values]


def _client(values: list[str]) -> ApkClient:
    client = ApkClient()
    client._parsed = lambda _path: _FakeParsed(values)  # type: ignore[method-assign]
    return client


def _run(values: list[str], **kwargs: Any) -> dict[str, Any]:
    return _client(values).endpoints(Path("dummy.apk"), **kwargs)


def _by_value(values: list[str], **kwargs: Any) -> dict[str, dict[str, Any]]:
    return {e["value"]: e for e in _run(values, **kwargs)["endpoints"]}


def test_extracts_absolute_url_with_scheme_host_and_source() -> None:
    out = _run(["connecting to https://api.test/v1/users now", "noise"])
    assert out["total"] == 1
    row = out["endpoints"][0]
    assert row["value"] == "https://api.test/v1/users"
    assert row["kind"] == "url"
    assert row["scheme"] == "https"
    assert row["host"] == "api.test"
    assert row["source"] == "connecting to https://api.test/v1/users now"
    assert row["count"] == 1
    assert out["hosts"] == ["api.test"]
    assert out["scan_capped"] is False


def test_deduplicates_and_counts_across_constants() -> None:
    out = _run(["a https://d.test/x", "b https://d.test/x", "noise"])
    assert out["total"] == 1
    assert out["endpoints"][0]["count"] == 2


def test_extracts_request_paths() -> None:
    endpoints = _by_value(["/api/login", "/users/profile", "/x", "/"])
    assert "/api/login" in endpoints  # single api segment
    assert "/users/profile" in endpoints  # two segments
    assert endpoints["/api/login"]["kind"] == "path"
    assert endpoints["/api/login"]["host"] == ""
    assert endpoints["/api/login"]["source"] == "/api/login"
    assert "/x" not in endpoints
    assert "/" not in endpoints


def test_include_paths_false_drops_relative_paths() -> None:
    endpoints = _by_value(["/api/login", "https://api.test/x"], include_paths=False)
    assert "/api/login" not in endpoints
    assert "https://api.test/x" in endpoints


def test_host_summary_is_distinct_and_sorted() -> None:
    out = _run(["https://b.test/1", "https://a.test/2", "https://b.test/3"])
    assert out["hosts"] == ["a.test", "b.test"]


def test_trailing_punctuation_is_stripped() -> None:
    assert "https://a.test/x" in _by_value(["see https://a.test/x."])


def test_websocket_scheme_is_recognised() -> None:
    row = _by_value(["socket at wss://rt.test/socket"])["wss://rt.test/socket"]
    assert row["kind"] == "url"
    assert row["scheme"] == "wss"
    assert row["host"] == "rt.test"


def test_name_filter_matches_host_or_value_case_insensitively() -> None:
    out = _run(["https://api.test/x", "https://cdn.test/y", "/api/z"], name_filter="CDN")
    assert [e["value"] for e in out["endpoints"]] == ["https://cdn.test/y"]


def test_sorted_by_count_descending() -> None:
    out = _run(["https://a.test/1", "https://a.test/1", "https://b.test/2"])
    assert out["endpoints"][0]["value"] == "https://a.test/1"
    assert out["endpoints"][0]["count"] == 2


def test_no_endpoints_is_empty_not_an_error() -> None:
    out = _run(["hello", "Ljava/lang/Object;", "a", "b"])
    assert out["endpoints"] == []
    assert out["total"] == 0
    assert out["hosts"] == []


def test_value_and_source_truncation_flags() -> None:
    long_url = "https://h.test/" + "a" * 600
    padded = "n" * 300 + " https://short.test/a"
    rows = {r["host"]: r for r in _run([long_url, padded])["endpoints"]}
    assert rows["h.test"]["value_truncated"] is True
    assert len(rows["h.test"]["value"]) == 512
    assert rows["h.test"]["source_truncated"] is True
    assert "value_truncated" not in rows["short.test"]
    assert rows["short.test"]["source_truncated"] is True
    assert len(rows["short.test"]["source"]) == 256


def test_findings_cap_sets_scan_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_ENDPOINT_FINDINGS", 2)
    urls = [f"https://h{i:02d}.test/p" for i in range(5)]
    out = _run(urls, limit=2000)
    assert out["scan_capped"] is True
    assert out["total"] == 2


def test_scan_budget_sets_scan_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_ENDPOINT_SCAN_STRINGS", 2)
    out = _run(["noise0", "noise1", "https://late.test/x"], limit=2000)
    assert out["scan_capped"] is True
    assert out["total"] == 0


def test_pages_and_reports_has_more() -> None:
    urls = [f"https://h{i:02d}.test/p" for i in range(10)]
    out = _run(urls, limit=3)
    assert out["count"] == 3
    assert out["total"] == 10
    assert out["has_more"] is True
    assert len(out["hosts"]) == 10


def test_page_limit_is_capped(monkeypatch: Any) -> None:
    from headless_re_mcp.backends.apk import client as mod

    monkeypatch.setattr(mod, "_MAX_STRINGS_PAGE", 2)
    urls = [f"https://h{i:02d}.test/p" for i in range(6)]
    out = _run(urls, limit=1000)
    assert out["count"] == 2
    assert out["total"] == 6
    assert out["has_more"] is True


def test_apk_endpoints_tool_docstring_and_read_only() -> None:
    doc = " ".join(_tool_docstring("apk.endpoints").split())
    assert "endpoints" in doc
    assert "hosts" in doc
    assert "source" in doc
    assert "include_paths" in doc
    from headless_re_mcp.tools.catalog import _READ_ONLY_NAMES

    assert "apk.endpoints" in _READ_ONLY_NAMES
