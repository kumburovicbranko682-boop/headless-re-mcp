"""apk.urls distils network indicators out of DEX string constants.

The core is _extract_url_indicators, pure over raw string values, so most of
this drives it directly. One test wires it through the ApkClient._parsed seam.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from headless_re_mcp.backends.apk.client import ApkClient, _extract_url_indicators
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


def test_extract_collects_urls_with_scheme_and_host() -> None:
    urls, hosts, ips, capped = _extract_url_indicators(
        [
            "base https://api.example.com/v1/login here",
            "ws://socket.example.com/live",
            "no url in this one",
        ]
    )
    by_url = {row["url"]: row for row in urls.values()}
    assert by_url["https://api.example.com/v1/login"]["scheme"] == "https"
    assert by_url["https://api.example.com/v1/login"]["host"] == "api.example.com"
    assert by_url["ws://socket.example.com/live"]["scheme"] == "ws"
    assert hosts["api.example.com"] == 1
    assert capped is False


def test_extract_trims_trailing_punctuation() -> None:
    urls, _hosts, _ips, _capped = _extract_url_indicators(
        ['visit "https://c2.evil.test/gate.php".']
    )
    assert "https://c2.evil.test/gate.php" in urls


def test_extract_tallies_hosts_across_distinct_urls() -> None:
    _urls, hosts, _ips, _capped = _extract_url_indicators(
        [
            "https://cdn.tracker.io/a.js",
            "https://cdn.tracker.io/b.js",
            "https://cdn.tracker.io/a.js",  # duplicate, counted once
        ]
    )
    # Two distinct URLs on the one host.
    assert hosts["cdn.tracker.io"] == 2


def test_extract_finds_bare_ipv4_and_ignores_bad_octets() -> None:
    _urls, _hosts, ips, _capped = _extract_url_indicators(
        [
            "callback 203.0.113.9 then 999.1.1.1 (not an ip)",
            "gateway 10.0.0.1",
        ]
    )
    assert "203.0.113.9" in ips
    assert "10.0.0.1" in ips
    assert "999.1.1.1" not in ips


def test_urls_method_pages_and_rolls_up(monkeypatch: Any) -> None:
    strings = [
        "https://api.example.com/a",
        "https://api.example.com/b",
        "http://8.8.8.8/health",
        "boring constant",
    ]
    fake_items = [SimpleNamespace(get_value=lambda v=s: v) for s in strings]
    fake_parsed = SimpleNamespace(
        analysis=SimpleNamespace(get_strings=lambda: fake_items)
    )
    client = ApkClient()
    client._parsed = lambda _path: fake_parsed  # type: ignore[method-assign]

    payload = client.urls(Path("d.apk"), offset=0, limit=2)

    assert payload["total"] == 3
    assert payload["count"] == 2
    assert payload["has_more"] is True
    hosts = {row["host"]: row["count"] for row in payload["hosts"]}
    assert hosts["api.example.com"] == 2
    assert "8.8.8.8" in payload["ips"]
    assert payload["scan_capped"] is False


def test_apk_urls_docstring_names_the_shape() -> None:
    doc = _tool_docstring("apk.urls")
    assert "hosts" in doc
    assert "ips" in doc
    assert "scan_capped" in doc
    assert "scheme" in doc
