"""proxy.hosts folds flows into a distinct contacted-host inventory.

The core is fold_hosts, pure over the recorder's summary rows, so these drive
it directly with fake rows. No live proxy needed.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy.client import fold_hosts
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


def _row(method: str, url: str, host: str, status: int | None, **extra: Any) -> dict[str, Any]:
    row = {"method": method, "url": url, "host": host, "status": status}
    row.update(extra)
    return row


def test_hosts_aggregate_hits_methods_and_statuses() -> None:
    rows = [
        _row("GET", "https://api.example/a", "api.example", 200, seq=1),
        _row("POST", "https://api.example/b", "api.example", 201, seq=2),
        _row("GET", "https://api.example/a", "api.example", 200, seq=5),
    ]
    result = fold_hosts(rows)
    assert result["total"] == 1
    host = result["hosts"][0]
    assert host["host"] == "api.example"
    assert host["hits"] == 3
    assert host["methods"] == ["GET", "POST"]
    assert host["statuses"] == [200, 201]
    assert host["first_seq"] == 1
    assert host["last_seq"] == 5


def test_hosts_flag_cleartext_and_secure_by_scheme() -> None:
    rows = [
        _row("GET", "https://secure.example/x", "secure.example", 200, seq=1),
        _row("GET", "http://plain.example/y", "plain.example", 200, seq=2),
        _row("GET", "http://mixed.example/a", "mixed.example", 200, seq=3),
        _row("GET", "https://mixed.example/b", "mixed.example", 200, seq=4),
    ]
    by_host = {h["host"]: h for h in fold_hosts(rows)["hosts"]}
    assert by_host["secure.example"]["secure"] is True
    assert by_host["secure.example"]["cleartext"] is False
    assert by_host["plain.example"]["cleartext"] is True
    assert by_host["plain.example"]["secure"] is False
    assert by_host["mixed.example"]["schemes"] == ["http", "https"]
    assert by_host["mixed.example"]["cleartext"] is True
    assert by_host["mixed.example"]["secure"] is True


def test_hosts_count_errors_and_rank_by_hits() -> None:
    rows = [
        _row("GET", "https://hot.example/1", "hot.example", 200, seq=1),
        _row("GET", "https://hot.example/2", "hot.example", 200, seq=2),
        _row("GET", "https://cold.example/1", "cold.example", None, seq=3, error=True),
    ]
    result = fold_hosts(rows)
    assert result["hosts"][0]["host"] == "hot.example"
    assert result["hosts"][0]["hits"] == 2
    cold = next(h for h in result["hosts"] if h["host"] == "cold.example")
    assert cold["errors"] == 1
    assert cold["statuses"] == []


def test_hosts_derive_host_from_url_when_row_lacks_it() -> None:
    rows = [_row("GET", "https://derived.host/x", "", 200, seq=1)]
    assert fold_hosts(rows)["hosts"][0]["host"] == "derived.host"


def test_hosts_cap_the_returned_list() -> None:
    rows = [_row("GET", f"https://h{i}.example/x", f"h{i}.example", 200, seq=i) for i in range(10)]
    result = fold_hosts(rows, limit=3)
    assert result["count"] == 3
    assert result["total"] == 10
    assert result["truncated"] is True


def test_hosts_on_an_empty_capture() -> None:
    result = fold_hosts([])
    assert result["total"] == 0
    assert result["total_flows"] == 0
    assert result["hosts"] == []


def test_proxy_hosts_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.hosts")
    assert "cleartext" in doc
    assert "schemes" in doc
    assert "first_seq" in doc
    assert "total_flows" in doc
