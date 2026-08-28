"""proxy.content_types folds flows into a served-content inventory.

The core is fold_content_types, pure over the recorder's summary rows (which
already carry content_type and response_size), so these drive it with fake rows.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.proxy.client import (
    _classify_content_type,
    fold_content_types,
)
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


def _row(
    fid: str, content_type: str, size: int, *, host: str = "h", status: int | None = 200
) -> dict[str, Any]:
    return {
        "id": fid,
        "method": "GET",
        "url": f"https://{host}/{fid}",
        "host": host,
        "status": status,
        "content_type": content_type,
        "response_size": size,
    }


def test_classify_content_type_flags_payloads() -> None:
    assert _classify_content_type("application/x-dosexec") == ("executable", True)
    assert _classify_content_type("application/vnd.android.package-archive") == (
        "android_package",
        True,
    )
    assert _classify_content_type("application/java-archive") == ("java", True)
    assert _classify_content_type("application/zip") == ("archive", True)
    assert _classify_content_type("application/octet-stream") == ("binary", True)
    # Benign families are bucketed but not flagged.
    assert _classify_content_type("text/html") == ("text", False)
    assert _classify_content_type("application/json") == ("json", False)
    assert _classify_content_type("image/png") == ("image", False)
    assert _classify_content_type("") == ("unknown", False)


def test_content_types_group_and_sum_bytes() -> None:
    rows = [
        _row("1", "text/html; charset=utf-8", 100),
        _row("2", "text/html", 200),
        _row("3", "application/json", 50),
    ]
    result = fold_content_types(rows)
    by_type = {t["content_type"]: t for t in result["types"]}
    # The charset tail is dropped so both html flows fold into one bucket.
    assert by_type["text/html"]["count"] == 2
    assert by_type["text/html"]["bytes"] == 300
    assert by_type["text/html"]["category"] == "text"
    assert result["total_flows"] == 3
    assert result["typed_flows"] == 3
    assert result["total_bytes"] == 350
    assert result["type_count"] == 2


def test_content_types_flag_binary_downloads() -> None:
    rows = [
        _row("1", "text/html", 100),
        _row("2", "application/vnd.android.package-archive", 5_000_000, host="cdn.bad"),
        _row("3", "application/x-dosexec", 2_000_000, host="cdn.bad"),
    ]
    result = fold_content_types(rows)
    assert result["flagged_count"] == 2
    flagged_ids = {f["id"] for f in result["flagged"]}
    assert flagged_ids == {"2", "3"}
    apk = next(f for f in result["flagged"] if f["id"] == "2")
    assert apk["category"] == "android_package"
    assert apk["response_size"] == 5_000_000
    assert apk["host"] == "cdn.bad"


def test_content_types_handles_missing_content_type() -> None:
    rows = [_row("1", "", 0, status=None)]
    result = fold_content_types(rows)
    assert result["typed_flows"] == 0
    assert result["types"][0]["content_type"] == "(none)"
    assert result["types"][0]["suspicious"] is False


def test_proxy_content_types_docstring_names_the_shape() -> None:
    doc = _tool_docstring("proxy.content_types")
    assert "content_type" in doc
    assert "flagged" in doc
    assert "suspicious" in doc
    assert "total_bytes" in doc
