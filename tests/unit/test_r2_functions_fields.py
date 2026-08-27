"""r2.functions description must name items_total/items_limit when the list was cut."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
from headless_re_mcp.tools.r2 import build_r2_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_r2_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_r2_functions_says_when_the_list_was_cut(tmp_path: Path) -> None:
    """The docstring named items_truncated but not items_total/items_limit.

    aflj on a large binary runs through the same enrich_r2_payload cap as the
    string/import/export/xref lists, so a >4096-function binary comes back
    items_truncated=True with items_total and items_limit set. r2.functions
    was the one list tool whose docstring named only items_truncated, so a
    caller could not learn how many functions the cap hid -- and a big binary
    really does hold more than 4096. Measured: 4099 functions, cap 4096, count
    4096, items_total 4099, items_limit 4096, no truncated/has_more/functions
    field.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {
            "name": f"fcn.{index:08x}",
            "offset": 0x140001000 + index,
            "size": 16,
        }
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["aflj"]},
        binary=binary,
    )
    assert payload["count"] == 4096
    assert len(payload["items"]) == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert payload["items_limit"] == 4096
    assert "truncated" not in payload
    assert "has_more" not in payload
    assert "functions" not in payload
    doc = _tool_docstring("r2.functions")
    assert "items_truncated" in doc
    assert "items_total" in doc
    assert "items_limit" in doc
    assert "no functions field" in doc
