"""r2.functions description must name items_truncated when the list was cut."""

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
    """aflj shares enrich_r2_payload's cap, so functions truncate like the rest.

    Measured: 4099 functions, cap 4096, items_truncated=True, items_total=4099,
    items_limit=4096, no truncated, has_more or functions field. A large
    statically-linked binary really does exceed 4096 functions, and a caller
    reading the docstring should learn the true count lives in items_total --
    the same disclosure r2.strings/imports/exports/xrefs already make.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": f"sym.f{index}", "offset": 0x140001000 + index, "size": 16}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["aa", "aflj"]},
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
    assert "no" in doc and "functions" in doc
