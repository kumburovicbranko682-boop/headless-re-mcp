"""r2.functions must document the same cut fields its sibling list tools do."""

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
    """functions is enriched exactly like strings/imports/exports/xrefs.

    aflj on a large binary can list far more than the 4096-item cap, at which
    point the payload carries items_truncated, items_total and items_limit -- the
    same "total is a floor" triple its sibling readers surface. Measured: 4099
    functions -> count 4096, items_truncated True, items_total 4099, no functions
    or has_more field.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {
            "name": f"fcn.{index:06d}",
            "offset": 0x140001000 + index,
            "size": 16,
        }
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
    assert "has_more" not in payload
    assert "functions" not in payload


def test_r2_list_tools_document_the_full_cut_triple() -> None:
    """Every truncatable r2 list tool must name all three cut fields.

    functions once named only items_truncated while strings/imports/exports/xrefs
    named items_truncated, items_total and items_limit -- yet enrich_r2_payload
    returns the same triple for all of them, so a caller reading the functions
    doc had no way to learn total is a floor. Guard the four (disasm is exempt:
    its count is capped at 512, below the 4096 item cap, so it never truncates).
    """
    for name in ("r2.functions", "r2.strings", "r2.imports", "r2.exports", "r2.xrefs"):
        doc = _tool_docstring(name)
        assert "items_truncated" in doc, name
        assert "items_total" in doc, name
        assert "items_limit" in doc, name
