"""r2.functions must name the list-cut fields exactly like its siblings.

r2.functions runs ``aflj`` and, like r2.strings / imports / exports / xrefs,
projects the JSON array through enrich_r2_payload and caps it at 4096 items.
Its siblings all name items_truncated, items_total and items_limit so a caller
that hit the cap can read the true count; r2.functions was the one r2 list tool
with no field test, and its docstring had drifted to name only items_truncated
-- leaving items_total and items_limit returned-but-unnamed. An unattended pass
reading r2.functions on a large binary would see the cut but have no field the
docstring told it about for how many functions really exist.
"""

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
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": f"fcn.{0x140001000 + index:08x}", "offset": 0x140001000 + index, "size": 16}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["aa", "aflj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert len(payload["items"]) == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    assert payload["items_limit"] == _MAX_ITEMS
    assert "truncated" not in payload
    assert "has_more" not in payload
    assert "functions" not in payload
    first = payload["items"][0]
    assert "name" in first and "offset" in first and "size" in first
    assert "address" in first  # va/rva/module, mapped from offset


def test_r2_functions_docstring_names_the_list_cut_fields() -> None:
    doc = _tool_docstring("r2.functions")
    assert "items_truncated" in doc
    assert "items_total" in doc
    assert "items_limit" in doc
    assert "4096" in doc
    assert "no functions" in doc
