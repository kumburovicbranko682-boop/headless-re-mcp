"""r2.xrefs description must name items_truncated when the list was cut."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_xrefs_payload
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


def test_r2_xrefs_says_when_the_list_was_cut(tmp_path: Path) -> None:
    """The catalog named items and never named the cut.

    Measured: 4099 xrefs, cap 4096, items_truncated=True, items_total=4099,
    no truncated, has_more or xrefs field. Looking for a complete xref
    list after a successful call reads the rest of the graph as empty.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"from": 0x140002000 + index, "type": "CODE"} for index in range(_MAX_ITEMS + 3)
    ]
    # The cap applies to the merged axtj+axfj list: 4097 references into the
    # address plus 2 out of it still surface as one items_truncated cut.
    outgoing = [{"from": 0x140001000, "to": 0x140003000 + index} for index in range(2)]
    payload = enrich_xrefs_payload(
        {
            "raw": json.dumps(entries[: _MAX_ITEMS + 1]) + "\n" + json.dumps(outgoing),
            "commands": ["axtj @ 5368713216", "axfj @ 5368713216"],
            "address": 0x140001000,
        },
        binary=binary,
        address=0x140001000,
    )
    assert payload["count"] == 4096
    assert len(payload["items"]) == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert "xrefs" not in payload
    assert "has_more" not in payload
    doc = _tool_docstring("r2.xrefs")
    assert "items_truncated" in doc
    assert "no" in doc and "xrefs" in doc
