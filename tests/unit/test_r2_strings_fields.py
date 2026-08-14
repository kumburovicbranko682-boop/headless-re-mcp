"""r2.strings description must name items_truncated when the list was cut."""

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


def test_r2_strings_says_when_the_list_was_cut(tmp_path: Path) -> None:
    """The catalog named items and never named the cut.

    Measured: 4099 strings, cap 4096, items_truncated=True, items_total=4099,
    no truncated, has_more or strings field. Looking for a complete list
    after a successful call reads the rest of the binary as having none.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {
            "string": f"s{index}",
            "vaddr": 0x140001000 + index,
            "section": ".rdata",
            "type": "ascii",
        }
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["izj"]},
        binary=binary,
    )
    assert payload["count"] == 4096
    assert len(payload["items"]) == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert payload["items_limit"] == 4096
    assert "truncated" not in payload
    assert "has_more" not in payload
    assert "strings" not in payload
    doc = _tool_docstring("r2.strings")
    assert "items_truncated" in doc
    assert "no strings" in doc
