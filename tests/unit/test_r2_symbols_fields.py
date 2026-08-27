"""r2.symbols must map every symbol and disclose a cut table, not just exports."""

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


def test_r2_symbols_map_each_row_and_keep_type_and_bind(tmp_path: Path) -> None:
    """Each isj row must gain a mapped address while keeping type/bind/is_imported.

    The point of symbols over exports is the local, non-exported names, and an
    agent branches on type (FUNC vs OBJ) and bind (LOCAL vs GLOBAL), so those
    fields have to survive enrichment intact.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": "frame_dummy", "type": "FUNC", "bind": "LOCAL", "vaddr": 0x140001120,
         "size": 0, "is_imported": False},
        {"name": "main", "type": "FUNC", "bind": "GLOBAL", "vaddr": 0x140001000,
         "size": 31, "is_imported": False},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 2
    local = next(row for row in payload["items"] if row["name"] == "frame_dummy")
    assert local["bind"] == "LOCAL"
    assert local["type"] == "FUNC"
    assert local["is_imported"] is False
    assert isinstance(local.get("address"), dict)
    assert local["address"].get("va") == 0x140001120
    # A symbol row is not xref-shaped, so it must not sprout to/from fields.
    assert "to_address" not in local
    assert "from_address" not in local


def test_r2_symbols_say_when_the_list_was_cut(tmp_path: Path) -> None:
    """A symbol table past the cap must be flagged, not silently ended.

    Measured: 4099 symbols, cap 4096, items_truncated=True, items_total=4099,
    and no symbols/truncated/has_more field -- the same disclosure the other r2
    readers make so "these are all the symbols" is never a wrong read.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": f"sym{index}", "type": "FUNC", "bind": "LOCAL",
         "vaddr": 0x140001000 + index}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["count"] == 4096
    assert len(payload["items"]) == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert "symbols" not in payload
    assert "has_more" not in payload
    doc = _tool_docstring("r2.symbols")
    assert "LOCAL" in doc
    assert "is_imported" in doc
    assert "items_truncated" in doc
    assert "no symbols" in doc
