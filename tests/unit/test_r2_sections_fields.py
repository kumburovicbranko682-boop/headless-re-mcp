"""r2.sections must map each section's address and disclose a cut list."""

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


def test_r2_sections_map_each_row_and_keep_perms(tmp_path: Path) -> None:
    """Each iSj row must gain a mapped address while keeping name and perm.

    An agent pivots from a section's vaddr into disasm and reads perm to spot a
    writable-and-executable segment, so both have to survive enrichment.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": ".text", "vaddr": 0x140001000, "paddr": 0x400, "size": 0x200,
         "vsize": 0x200, "perm": "-r-x"},
        {"name": ".data", "vaddr": 0x140002000, "paddr": 0x600, "size": 0x100,
         "vsize": 0x100, "perm": "-rw-"},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 2
    text = next(row for row in payload["items"] if row["name"] == ".text")
    assert text["perm"] == "-r-x"
    assert isinstance(text.get("address"), dict)
    assert text["address"].get("va") == 0x140001000
    # A section row is not xref-shaped, so it must not sprout to/from fields.
    assert "to_address" not in text
    assert "from_address" not in text


def test_r2_sections_say_when_the_list_was_cut(tmp_path: Path) -> None:
    """A section table longer than the cap must be flagged, not silently ended.

    Measured: 4099 sections, cap 4096, items_truncated=True, items_total=4099,
    and no sections/truncated/has_more field -- the same disclosure the other
    r2 readers make so "these are all the sections" is never a wrong read.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"name": f"s{index}", "vaddr": 0x140001000 + index, "perm": "-r--"}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["count"] == 4096
    assert len(payload["items"]) == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert "sections" not in payload
    assert "has_more" not in payload
    doc = _tool_docstring("r2.sections")
    assert "perm" in doc
    assert "items_truncated" in doc
    assert "no sections" in doc
