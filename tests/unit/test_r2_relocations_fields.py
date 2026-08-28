"""r2.relocations must map each irj row and keep the reloc type/name/ifunc."""

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


def test_r2_relocations_map_each_row_and_keep_type_and_name() -> None:
    """Each irj row must gain a mapped address while keeping type/name/is_ifunc.

    A named relocation (a GOT/PLT slot bound to an import like printf) is the
    map that turns an indirect call into a named target, so an agent pivots from
    the reloc's vaddr into disasm/read: name, type and a mapped address all have
    to survive enrichment. On an ELF r2 reports absolute vaddrs (no image base),
    so mapped means va.
    """
    binary = Path(__file__)  # any real file; ELF/PE header only affects arch/base
    entries = [
        {"type": "ADD_64", "ntype": 8, "vaddr": 0x3DD0, "paddr": 0x2DD0, "is_ifunc": False},
        {
            "name": "printf",
            "type": "SET_64",
            "ntype": 6,
            "vaddr": 0x3FC0,
            "paddr": 0x2FC0,
            "is_ifunc": False,
        },
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["irj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 2
    named = next(row for row in payload["items"] if row.get("name") == "printf")
    assert named["type"] == "SET_64"
    assert named["is_ifunc"] is False
    assert isinstance(named.get("address"), dict)
    assert named["address"].get("va") == 0x3FC0
    # A reloc row is not xref-shaped, so it must not sprout to/from fields.
    assert "to_address" not in named
    assert "from_address" not in named
    # A relative rebase carries no name but is still mapped by its vaddr.
    unnamed = next(row for row in payload["items"] if "name" not in row)
    assert unnamed["type"] == "ADD_64"
    assert isinstance(unnamed.get("address"), dict)


def test_r2_relocations_say_when_the_list_was_cut() -> None:
    """A reloc table longer than the cap must be flagged, not silently ended.

    The same disclosure the other r2 readers make (items_truncated/items_total/
    items_limit, and no relocations/has_more field) so "these are all the
    relocations" is never a wrong read on a crafted table.
    """
    binary = Path(__file__)
    entries = [
        {"type": "SET_64", "vaddr": 0x3000 + index * 8, "is_ifunc": False}
        for index in range(_MAX_ITEMS + 5)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["irj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 5
    assert "relocations" not in payload
    assert "has_more" not in payload
    doc = _tool_docstring("r2.relocations")
    assert "is_ifunc" in doc
    assert "items_truncated" in doc
    assert "no relocations" in doc


def test_r2_relocations_empty_table_is_a_clean_parse() -> None:
    """A binary with no relocations must read as parsed with zero items."""
    binary = Path(__file__)
    payload = enrich_r2_payload(
        {"raw": "[]", "commands": ["irj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 0
    assert payload["items"] == []
