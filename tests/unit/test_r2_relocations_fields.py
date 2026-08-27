"""r2.relocations maps irj entries to items with Address, and names the cut."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.client import _require_allowed_command
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


def test_r2_relocations_map_vaddr_and_keep_reloc_fields() -> None:
    """irj entries keep their raw fields and gain a structured Address.

    A relocation is picked out by vaddr (the slot the loader patches), and
    vaddr is one of the keys the shared enrichment reads, so each row must
    carry an ``address`` dict alongside the type/name a caller reads to tell
    which import lands in which GOT/PLT slot.
    """
    binary = Path(__file__)  # any real file; ELF-shaped fixture, no PE base
    entries = [
        {
            "demname": demname,
            "name": name,
            "type": reloc_type,
            "vaddr": va,
            "paddr": va - 0x1000,
            "is_ifunc": False,
        }
        for demname, name, reloc_type, va in (
            ("puts", "puts", "JUMP_SLOT", 0x4018),
            ("__libc_start_main", "__libc_start_main", "GLOB_DAT", 0x3FE0),
            ("", "", "ADD_64", 0x4000),
        )
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["irj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 3
    jump = next(item for item in payload["items"] if item["name"] == "puts")
    assert jump["type"] == "JUMP_SLOT"
    assert jump["is_ifunc"] is False
    assert isinstance(jump["address"], dict)
    assert jump["address"]["va"] == 0x4018
    # This fixture has no PE ImageBase, so no RVA should be fabricated.
    assert "rva" not in jump["address"]
    # An anonymous relocation (no symbol) still maps its slot address.
    anon = next(item for item in payload["items"] if item["type"] == "ADD_64")
    assert anon["name"] == ""
    assert anon["address"]["va"] == 0x4000
    assert "relocations" not in payload
    assert "has_more" not in payload


def test_r2_relocations_say_when_the_list_was_cut() -> None:
    binary = Path(__file__)
    entries = [
        {"name": f"sym{index}", "type": "JUMP_SLOT", "vaddr": 0x4000 + index * 8}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["irj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    assert payload["items_limit"] == _MAX_ITEMS


def test_r2_irj_is_whitelisted() -> None:
    """The relocations command must pass the backend whitelist unchanged."""
    _require_allowed_command("irj")


def test_r2_relocations_docstring_names_the_shape_and_the_cut() -> None:
    doc = _tool_docstring("r2.relocations")
    assert doc, "r2.relocations is missing its docstring"
    assert "irj" in doc
    assert "type" in doc
    assert "is_ifunc" in doc
    assert "items_truncated" in doc
    assert "relocations, truncated or has_more" in doc
