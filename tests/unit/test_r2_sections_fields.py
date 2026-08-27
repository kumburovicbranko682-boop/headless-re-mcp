"""r2.sections maps iSj entries to items with Address, and names the cut."""

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


def test_r2_sections_map_vaddr_to_an_address() -> None:
    """iSj entries keep their raw fields and gain a structured Address.

    A section is picked out by vaddr, and vaddr is one of the keys the shared
    enrichment reads, so each row must carry an ``address`` dict alongside the
    name/perm/size the caller reads to lay out the binary.
    """
    binary = Path(__file__)  # any real file; this fixture is ELF-shaped, no PE base
    entries = [
        {"name": name, "size": size, "vsize": vsize, "paddr": va, "vaddr": va, "perm": perm}
        for name, size, vsize, va, perm in (
            (".text", 0x400, 0x400, 0x1000, "-r-x"),
            (".rodata", 0x80, 0x80, 0x2000, "-r--"),
            (".data", 0x40, 0x60, 0x3000, "-rw-"),
        )
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 3
    text = next(item for item in payload["items"] if item["name"] == ".text")
    assert text["perm"] == "-r-x"
    assert text["vsize"] == 0x400
    assert isinstance(text["address"], dict)
    assert text["address"]["va"] == 0x1000
    # This fixture has no PE ImageBase, so no RVA should be fabricated.
    assert "rva" not in text["address"]
    assert "sections" not in payload
    assert "has_more" not in payload


def test_r2_sections_say_when_the_list_was_cut() -> None:
    binary = Path(__file__)
    entries = [
        {"name": f"s{index}", "vaddr": 0x1000 + index}
        for index in range(_MAX_ITEMS + 2)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 2
    assert payload["items_limit"] == _MAX_ITEMS


def test_r2_sections_docstring_names_the_shape_and_the_cut() -> None:
    doc = _tool_docstring("r2.sections")
    assert doc, "r2.sections is missing its docstring"
    assert "iSj" in doc
    assert "perm" in doc
    assert "vsize" in doc
    assert "items_truncated" in doc
    assert "no sections" in doc
