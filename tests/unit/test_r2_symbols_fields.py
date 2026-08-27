"""r2.symbols maps isj entries to items with Address, and names the cut."""

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


def test_r2_symbols_map_vaddr_and_keep_symbol_fields() -> None:
    """isj entries keep their raw fields and gain a structured Address.

    A symbol is picked out by vaddr, and vaddr is one of the keys the shared
    enrichment reads, so each row must carry an ``address`` dict alongside the
    name/type/bind/is_imported a caller reads to tell a local FUNC from an
    imported thunk.
    """
    binary = Path(__file__)  # any real file; this fixture is ELF-shaped, no PE base
    entries = [
        {
            "name": name,
            "realname": name,
            "flagname": f"sym.{name}",
            "type": sym_type,
            "bind": bind,
            "size": size,
            "vaddr": va,
            "paddr": va,
            "is_imported": imported,
        }
        for name, sym_type, bind, size, va, imported in (
            ("main", "FUNC", "GLOBAL", 42, 0x1149, False),
            ("helper", "FUNC", "LOCAL", 20, 0x1130, False),
            ("puts", "FUNC", "GLOBAL", 0, 0x1030, True),
        )
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 3
    main = next(item for item in payload["items"] if item["name"] == "main")
    assert main["type"] == "FUNC"
    assert main["bind"] == "GLOBAL"
    assert main["is_imported"] is False
    assert isinstance(main["address"], dict)
    assert main["address"]["va"] == 0x1149
    # This fixture has no PE ImageBase, so no RVA should be fabricated.
    assert "rva" not in main["address"]
    # An imported thunk keeps is_imported true -- that is the flag separating
    # r2.imports' slice from the local symbols this superset also lists.
    imported = next(item for item in payload["items"] if item["name"] == "puts")
    assert imported["is_imported"] is True
    assert "symbols" not in payload
    assert "has_more" not in payload


def test_r2_symbols_say_when_the_list_was_cut() -> None:
    binary = Path(__file__)
    entries = [
        {"name": f"sym{index}", "type": "FUNC", "vaddr": 0x1000 + index}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    assert payload["items_limit"] == _MAX_ITEMS


def test_r2_symbols_docstring_names_the_shape_and_the_cut() -> None:
    doc = _tool_docstring("r2.symbols")
    assert doc, "r2.symbols is missing its docstring"
    assert "isj" in doc
    assert "is_imported" in doc
    assert "bind" in doc
    assert "items_truncated" in doc
    assert "symbols, truncated or has_more" in doc
