"""r2.entrypoints maps iej entries to items with Address, and names the cut."""

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


def test_r2_entrypoints_map_vaddr_and_keep_the_type() -> None:
    """iej entries keep their type and gain a structured Address from vaddr.

    An entry point is picked out by vaddr (where execution starts), and vaddr is
    one of the keys the shared enrichment reads, so each row must carry an
    ``address`` dict alongside the type -- the field that tells the real entry
    from a TLS callback that runs before it.
    """
    binary = Path(__file__)  # any real file; ELF-shaped fixture, no PE base
    entries = [
        {"vaddr": 0x1060, "paddr": 0x1060, "haddr": 0x18, "hvaddr": 0x18, "type": "program"},
        {"vaddr": 0x1200, "paddr": 0x1200, "haddr": 0x20, "hvaddr": 0x20, "type": "tls"},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iej"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 2
    program = next(item for item in payload["items"] if item["type"] == "program")
    assert isinstance(program["address"], dict)
    assert program["address"]["va"] == 0x1060
    # This fixture has no PE ImageBase, so no RVA should be fabricated.
    assert "rva" not in program["address"]
    # The TLS callback -- the entry that runs before the program entry -- keeps
    # its own address so it can be disassembled directly.
    tls = next(item for item in payload["items"] if item["type"] == "tls")
    assert tls["address"]["va"] == 0x1200
    assert "entrypoints" not in payload
    assert "has_more" not in payload


def test_r2_entrypoints_say_when_the_list_was_cut() -> None:
    binary = Path(__file__)
    entries = [
        {"vaddr": 0x1000 + index * 8, "type": "program"} for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iej"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    assert payload["items_limit"] == _MAX_ITEMS


def test_r2_iej_is_whitelisted() -> None:
    """The entrypoints command must pass the backend whitelist unchanged."""
    _require_allowed_command("iej")


def test_r2_entrypoints_docstring_names_the_shape_and_the_cut() -> None:
    doc = _tool_docstring("r2.entrypoints")
    assert doc, "r2.entrypoints is missing its docstring"
    assert "iej" in doc
    assert "type" in doc
    assert "tls" in doc
    assert "items_truncated" in doc
    assert "entrypoints, truncated or has_more" in doc
