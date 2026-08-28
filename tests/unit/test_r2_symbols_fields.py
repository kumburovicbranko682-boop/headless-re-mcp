"""r2.symbols maps each symbol's vaddr to an address and names the cut."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from headless_re_mcp.backends.r2.client import _require_allowed_command
from headless_re_mcp.backends.r2.mapping import _MAX_ITEMS, enrich_r2_payload
from headless_re_mcp.core.models import Architecture
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


def test_isj_is_whitelisted() -> None:
    """The symbol-listing command must pass the r2 command whitelist."""
    _require_allowed_command("isj")


def test_r2_symbols_carry_type_bind_and_mapped_address() -> None:
    """Each symbol keeps its r2 fields (type/bind) and gains a mapped address,
    including OBJ data symbols no other r2 tool surfaces."""
    entries = [
        {"name": "main", "type": "FUNC", "bind": "GLOBAL", "size": 0x30,
         "vaddr": 0x401130, "paddr": 0x1130},
        {"name": "global_table", "type": "OBJ", "bind": "GLOBAL", "size": 0x10,
         "vaddr": 0x404010, "paddr": 0x3010},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=Path("f.bin"),
        architecture=Architecture.X64,
    )
    assert payload["count"] == 2
    obj = payload["items"][1]
    assert obj["name"] == "global_table"
    assert obj["type"] == "OBJ"
    assert obj["bind"] == "GLOBAL"
    assert obj["address"]["va"] == 0x404010
    assert "symbols" not in payload


def test_r2_symbols_say_when_the_list_was_cut(tmp_path: Path) -> None:
    """A symbol table longer than the cap reports items_truncated, not a
    silently-short list that reads as the whole table."""
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {"name": f"sym{index}", "type": "FUNC", "vaddr": 0x1000 + index}
        for index in range(_MAX_ITEMS + 7)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 7
    assert "symbols" not in payload
    assert "has_more" not in payload


def test_r2_symbols_docstring_names_items_type_and_obj() -> None:
    doc = _tool_docstring("r2.symbols")
    assert "items" in doc
    assert "type" in doc
    assert "OBJ" in doc
    assert "no" in doc.lower() and "symbols" in doc.lower()
