"""r2.sections maps each section's vaddr to an address and names the cut."""

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
    """The section-listing command must pass the r2 command whitelist."""
    _require_allowed_command("iSj")


def test_r2_sections_map_vaddr_to_address() -> None:
    """Each section carries its r2 fields plus a mapped address from vaddr."""
    entries = [
        {"name": ".text", "size": 0x100, "vsize": 0x100, "paddr": 0x1000,
         "vaddr": 0x401000, "perm": "-r-x"},
        {"name": ".data", "size": 0x40, "vsize": 0x40, "paddr": 0x2000,
         "vaddr": 0x402000, "perm": "-rw-"},
    ]
    # A PE image base so the va -> rva mapping has something to subtract.
    binary = Path("f.bin")
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
        architecture=Architecture.X64,
    )
    assert payload["count"] == 2
    text = payload["items"][0]
    assert text["name"] == ".text"
    assert text["perm"] == "-r-x"
    assert text["address"]["va"] == 0x401000
    assert "sections" not in payload


def test_r2_sections_say_when_the_list_was_cut(tmp_path: Path) -> None:
    """A section table longer than the cap reports items_truncated, not a
    silently-short list that reads as the whole layout."""
    binary = tmp_path / "f.bin"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {"name": f"s{index}", "vaddr": 0x1000 + index, "perm": "-r--"}
        for index in range(_MAX_ITEMS + 5)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 5
    assert "sections" not in payload
    assert "has_more" not in payload


def test_r2_sections_docstring_names_items_and_rwx() -> None:
    doc = _tool_docstring("r2.sections")
    assert "items" in doc
    assert "perm" in doc
    assert "rwx" in doc
    assert "no sections" in doc.lower()
