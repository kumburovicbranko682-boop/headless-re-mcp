"""r2.entrypoints must map each entry and disclose a cut list."""

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


def test_r2_entrypoints_map_the_program_entry(tmp_path: Path) -> None:
    """The program entry must gain a mapped address while keeping type and baddr.

    An agent seeds r2.disasm at the program entry on a stripped target, so the
    vaddr has to survive as a mapped address and the type has to say which entry
    this is (program vs init/fini).
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"paddr": 0xD20, "vaddr": 0x1400013E0, "baddr": 0x140000000,
         "laddr": 0, "haddr": 0x118, "type": "program"},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iej"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["count"] == 1
    entry = payload["items"][0]
    assert entry["type"] == "program"
    assert entry["baddr"] == 0x140000000
    assert isinstance(entry.get("address"), dict)
    assert entry["address"].get("va") == 0x1400013E0
    # An entry row is not xref-shaped, so it must not sprout to/from fields.
    assert "to_address" not in entry
    assert "from_address" not in entry


def test_r2_entrypoints_say_when_the_list_was_cut(tmp_path: Path) -> None:
    """An entry list past the cap must be flagged, not silently ended.

    Measured: 4099 entries, cap 4096, items_truncated=True, items_total=4099,
    and no entrypoints/truncated/has_more field -- the same disclosure the other
    r2 readers make so "these are all the entries" is never a wrong read.
    """
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"vaddr": 0x140001000 + index, "type": "init"}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iej"]},
        binary=binary,
    )
    assert payload["count"] == 4096
    assert len(payload["items"]) == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert "entrypoints" not in payload
    assert "has_more" not in payload
    doc = _tool_docstring("r2.entrypoints")
    assert "program" in doc
    assert "items_truncated" in doc
    assert "no entrypoints" in doc
