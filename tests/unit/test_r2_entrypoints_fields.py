"""r2.entrypoints maps iej entries, keeps type, and owns up when the list was cut."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from headless_re_mcp.backends.r2.client import R2Error, _require_allowed_command
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


def test_r2_entrypoints_maps_each_entry_and_keeps_type(tmp_path: Path) -> None:
    """The catalog said items carry type and an address object, not a bare VA.

    Measured: iej on a native .so lists the program entry plus init/fini
    constructors; enrich_r2_payload puts {va, ...} on each item.address from
    vaddr and leaves type untouched. A caller keying on an integer address
    after a successful list reads radare2 as having returned no VA.
    """
    binary = tmp_path / "libnative.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {"vaddr": 0x1140, "paddr": 0x1140, "type": "program"},
        {"vaddr": 0x1200, "paddr": 0x1200, "type": "init"},
        {"vaddr": 0x1260, "paddr": 0x1260, "type": "fini"},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iej"]},
        binary=binary,
    )
    assert payload["count"] == 3
    items = payload["items"]
    assert [item["type"] for item in items] == ["program", "init", "fini"]
    assert items[0]["address"]["va"] == 0x1140
    assert items[1]["address"]["va"] == 0x1200
    assert type(items[0]["address"]) is not int
    described = _tool_docstring("r2.entrypoints")
    assert "Answers with items" in described
    assert "va/rva/module" in described
    assert "no integer address" in described.replace("\n", " ")
    assert "init" in described and "fini" in described


def test_r2_entrypoints_says_when_the_list_was_cut(tmp_path: Path) -> None:
    """A list stopped at the cap looks exactly like a list that ended.

    Measured: 4099 entries, cap 4096, items_truncated=True, items_total=4099,
    and no entrypoints, entries, truncated or has_more field to misread.
    """
    binary = tmp_path / "libnative.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [{"vaddr": 0x1000 + index, "type": "init"} for index in range(_MAX_ITEMS + 3)]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iej"]},
        binary=binary,
    )
    assert payload["count"] == 4096
    assert len(payload["items"]) == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert payload["items_limit"] == _MAX_ITEMS
    for absent in ("entrypoints", "entries", "truncated", "has_more"):
        assert absent not in payload
    doc = _tool_docstring("r2.entrypoints")
    assert "items_truncated" in doc
    assert "no" in doc and "has_more" in doc


def test_r2_entrypoints_of_a_data_object_is_an_empty_list(tmp_path: Path) -> None:
    """No entry point is an empty items list, not an error or a missing key."""
    binary = tmp_path / "data.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    payload = enrich_r2_payload(
        {"raw": json.dumps([]), "commands": ["iej"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["items"] == []
    assert payload["count"] == 0


def test_iej_is_whitelisted_and_bogus_commands_are_not() -> None:
    """iej reaches the launcher; a lookalike does not silently slip through."""
    _require_allowed_command("iej")
    with pytest.raises(R2Error) as excinfo:
        _require_allowed_command("ie!")
    assert excinfo.value.code == "invalid_params"
