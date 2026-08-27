"""r2.classes maps icj entries, keeps methods/fields, and owns up when cut."""

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


def test_r2_classes_maps_addr_and_keeps_methods_and_fields(tmp_path: Path) -> None:
    """The catalog said classname, address and the member lists.

    Measured: icj on a C++ binary lists each class with an addr; enrich puts
    {va, ...} on item.address and leaves classname/methods/fields untouched.
    A caller keying on an integer address after a successful list reads as
    radare2 returning no class VA.
    """
    binary = tmp_path / "libnative.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {
            "classname": "Foo",
            "addr": 0x1140,
            "index": 0,
            "methods": [{"name": "Foo::bar", "addr": 0x1200}],
            "fields": [{"name": "Foo::x", "addr": 0x2000}],
        },
        {"classname": "Bar", "addr": 0x1300, "index": 1, "methods": [], "fields": []},
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["icj"]},
        binary=binary,
    )
    assert payload["count"] == 2
    items = payload["items"]
    assert [item["classname"] for item in items] == ["Foo", "Bar"]
    assert items[0]["address"]["va"] == 0x1140
    assert type(items[0]["address"]) is not int
    # The per-class member lists are radare2's, kept as-is.
    assert items[0]["methods"] == [{"name": "Foo::bar", "addr": 0x1200}]
    assert items[0]["fields"] == [{"name": "Foo::x", "addr": 0x2000}]
    described = _tool_docstring("r2.classes")
    assert "classname" in described
    assert "va/rva/module" in described
    assert "methods" in described and "fields" in described


def test_r2_classes_of_a_c_binary_is_an_empty_list(tmp_path: Path) -> None:
    """No recovered classes is an empty items list, not an error."""
    binary = tmp_path / "libc_only.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    payload = enrich_r2_payload(
        {"raw": json.dumps([]), "commands": ["icj"]},
        binary=binary,
    )
    assert payload["parsed"] is True
    assert payload["items"] == []
    assert payload["count"] == 0


def test_r2_classes_says_when_the_list_was_cut(tmp_path: Path) -> None:
    """A list stopped at the cap looks exactly like a list that ended."""
    binary = tmp_path / "libnative.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {"classname": f"C{index}", "addr": 0x1000 + index} for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["icj"]},
        binary=binary,
    )
    assert payload["count"] == 4096
    assert payload["items_truncated"] is True
    assert payload["items_total"] == 4099
    assert payload["items_limit"] == _MAX_ITEMS
    for absent in ("classes", "truncated", "has_more"):
        assert absent not in payload
    doc = _tool_docstring("r2.classes")
    assert "items_truncated" in doc


def test_icj_is_whitelisted_and_bogus_commands_are_not() -> None:
    """icj reaches the launcher; a lookalike does not silently slip through."""
    _require_allowed_command("icj")
    with pytest.raises(R2Error) as excinfo:
        _require_allowed_command("ic!")
    assert excinfo.value.code == "invalid_params"
