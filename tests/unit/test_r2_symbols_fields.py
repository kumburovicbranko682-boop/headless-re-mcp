"""r2.symbols maps the isj table and names the cut; isj is whitelisted."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client
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


def test_r2_symbols_maps_each_entry_and_keeps_its_bind_type_size(tmp_path: Path) -> None:
    """isj carries bind/type/size a caller sizing a table needs, plus an Address.

    A raw vaddr reads the same whether the loader placed the module at that base
    or not, so the mapped address (va/rva/module) is what tells a local symbol's
    live location from its file offset.
    """
    binary = tmp_path / "libnative.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {
            "name": "computeHmac",
            "type": "FUNC",
            "bind": "LOCAL",
            "size": 128,
            "vaddr": 0x1200,
            "paddr": 0x1200,
        },
        {
            "name": "gConfig",
            "type": "OBJECT",
            "bind": "GLOBAL",
            "size": 8,
            "vaddr": 0x4050,
            "paddr": 0x4050,
        },
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["count"] == 2
    local = payload["items"][0]
    assert local["name"] == "computeHmac"
    assert local["type"] == "FUNC"
    assert local["bind"] == "LOCAL"
    assert local["size"] == 128
    assert local["address"]["va"] == 0x1200
    assert "symbols" not in payload
    assert "has_more" not in payload


def test_r2_symbols_says_when_the_table_was_cut(tmp_path: Path) -> None:
    binary = tmp_path / "libnative.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {"name": f"s{index}", "type": "FUNC", "vaddr": 0x1000 + index}
        for index in range(_MAX_ITEMS + 5)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["isj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 5
    assert payload["items_limit"] == _MAX_ITEMS
    doc = _tool_docstring("r2.symbols")
    assert "items_truncated" in doc
    assert "no symbols" in doc


def test_isj_is_whitelisted_and_reaches_the_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tool is inert unless isj clears the strict command whitelist."""
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "libnative.so"
    binary.write_bytes(b"\x7fELF")
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = R2Client(executable).run(binary, ["isj"])

    assert result["commands"] == ["isj"]
    assert len(launched) == 1
