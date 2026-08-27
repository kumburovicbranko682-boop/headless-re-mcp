"""r2.sections maps the section table into items and names the cut honestly."""

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


def test_r2_sections_maps_entries_to_items(tmp_path: Path) -> None:
    """A section carries its name/perm/sizes and a mapped address.

    Measured: an iSj array of .text/.data comes back as items with name,
    size, vsize, paddr, vaddr and perm preserved and an address block added,
    under count. The field is items, not sections.
    """
    binary = tmp_path / "libx.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {
            "name": ".text",
            "paddr": 4096,
            "size": 8192,
            "vaddr": 4096,
            "vsize": 8192,
            "perm": "-r-x",
        },
        {
            "name": ".data",
            "paddr": 16384,
            "size": 512,
            "vaddr": 16384,
            "vsize": 512,
            "perm": "-rw-",
        },
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["count"] == 2
    assert "sections" not in payload
    text = payload["items"][0]
    assert text["name"] == ".text"
    assert text["size"] == 8192
    assert text["vsize"] == 8192
    assert text["paddr"] == 4096
    assert text["perm"] == "-r-x"
    assert isinstance(text["address"], dict)
    assert text["address"]["va"] == 4096
    doc = _tool_docstring("r2.sections")
    assert "items_truncated" in doc
    assert "no sections" in doc


def test_r2_sections_says_when_the_list_was_cut(tmp_path: Path) -> None:
    """A section table past the cap sets items_truncated, not a silent end."""
    binary = tmp_path / "libx.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 200)
    entries = [
        {"name": f"s{index}", "vaddr": 0x1000 + index, "size": 16, "perm": "-r--"}
        for index in range(_MAX_ITEMS + 3)
    ]
    payload = enrich_r2_payload(
        {"raw": json.dumps(entries), "commands": ["iSj"]},
        binary=binary,
    )
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 3
    assert "has_more" not in payload


def test_r2_sections_command_is_whitelisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """iSj passes the command whitelist and its output reaches items.

    Guards the one edit that could silently un-ship the tool: if iSj were not
    added to the allowlist, client.run would reject it before launch.
    """
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "libx.so"
    binary.write_bytes(b"\x7fELF" + b"\x00" * 8)
    entries = [{"name": ".text", "vaddr": 4096, "size": 32, "perm": "-r-x"}]

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        return Completed(0, json.dumps(entries).encode("utf-8"), b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = R2Client(executable).run(binary, ["iSj"])
    assert result["commands"] == ["iSj"]
    assert result["count"] == 1
    assert result["items"][0]["name"] == ".text"
