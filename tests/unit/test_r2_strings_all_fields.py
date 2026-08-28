"""r2.strings_all must scan the whole file (izzj) and map every hit's vaddr."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client, R2Error
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


def _service_command_for(func_name: str) -> list[str]:
    """The literal command list a one-line _r2_request method passes."""
    source = Path("src/headless_re_mcp/core/service_ext.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "_r2_request"
                ):
                    # commands is the third positional arg.
                    return ast.literal_eval(call.args[2])
    raise AssertionError(f"{func_name} does not call _r2_request")


def _client_and_binary(tmp_path: Path) -> tuple[R2Client, Path]:
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    return R2Client(executable), binary


def test_strings_all_routes_izzj_not_izj() -> None:
    """The distinction is the whole point: izzj scans the file, izj the data."""
    assert _service_command_for("r2_strings_all") == ["izzj"]
    assert _service_command_for("r2_strings") == ["izj"]


def test_izzj_is_whitelisted_and_izj_still_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    result = client.run(binary, ["izzj"])
    assert result["commands"] == ["izzj"]
    assert len(launched) == 1


def test_izzj_composed_forms_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, binary = _client_and_binary(tmp_path)
    launched: list[list[str]] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        launched.append(cmd)
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    for bad in ("izzj foo", "izzj;!echo x", "izzj @ 0", "izzjj"):
        with pytest.raises(R2Error, match="not whitelisted"):
            client.run(binary, [bad])
    assert launched == []


def test_strings_all_maps_vaddr_including_between_sections(tmp_path: Path) -> None:
    """izzj hits often sit between sections (section == ''); still map them.

    A whole-file scan surfaces the interpreter path and imported symbol names
    that izj misses. Each carries vaddr, so the address object must still be
    built even when the hit is not inside a named section.
    """
    pe = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    pe.write_bytes(bytes(image))
    entries = [
        {"string": "printf", "vaddr": 0x140002000, "section": "", "type": "ascii"},
        {
            "string": "/lib64/ld-linux-x86-64.so.2",
            "vaddr": 0x140002100,
            "section": ".interp",
            "type": "ascii",
        },
    ]
    payload = enrich_r2_payload({"raw": json.dumps(entries), "commands": ["izzj"]}, binary=pe)
    assert payload["count"] == 2
    first = payload["items"][0]
    assert first["string"] == "printf"
    assert first["address"] == {
        "module": "demo64.exe",
        "rva": 0x2000,
        "va": 0x140002000,
        "architecture": "x64",
    }
    assert payload["items"][1]["address"]["va"] == 0x140002100


def test_strings_all_says_when_the_list_was_cut(tmp_path: Path) -> None:
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    entries = [
        {"string": f"s{i}", "vaddr": 0x140001000 + i, "section": "", "type": "ascii"}
        for i in range(_MAX_ITEMS + 5)
    ]
    payload = enrich_r2_payload({"raw": json.dumps(entries), "commands": ["izzj"]}, binary=binary)
    assert payload["count"] == _MAX_ITEMS
    assert payload["items_truncated"] is True
    assert payload["items_total"] == _MAX_ITEMS + 5
    assert payload["items_limit"] == _MAX_ITEMS
    assert "truncated" not in payload
    assert "has_more" not in payload
    assert "strings" not in payload


def test_strings_all_docstring_contract() -> None:
    doc = _tool_docstring("r2.strings_all")
    assert "izzj" in doc
    assert "r2.strings" in doc
    assert "items_truncated" in doc
    assert "no integer address" in doc.replace("\n", " ")
