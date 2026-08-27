"""r2.xrefs runs axtj (references TO the address), not the whole-binary axj dump.

``axj`` prints the entire binary's cross-reference table and ignores the ``@``
seek, so ``R2Client.xrefs`` -- which ran ``axj @ address`` -- answered "who
references this address?" with every xref in the file. ``axtj`` is the
seek-relative "references to" command. These tests pin the command switch and
that ``enrich_r2_payload`` surfaces the axtj entry shape (from/opcode/fcn_name,
with enriched from_address/fcn_address) without needing radare2; a live gate
proves it against the real tool.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

import headless_re_mcp.backends.r2.client as r2_module
from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2.client import R2Client
from headless_re_mcp.backends.r2.mapping import enrich_r2_payload
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


def test_xrefs_runs_axtj_not_axj(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The command actually spawned is axtj @ addr, never the global axj dump."""
    executable = tmp_path / "r2.exe"
    executable.write_bytes(b"")
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    scripts: list[str] = []

    def fake_run(cmd: list[str], **kwargs: Any) -> Completed:
        del kwargs
        # argv is [exe, "-q0", "-c", script, binary]; capture the script.
        scripts.append(cmd[3])
        return Completed(0, b"[]", b"")

    monkeypatch.setattr(r2_module, "run_bounded", fake_run)
    client = R2Client(executable)
    client.xrefs(binary, 0x401000)

    assert len(scripts) == 1
    script = scripts[0]
    assert "axtj @ 4198400" in script
    assert "axj @" not in script  # the buggy whole-binary command is gone


def test_enrich_maps_the_axtj_caller_shape(tmp_path: Path) -> None:
    """An axtj entry becomes a caller record: from-address, fcn_address, opcode.

    The shape mirrors what radare2 emits for ``axtj``: ``from`` is the call
    site, ``fcn_addr``/``fcn_name`` the containing function, and there is no
    forward ``to`` edge (the target is the queried address).
    """
    import json

    binary = tmp_path / "demo64.exe"
    image = bytearray(0x200)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x94:0x96] = (0xF0).to_bytes(2, "little")
    image[0x98:0x9A] = (0x20B).to_bytes(2, "little")
    image[0xB0:0xB8] = (0x140000000).to_bytes(8, "little")
    binary.write_bytes(bytes(image))

    entry = {
        "from": 0x140002000,
        "type": "CALL",
        "opcode": "call sym.helper",
        "fcn_addr": 0x140001F00,
        "fcn_name": "main",
        "refname": "sym.helper",
    }
    payload = enrich_r2_payload(
        {
            "raw": json.dumps([entry]),
            "commands": ["aa", "axtj @ 5368713216"],
            "address": 0x140001000,
        },
        binary=binary,
        architecture=Architecture.X64,
    )
    item = payload["items"][0]
    # The call site is the primary address and is echoed as from_address.
    assert item["address"]["va"] == 0x140002000
    assert item["from_address"]["va"] == 0x140002000
    assert item["from_address"]["rva"] == 0x2000
    # The containing function's address is surfaced as an Address too.
    assert item["fcn_address"]["va"] == 0x140001F00
    # radare2's own fields are preserved unchanged.
    assert item["opcode"] == "call sym.helper"
    assert item["fcn_name"] == "main"
    # No forward edge: axtj does not report a target.
    assert "to_address" not in item


def test_r2_xrefs_docstring_states_references_to_not_from() -> None:
    doc = " ".join(_tool_docstring("r2.xrefs").split())
    assert "References TO address" in doc
    assert "axtj" in doc
    # The old promise of a "to"/"to_address" edge is gone; axtj has no target.
    assert "no integer address, to, to_address" in doc
    # Companions the field tests already rely on must remain.
    assert "from_address" in doc
    assert "fcn_address" in doc
    assert "address_va" in doc
