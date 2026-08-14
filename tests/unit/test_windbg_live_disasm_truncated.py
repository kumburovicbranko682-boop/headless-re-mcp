"""windbg.live_disasm description must name truncated when cdb text was cut."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.windbg.client import WindbgClient
from headless_re_mcp.tools.windbg import build_windbg_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_windbg_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_windbg_live_disasm_says_when_cdb_text_was_cut(monkeypatch: Any) -> None:
    """The catalog named disasm and never named the cut.

    Measured: 500-char session, cap 64 -> truncated True, output_chars 500,
    returned_chars 64, disasm 64 chars. Looking at disasm after a successful
    live probe reads a listing that stopped at the buffer as the whole
    function.
    """
    client = WindbgClient(cdb=Path("cdb.exe"))
    monkeypatch.setattr(
        client,
        "_run_process",
        lambda *args, **kwargs: {
            "output": "A" * 64,
            "truncated": True,
            "output_chars": 500,
            "returned_chars": 64,
        },
    )
    payload = client.live_disasm(4242, 0x401000, allowed_pid=4242, length=16)
    assert payload["truncated"] is True
    assert payload["output_chars"] == 500
    assert payload["returned_chars"] == 64
    assert payload["disasm"] == "A" * 64
    assert "output" not in payload
    doc = _tool_docstring("windbg.live_disasm")
    assert "truncated" in doc
    assert "output_chars" in doc
