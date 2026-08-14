"""windbg.attach description must name truncated when probe text was cut."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.windbg.client import _MAX_ATTACH_OUTPUT, WindbgClient
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


def test_windbg_attach_says_when_probe_text_was_cut(monkeypatch: Any) -> None:
    """The catalog named output and never named the cut.

    Measured: 8040-char session, cap 8000 -> truncated True, output_chars
    8040, returned_chars 8000, output 8000 chars. Looking at output after a
    successful attach reads a probe that stopped at the buffer as the whole
    vertarget/version dump.
    """
    client = WindbgClient(cdb=Path("cdb.exe"))
    monkeypatch.setattr(
        client,
        "_run_process",
        lambda *args, **kwargs: {"output": "A" * (_MAX_ATTACH_OUTPUT + 40)},
    )
    payload = client.attach(4242, allowed_pid=4242)
    assert payload["truncated"] is True
    assert payload["output_chars"] == _MAX_ATTACH_OUTPUT + 40
    assert payload["returned_chars"] == _MAX_ATTACH_OUTPUT
    assert payload["output"] == "A" * _MAX_ATTACH_OUTPUT
    doc = _tool_docstring("windbg.attach")
    assert "truncated" in doc
    assert "8_000" in doc or "8000" in doc
