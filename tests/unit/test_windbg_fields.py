"""windbg tool descriptions must name the fields the client actually returns."""

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


def test_windbg_live_threads_names_pid_not_process_id(monkeypatch: Any) -> None:
    """The catalog named threads and never named the pid field.

    Measured: live_threads(4242) -> pid 4242, threads holding the cdb text,
    no process_id or output key. Looking for process_id after a successful
    list reads as a debuggee that returned no process.
    """
    client = WindbgClient(cdb=Path("cdb.exe"))
    monkeypatch.setattr(
        client,
        "_run_process",
        lambda *args, **kwargs: {"output": "~0  Suspended"},
    )
    payload = client.live_threads(4242, allowed_pid=4242)
    assert "process_id" not in payload
    assert "output" not in payload
    assert payload["pid"] == 4242
    assert payload["threads"] == "~0  Suspended"
    doc = " ".join(_tool_docstring("windbg.live_threads").split())
    assert "Answers with threads" in doc
    assert "pid" in doc
    assert "There is no process_id" in doc