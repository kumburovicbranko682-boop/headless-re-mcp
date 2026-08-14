"""windbg.live_modules description must name truncated when cdb text was cut."""

from __future__ import annotations

import ast
import subprocess
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


def test_windbg_live_modules_says_when_cdb_text_was_cut(
    tmp_path: Path, monkeypatch: Any
) -> None:
    """The catalog named modules and never named the cut.

    Measured: 500-char cdb stdout, cap 64 -> truncated True, output_chars
    500, returned_chars 64, modules 64 chars. Looking at modules after a
    successful probe reads a listing that stopped at the buffer as every
    loaded module.
    """
    import headless_re_mcp.backends.windbg.client as windbg_module

    cdb = tmp_path / "cdb.exe"
    cdb.write_bytes(b"MZ")
    monkeypatch.setattr(windbg_module, "_MAX_OUTPUT", 64)

    def huge(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"A" * 500, stderr=b""
        )

    monkeypatch.setattr(windbg_module, "run_bounded", huge)
    monkeypatch.setattr(windbg_module, "_is_launchable_cdb", lambda _path: True)
    payload = WindbgClient(cdb).live_modules(4242, allowed_pid=4242)
    assert payload["truncated"] is True
    assert payload["output_chars"] == 500
    assert payload["returned_chars"] == 64
    assert payload["modules"] == "A" * 64
    assert payload["pid"] == 4242
    doc = _tool_docstring("windbg.live_modules")
    assert "truncated" in doc
    assert "output_chars" in doc
