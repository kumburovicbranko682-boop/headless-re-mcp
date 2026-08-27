"""r2.open descriptions must name the fields the one-shot check actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.backends.r2.client import R2Client
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


def test_r2_open_puts_identity_text_in_info_not_raw(tmp_path: Path) -> None:
    """r2.info answers with raw; r2.open does not.

    Measured: open() keys are binary, info, note, opened. raw is absent.
    Looking for raw after a successful open reads as radare2 printing
    nothing, so the overnight pass retries open or skips analysis.
    """
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    binary = tmp_path / "a.exe"
    binary.write_bytes(b"MZ")
    client = R2Client(stub)
    client.run = lambda _binary, _cmds, timeout=30.0, slice_arch=None: {  # type: ignore[method-assign]
        "raw": "arch     x86\nbinsz    16\n"
    }
    payload = client.open(binary)
    assert "raw" not in payload
    assert payload["opened"] is True
    assert payload["info"].startswith("arch")
    assert payload["binary"] == str(binary)
    doc = _tool_docstring("r2.open")
    assert "Answers with opened" in doc
    assert "info" in doc
    assert "not a raw field" in doc
