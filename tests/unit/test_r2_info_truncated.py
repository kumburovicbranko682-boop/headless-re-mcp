"""r2.info description must name truncated when identity text was cut."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

from headless_re_mcp.backends.common.bounded_run import Completed
from headless_re_mcp.backends.r2 import client as r2_client
from headless_re_mcp.backends.r2.client import _MAX_OUTPUT, R2Client
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


def test_r2_info_says_when_identity_text_was_cut(
    tmp_path: Path, monkeypatch: object
) -> None:
    """The catalog named raw and never named the cut.

    Measured: 1_000_040 bytes of identity text, cap 1_000_000, truncated=True,
    output_bytes=1000040, returned_bytes=1000000. Looking at raw after a
    successful call reads a listing that stopped at the buffer as the whole
    identity dump.
    """
    monkeypatch.setattr(
        r2_client,
        "run_bounded",
        lambda *args, **kwargs: Completed(
            returncode=0,
            stdout=b"X" * (_MAX_OUTPUT + 40),
            stderr=b"",
        ),
    )
    binary = tmp_path / "f.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 200)
    payload = R2Client(Path(sys.executable)).run(binary, ["i"])
    assert payload["truncated"] is True
    assert payload["output_bytes"] == _MAX_OUTPUT + 40
    assert payload["returned_bytes"] == _MAX_OUTPUT
    assert len(payload["raw"]) == _MAX_OUTPUT
    doc = _tool_docstring("r2.info")
    assert "truncated" in doc
    assert "output_bytes" in doc
