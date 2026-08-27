"""r2.open must say when the identity preview was cut at the info buffer."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from headless_re_mcp.backends.r2.client import _MAX_OPEN_INFO, R2Client
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


def test_r2_open_says_when_the_identity_preview_was_cut(tmp_path: Path) -> None:
    """r2.info flags a cut identity dump; r2.open cut the same text silently.

    open() inlines the ``i`` text as info but slices it to 8000 characters --
    tighter than run()'s 1 MB buffer, so run()'s own truncated flag never
    fires. A caller reading info for the section or library count would read a
    preview that stopped at the buffer as the whole identity dump. It now says
    info_truncated when that slice dropped anything.
    """
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    binary = tmp_path / "a.exe"
    binary.write_bytes(b"MZ")
    client = R2Client(stub)
    full = "lib libc.so\n" * _MAX_OPEN_INFO  # far longer than the info buffer
    client.run = lambda _binary, _cmds, timeout=30.0: {"raw": full}  # type: ignore[method-assign]

    payload = client.open(binary)

    assert payload["info_truncated"] is True
    assert len(payload["info"]) == _MAX_OPEN_INFO
    assert "raw" not in payload
    doc = _tool_docstring("r2.open")
    assert "info_truncated" in doc


def test_r2_open_short_identity_is_not_flagged(tmp_path: Path) -> None:
    """A preview that fits the buffer must not claim it was cut."""
    stub = tmp_path / "r2.exe"
    stub.write_bytes(b"")
    binary = tmp_path / "a.exe"
    binary.write_bytes(b"MZ")
    client = R2Client(stub)
    identity: dict[str, Any] = {"raw": "arch     x86\nbinsz    16\n"}
    client.run = lambda _binary, _cmds, timeout=30.0: identity  # type: ignore[method-assign]

    payload = client.open(binary)

    assert "info_truncated" not in payload
    assert payload["info"].startswith("arch")
