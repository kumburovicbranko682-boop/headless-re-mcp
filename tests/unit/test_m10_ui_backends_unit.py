"""Unit tests for SendInput foreground PID fail-closed."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from headless_re_mcp.core.windows import UiPidBoundaryError


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
def test_sendinput_requires_foreground_allowed() -> None:
    from headless_re_mcp.core import ui_sendinput

    with (
        patch.object(ui_sendinput, "foreground_hwnd", return_value=0x111),
        patch.object(ui_sendinput, "hwnd_owner_pid", return_value=9999),
    ):
        with pytest.raises(UiPidBoundaryError) as exc:
            ui_sendinput.require_foreground_allowed(frozenset({1, 2, 3}))
    assert exc.value.code == "permission_denied"


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
def test_uia_available_probe() -> None:
    from headless_re_mcp.core.ui_uia import uia_available

    assert isinstance(uia_available(), bool)


@pytest.mark.skipif(os.name != "nt", reason="Windows only")
def test_windows_ocr_available_probe() -> None:
    from headless_re_mcp.core.ui_ocr import windows_ocr_available

    assert isinstance(windows_ocr_available(), bool)


def test_the_tree_tool_names_a_cut_walk() -> None:
    """The walk already set truncated; the description did not.

    An agent that only reads the tool text treats a max_nodes stop as the
    whole window tree.
    """
    import ast
    import inspect

    from headless_re_mcp.tools import ui as ui_tools

    tree = ast.parse(inspect.getsource(ui_tools.build_ui_tools))
    docs = {
        node.name: ast.get_docstring(node)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    }
    assert docs["ui_tree"]
    assert "truncated" in docs["ui_tree"]
