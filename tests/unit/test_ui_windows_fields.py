"""ui.windows.list must name the field the enumerator actually returns."""

from __future__ import annotations

import ast
from pathlib import Path

from headless_re_mcp.core.service_ui import _ui_finalize_windows
from headless_re_mcp.tools.ui import build_ui_tools


def _tool_docstring(name: str) -> str:
    source = Path(build_ui_tools.__code__.co_filename).read_text(encoding="utf-8")
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


def test_ui_windows_list_puts_hwnds_in_windows_not_items() -> None:
    """The catalog said list windows and never named the list field.

    Measured: _ui_finalize_windows keeps windows and sets count. There is no
    items or tree field. Looking for items after a successful list reads as
    the debuggee having no windows, so the agent retries or drives clicks
    against hwnds it never got.
    """
    payload = _ui_finalize_windows(
        {"windows": [{"hwnd": 1, "pid": 7, "class_name": "A", "title": "t"}]},
        {"allowed": frozenset({7}), "debuggee_pid": 7},
    )
    assert "items" not in payload
    assert "tree" not in payload
    assert payload["count"] == 1
    assert payload["windows"][0]["hwnd"] == 1
    described = _tool_docstring("ui.windows.list")
    assert "Answers with windows" in described
    assert "no items" in described
    assert "no tree field" in described

def _patch_child_probe(monkeypatch, *, children, windows_of, alive=lambda pid: True):  # type: ignore[no-untyped-def]
    """Point the ui.process_tree child helper at fake process/window data."""
    from headless_re_mcp.core import service_ui

    def fake_enumerate(parent_pid, *, max_pids):  # type: ignore[no-untyped-def]
        return list(children)[:max_pids]

    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.enumerate_direct_children", fake_enumerate
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.process_image_path",
        lambda pid: f"img-{pid}",
    )
    monkeypatch.setattr(
        service_ui, "list_windows_for_pids", lambda pids: list(windows_of(pids[0]))
    )
    monkeypatch.setattr(service_ui, "is_pid_alive", alive)


def test_process_tree_child_list_says_when_it_is_a_bounded_page(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A debuggee with more children than the cap must not read as exactly the cap.

    ui.process_tree caps the child list so a Chromium-style tree cannot balloon
    the reply, but the old code took the default cap and returned a bare list:
    17 direct children came back as 16 with nothing to say one was dropped, and
    a caller hunting the child that owns the real window never learned it fell
    off the end. The helper now enumerates one past the cap and reports the
    truncation.
    """
    from headless_re_mcp.core.service_ui import (
        _UI_CHILD_ROW_LIMIT,
        _ui_child_process_rows,
    )

    over = list(range(1000, 1000 + _UI_CHILD_ROW_LIMIT + 1))
    _patch_child_probe(monkeypatch, children=over, windows_of=lambda pid: [])
    rows, truncated = _ui_child_process_rows(4242)

    assert len(rows) == _UI_CHILD_ROW_LIMIT, "the page is still capped"
    assert truncated is True, "but the reply admits there are more children"

    # Exactly at the cap is not truncation.
    exact = list(range(2000, 2000 + _UI_CHILD_ROW_LIMIT))
    _patch_child_probe(monkeypatch, children=exact, windows_of=lambda pid: [])
    rows, truncated = _ui_child_process_rows(4242)
    assert len(rows) == _UI_CHILD_ROW_LIMIT
    assert truncated is False


def test_process_tree_child_window_list_carries_its_true_total(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Each child's window page reports its real count, not just the slice.

    A child owning more top-level windows than the per-row cap used to show the
    capped slice with no signal, so the window the caller wanted could be hidden
    behind the cap while the row looked complete.
    """
    from headless_re_mcp.core.service_ui import (
        _UI_CHILD_WINDOW_LIMIT,
        _ui_child_process_rows,
    )

    many = _UI_CHILD_WINDOW_LIMIT + 5

    def windows_of(pid: int) -> list[dict[str, int]]:
        # pid 900 owns many windows; pid 901 owns two.
        return [{"hwnd": i} for i in range(many if pid == 900 else 2)]

    _patch_child_probe(monkeypatch, children=[900, 901], windows_of=windows_of)
    rows, truncated = _ui_child_process_rows(4242)

    assert truncated is False, "two children is under the child cap"
    busy = next(r for r in rows if r["pid"] == 900)
    assert len(busy["top_level_windows"]) == _UI_CHILD_WINDOW_LIMIT
    assert busy["top_level_windows_total"] == many
    assert busy["top_level_windows_truncated"] is True

    quiet = next(r for r in rows if r["pid"] == 901)
    assert len(quiet["top_level_windows"]) == 2
    assert quiet["top_level_windows_total"] == 2
    assert quiet["top_level_windows_truncated"] is False
    assert quiet["image"] == "img-901"
    assert quiet["alive"] is True


def test_ui_process_tree_puts_windows_in_debuggee_windows_not_tree() -> None:
    """The catalog said process-tree and never named the payload.

    Measured against the service action: windows are debuggee_windows, child
    processes are children, plus child_candidates and note. There is no tree
    or processes field. Looking for tree after a successful probe reads as
    the debuggee having no windows, so the agent never passes allow_child_pids.
    """
    source = Path(_ui_finalize_windows.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def ui_process_tree")
    chunk = source[start : source.index("def ui_tree", start)]
    returned = chunk[chunk.index("return {") :]
    assert '"debuggee_windows"' in returned
    assert '"children"' in returned
    assert '"child_candidates"' in returned
    assert '"tree"' not in returned
    assert '"processes"' not in returned
    described = _tool_docstring("ui.process_tree")
    assert "Answers with debuggee_windows" in described
    assert "children" in described
    assert "no tree field" in described
    assert "no processes field" in described

def test_ui_resolve_nests_hwnd_under_window() -> None:
    """The catalog said resolve a window and never named the payload.

    Measured against the service action: the match is window (hwnd, pid,
    class_name, title), plus debuggee_pid, debugger_pid and backend. There is
    no top-level hwnd field. Looking for hwnd after a successful resolve
    reads as no match, so the agent retries or clicks a stale handle.
    """
    source = Path(_ui_finalize_windows.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def ui_resolve")
    chunk = source[start : source.index("def ui_click", start)]
    returned = chunk[chunk.index("return {") :]
    assert '"window": window' in returned
    assert '"hwnd"' not in returned
    described = _tool_docstring("ui.resolve")
    assert "Answers with window" in described
    assert "no hwnd field" in described

def test_ui_click_names_action_not_clicked() -> None:
    """The catalog said click and never named the payload.

    Measured against click_hwnd: success is hwnd, action, backend,
    foreground_required and injection_required. There is no clicked field.
    Looking for clicked after a successful click reads as the click not
    happening, so the agent retries and double-fires the control.
    """
    from headless_re_mcp.core.ui_win32 import click_hwnd

    source = Path(click_hwnd.__code__.co_filename).read_text(encoding="utf-8")
    start = source.index("def click_hwnd(")
    chunk = source[start : source.index("def click_hwnd_at")]
    returned = chunk[chunk.rindex("return {") :]
    assert '"action": "click"' in returned
    assert '"hwnd"' in returned
    assert '"clicked"' not in returned
    described = _tool_docstring("ui.click")
    assert "Answers with hwnd" in described
    assert "action" in described
    assert "no clicked field" in described
