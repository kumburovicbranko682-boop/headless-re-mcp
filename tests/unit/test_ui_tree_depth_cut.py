"""A node stopped at max_depth must not pose as a childless leaf.

Both ui.tree backends returned ``children: []`` for a node cut off at the
depth bound and left the top-level ``truncated`` false for a depth-only cut.
A caller walking the tree to find a control read that empty list as "this
window has no children" and gave up, when the target lived one level below
the cut. The fix tags such a node with ``children_truncated`` and flips the
top-level ``truncated`` flag.
"""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core import ui_uia, ui_win32


def _win32_child_lister(children_map: dict[int, list[dict[str, Any]]]) -> Any:
    def list_child_windows(
        parent_hwnd: int,
        _allowed_pids: frozenset[int],
        *,
        max_callbacks: int | None = None,
    ) -> list[dict[str, Any]]:
        kids = children_map.get(int(parent_hwnd), [])
        return kids if max_callbacks is None else kids[:max_callbacks]

    return list_child_windows


def test_win32_depth_cut_flags_a_node_that_still_has_children(monkeypatch: Any) -> None:
    """hwnd 2 sits at the depth bound but owns hwnd 3 below it."""
    children_map = {
        1: [{"hwnd": 2, "pid": 1}],
        2: [{"hwnd": 3, "pid": 1}],
        3: [],
    }
    monkeypatch.setattr(ui_win32, "list_child_windows", _win32_child_lister(children_map))

    result = ui_win32.build_window_tree(
        [{"hwnd": 1, "pid": 1}],
        frozenset({1}),
        max_depth=1,
        max_nodes=256,
    )

    child = result["nodes"][0]["children"][0]
    assert child["hwnd"] == 2
    assert child["children"] == []
    assert child["children_truncated"] is True
    assert result["truncated"] is True


def test_win32_depth_cut_leaves_a_real_leaf_unflagged(monkeypatch: Any) -> None:
    """hwnd 2 is at the depth bound and genuinely has no children."""
    children_map = {
        1: [{"hwnd": 2, "pid": 1}],
        2: [],
    }
    monkeypatch.setattr(ui_win32, "list_child_windows", _win32_child_lister(children_map))

    result = ui_win32.build_window_tree(
        [{"hwnd": 1, "pid": 1}],
        frozenset({1}),
        max_depth=1,
        max_nodes=256,
    )

    child = result["nodes"][0]["children"][0]
    assert child["hwnd"] == 2
    assert child["children"] == []
    assert "children_truncated" not in child
    assert result["truncated"] is False


class _FakeControl:
    def __init__(self, pid: int, name: str, children: list[_FakeControl]) -> None:
        self.ProcessId = pid
        self.name = name
        self._children = children

    def GetChildren(self) -> list[_FakeControl]:
        return list(self._children)


def _patch_uia(monkeypatch: Any, root: _FakeControl) -> None:
    monkeypatch.setattr(ui_uia, "_control_from_hwnd", lambda _hwnd, _allowed: root)
    monkeypatch.setattr(
        ui_uia,
        "_describe_control",
        lambda ctrl: {"name": ctrl.name, "process_id": ctrl.ProcessId},
    )


def test_uia_depth_cut_flags_a_node_that_still_has_children(monkeypatch: Any) -> None:
    grand = _FakeControl(1, "grand", [])
    child = _FakeControl(1, "child", [grand])
    root = _FakeControl(1, "root", [child])
    _patch_uia(monkeypatch, root)

    result = ui_uia.build_uia_tree(0, frozenset({1}), max_depth=1, max_nodes=256)

    child_node = result["nodes"][0]["children"][0]
    assert child_node["name"] == "child"
    assert child_node["children"] == []
    assert child_node["children_truncated"] is True
    assert result["truncated"] is True


def test_uia_depth_cut_ignores_children_outside_the_pid_scope(monkeypatch: Any) -> None:
    """An out-of-scope child would not have been shown, so it is not hidden."""
    outsider = _FakeControl(999, "outsider", [])
    child = _FakeControl(1, "child", [outsider])
    root = _FakeControl(1, "root", [child])
    _patch_uia(monkeypatch, root)

    result = ui_uia.build_uia_tree(0, frozenset({1}), max_depth=1, max_nodes=256)

    child_node = result["nodes"][0]["children"][0]
    assert child_node["children"] == []
    assert "children_truncated" not in child_node
    assert result["truncated"] is False
