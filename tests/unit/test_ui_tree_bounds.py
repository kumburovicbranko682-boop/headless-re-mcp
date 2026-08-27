"""The advertised UI tree node budget must bound Win32 enumeration work."""

from __future__ import annotations

from typing import Any

from headless_re_mcp.core import ui_win32


def test_tree_node_budget_stops_native_enumeration(
    monkeypatch: Any,
) -> None:
    """Returning three nodes must not first materialize fifty thousand.

    ``EnumChildWindows`` calls the callback for every descendant until it
    returns false.  The tree used to collect all 50,000 fake descendants and
    only then notice ``max_nodes=3`` while assembling the response.  That made
    the published node bound a result-size hint rather than a work bound.

    The depth-cut honesty probe adds at most one ``max_callbacks=1`` existence
    check per returned node that stops at the depth bound (so it can report
    ``children_truncated`` instead of posing as a leaf); that stays a small
    multiple of ``max_nodes`` and nowhere near the 50,000 descendants.
    """
    max_nodes = 3

    class FakeUser32:
        def __init__(self) -> None:
            self.callback_count = 0

        def EnumChildWindows(self, _parent: int, callback: Any, _data: int) -> None:
            for hwnd in range(10_000, 60_000):
                self.callback_count += 1
                if not callback(hwnd, 0):
                    break

    fake = FakeUser32()
    monkeypatch.setattr(ui_win32, "_user32", lambda: fake)
    monkeypatch.setattr(ui_win32, "require_allowed_hwnd", lambda *_args: 1)
    monkeypatch.setattr(ui_win32, "hwnd_owner_pid", lambda _hwnd: 1)
    monkeypatch.setattr(
        ui_win32,
        "describe_hwnd",
        lambda hwnd: {"hwnd": int(hwnd), "pid": 1},
    )

    result = ui_win32.build_window_tree(
        [{"hwnd": 1, "pid": 1}],
        frozenset({1}),
        max_depth=1,
        max_nodes=max_nodes,
    )

    assert result["count"] == max_nodes
    assert result["truncated"] is True
    assert fake.callback_count <= 2 * max_nodes, (
        f"max_nodes={max_nodes} returned {result['count']} nodes but "
        f"enumerated {fake.callback_count} descendants"
    )
