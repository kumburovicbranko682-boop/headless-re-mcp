from __future__ import annotations

import inspect

from headless_re_mcp.core.service import AnalysisService, _ui_finalize_windows


def test_dynamic_attach_defaults_pause_after_attach_false() -> None:
    sig = inspect.signature(AnalysisService.dynamic_attach)
    assert sig.parameters["pause_after_attach"].default is False


def test_ui_finalize_windows_empty_hints_children(monkeypatch) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service.is_pid_alive",
        lambda pid: True,
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.probe_child_window_candidates",
        lambda pid, list_windows_fn=None: [
            {"pid": 99, "image": "x", "window_count": 1, "visible_count": 1, "titles": ["T"], "same_image": True}
        ],
    )
    out = _ui_finalize_windows(
        {"windows": []},
        {"allowed": frozenset({1}), "debuggee_pid": 1, "debugger_pid": 2},
    )
    assert out["hint"] == "windows_on_child_pids"
    assert out["suggested_child_pids"] == [99]


def test_ui_process_tree_method_exists() -> None:
    assert hasattr(AnalysisService, "ui_process_tree")
