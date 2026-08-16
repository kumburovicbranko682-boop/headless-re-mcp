from __future__ import annotations

import inspect

from headless_re_mcp.core.service import AnalysisService
from headless_re_mcp.core.service_ui import _ui_finalize_windows


def test_dynamic_attach_defaults_pause_after_attach_false() -> None:
    sig = inspect.signature(AnalysisService.dynamic_attach)
    assert sig.parameters["pause_after_attach"].default is False


def test_ui_finalize_windows_empty_hints_children(monkeypatch) -> None:
    monkeypatch.setattr(
        "headless_re_mcp.core.service_ui.is_pid_alive",
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


def test_an_empty_window_list_on_a_hidden_desktop_says_why() -> None:
    """"No windows" and "not on this desktop" are different answers.

    ui.windows.list enumerates the desktop the service runs on. Under
    hidden_desktop the debuggee's windows live on a separate Win32 desktop
    object, so the list comes back empty -- and an unattended caller reading
    count=0 concludes the sample has no user interface and stops looking.
    hidden_desktop is the setting an unattended deployment is most likely to
    have on, so this is the configuration where the answer misleads.
    """
    from headless_re_mcp.core.service_ui import _ui_finalize_windows

    ctx = {"allowed": frozenset({4242}), "debuggee_pid": 0, "debugger_pid": 1}

    on_visible_desktop = _ui_finalize_windows({"windows": []}, ctx, hidden_desktop=False)
    assert "hint" not in on_visible_desktop, "an ordinary empty list needs no excuse"

    on_hidden_desktop = _ui_finalize_windows({"windows": []}, ctx, hidden_desktop=True)
    assert on_hidden_desktop["hint"] == "windows_on_hidden_desktop"
    assert "ui.virtual_desktop.snapshot" in on_hidden_desktop["suggestion"]

    found = _ui_finalize_windows(
        {"windows": [{"pid": 4242, "hwnd": 7, "title": "x"}]}, ctx, hidden_desktop=True
    )
    assert found["count"] == 1
    assert "hint" not in found, "the hint is for the empty case only"


class TestUiProcessTreeSaysWhenWindowsStopped:
    """Child window lists were sliced at 16 and said nothing.

    Measured: 40 windows came back as 16 with no has_more, so a caller
    would treat a page as every top-level window on that child.
    """

    def test_hitting_the_cap_is_reported(self) -> None:
        from headless_re_mcp.core.service_ui import _page_windows

        page, has_more = _page_windows([{"hwnd": index} for index in range(40)])
        assert len(page) == 16
        assert has_more is True

    def test_a_complete_answer_is_not_labelled_partial(self) -> None:
        from headless_re_mcp.core.service_ui import _page_windows

        page, has_more = _page_windows([{"hwnd": 1}, {"hwnd": 2}])
        assert len(page) == 2
        assert has_more is False

    def test_the_debuggee_list_cap_is_reported(self) -> None:
        from headless_re_mcp.core.service_ui import _MAX_WINDOWS_LIST, _page_windows

        page, has_more = _page_windows(
            [{"hwnd": index} for index in range(500)],
            limit=_MAX_WINDOWS_LIST,
        )
        assert len(page) == 256
        assert has_more is True


class TestUiWindowsListIsCapped:
    """The debuggee window list had no page and no signal that it had stopped.

    Measured: 500 windows came back in one reply, with no has_more.
    """

    def test_hitting_the_cap_is_reported(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from headless_re_mcp.core.service_ui import _windows_list_payload

        monkeypatch.setattr(
            "headless_re_mcp.core.service_ui.list_windows_for_pids",
            lambda pids: [{"pid": 1, "hwnd": index} for index in range(500)],
        )
        page = _windows_list_payload(
            {
                "debuggee_pid": 1,
                "debugger_pid": 2,
                "allowed": frozenset({1}),
                "blocked": frozenset(),
            }
        )
        assert len(page["windows"]) == 256
        assert page["has_more"] is True

    def test_a_complete_answer_is_not_labelled_partial(self, monkeypatch) -> None:  # type: ignore[no-untyped-def]
        from headless_re_mcp.core.service_ui import _windows_list_payload

        monkeypatch.setattr(
            "headless_re_mcp.core.service_ui.list_windows_for_pids",
            lambda pids: [{"pid": 1, "hwnd": 7}],
        )
        page = _windows_list_payload(
            {
                "debuggee_pid": 1,
                "debugger_pid": 2,
                "allowed": frozenset({1}),
                "blocked": frozenset(),
            }
        )
        assert page["has_more"] is False