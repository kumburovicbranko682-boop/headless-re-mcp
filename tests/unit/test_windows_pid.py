from __future__ import annotations

import pytest

from headless_re_mcp.core.windows import (
    UiPidBoundaryError,
    resolve_allowed_ui_pids,
)


def test_resolve_allowed_ui_pids_defaults_to_debuggee_only() -> None:
    allowed, blocked = resolve_allowed_ui_pids(
        debuggee_pid=7100,
        debugger_pid=7000,
        self_pid=42,
    )
    assert allowed == frozenset({7100})
    assert blocked == frozenset({7000, 42})


def test_resolve_allowed_ui_pids_requires_active_debuggee() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        resolve_allowed_ui_pids(debuggee_pid=0, debugger_pid=7000, self_pid=42)
    assert exc.value.code == "invalid_state"


def test_resolve_allowed_ui_pids_blocks_debugger_as_child() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        resolve_allowed_ui_pids(
            debuggee_pid=7100,
            debugger_pid=7000,
            allow_child_pids=[7000],
            self_pid=42,
        )
    assert exc.value.code == "permission_denied"


def test_resolve_allowed_ui_pids_blocks_host_as_child() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        resolve_allowed_ui_pids(
            debuggee_pid=7100,
            debugger_pid=7000,
            allow_child_pids=[42],
            self_pid=42,
        )
    assert exc.value.code == "permission_denied"


def test_resolve_allowed_ui_pids_allows_explicit_child() -> None:
    allowed, blocked = resolve_allowed_ui_pids(
        debuggee_pid=7100,
        debugger_pid=7000,
        allow_child_pids=[7201],
        self_pid=42,
    )
    assert allowed == frozenset({7100, 7201})
    assert 7000 in blocked
    assert 42 in blocked


def test_resolve_allowed_ui_pids_same_image_opt_in(monkeypatch) -> None:
    import headless_re_mcp.core.windows as windows

    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.enumerate_direct_children",
        lambda parent: [7201, 7202],
    )
    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.filter_same_image_pids",
        lambda debuggee, candidates: [7201],
    )
    allowed, blocked = windows.resolve_allowed_ui_pids(
        debuggee_pid=7100,
        debugger_pid=7000,
        include_same_image_children=True,
        self_pid=42,
    )
    assert allowed == frozenset({7100, 7201})
    assert 7000 in blocked


def test_resolve_allowed_ui_pids_same_image_off_by_default(monkeypatch) -> None:
    import headless_re_mcp.core.windows as windows

    called = {"n": 0}

    def boom(*_a, **_k):
        called["n"] += 1
        return [7201]

    monkeypatch.setattr(
        "headless_re_mcp.core.process_tree.enumerate_direct_children",
        boom,
    )
    allowed, _blocked = windows.resolve_allowed_ui_pids(
        debuggee_pid=7100,
        debugger_pid=7000,
        self_pid=42,
    )
    assert allowed == frozenset({7100})
    assert called["n"] == 0
