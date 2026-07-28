from __future__ import annotations

from pathlib import Path

import pytest

from headless_re_mcp.core.ui_win32 import (
    _INVOKE_WHITELIST,
    BM_CLICK,
    WM_COMMAND,
    capture_hwnd_screenshot,
    close_hwnd,
)
from headless_re_mcp.core.windows import UiPidBoundaryError


def test_invoke_whitelist_is_indexable_dict() -> None:
    assert isinstance(_INVOKE_WHITELIST, dict)
    assert _INVOKE_WHITELIST["click"] == BM_CLICK
    assert _INVOKE_WHITELIST["command"] == WM_COMMAND
    assert "close" in _INVOKE_WHITELIST
    assert "bogus" not in _INVOKE_WHITELIST


def test_close_hwnd_rejects_disallowed_pid() -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        close_hwnd(1, frozenset({999999}))
    assert exc.value.code in {"not_found", "permission_denied", "invalid_params"}


def test_ui_pid_boundary_error_rejects_message_kw_collision() -> None:
    # details must not use the reserved constructor kw "message"
    with pytest.raises(TypeError):
        UiPidBoundaryError("timeout", "failed", message=0xF5)  # type: ignore[misc]

    err = UiPidBoundaryError("timeout", "failed", win32_message=0xF5, hwnd=1)
    assert err.message == "failed"
    assert err.details["win32_message"] == 0xF5


def test_screenshot_rejects_disallowed_hwnd(tmp_path: Path) -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        capture_hwnd_screenshot(0, frozenset({1}), tmp_path / "x.bmp")
    assert exc.value.code in {"invalid_params", "not_found", "permission_denied"}


def test_screenshot_rejects_non_bmp_extension(tmp_path: Path) -> None:
    with pytest.raises(UiPidBoundaryError) as exc:
        capture_hwnd_screenshot(1, frozenset({1}), tmp_path / "x.png")
    assert exc.value.code == "invalid_params"
    assert "bmp" in exc.value.message.casefold()
