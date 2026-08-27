"""Coverage for the optional UI Automation backend on a non-Windows host.

The ``uiautomation`` package is Windows-only, so these tests fake ``os.name``
as ``"nt"`` and install a fake module in ``sys.modules`` whose controls expose
the same pattern surface (Invoke/Value/Click, children, bounding rectangles).
"""

from __future__ import annotations

import os
import sys
import types
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_uia as uia
from headless_re_mcp.core.ui_uia import (
    _describe_control,
    _require_uia,
    build_uia_tree,
    click_hwnd_uia,
    set_value_uia,
    uia_available,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_ALLOWED = frozenset({7})


class _FakeControl:
    def __init__(
        self,
        *,
        pid: int = 7,
        name: str = "btn",
        children: list[_FakeControl] | None = None,
        children_raise: bool = False,
        invoke_pattern: Any = "working",
        invoke_raises: bool = False,
        click_raises: bool = False,
        value_patterns: list[Any] | None = None,
        value_raises: bool = False,
        bounding: Any = None,
        native: Any = 100,
    ) -> None:
        self.ProcessId = pid
        self.Name = name
        self.AutomationId = "aid"
        self.ClassName = "cls"
        self.ControlTypeName = "Button"
        self.NativeWindowHandle = native
        self.BoundingRectangle = (
            bounding if bounding is not None else SimpleNamespace(left=0, top=0, right=2, bottom=2)
        )
        self._children = children or []
        self._children_raise = children_raise
        self._invoke_pattern = invoke_pattern
        self._invoke_raises = invoke_raises
        self._click_raises = click_raises
        self._value_patterns = value_patterns
        self._value_raises = value_raises
        self.invoked: list[str] = []

    def GetChildren(self) -> list[_FakeControl]:
        if self._children_raise:
            raise RuntimeError("children unavailable")
        return self._children

    def GetInvokePattern(self) -> Any:
        if self._invoke_raises:
            raise RuntimeError("no invoke pattern")
        if self._invoke_pattern == "working":
            return SimpleNamespace(Invoke=lambda: self.invoked.append("invoke"))
        return self._invoke_pattern

    def Click(self, simulateMove: bool = False) -> None:
        if self._click_raises:
            raise RuntimeError("click failed")
        self.invoked.append("click")

    def GetValuePattern(self) -> Any:
        if self._value_raises:
            raise RuntimeError("no value pattern")
        if self._value_patterns is not None:
            return self._value_patterns.pop(0)
        return SimpleNamespace(SetValue=lambda text: self.invoked.append("set"))


def _install(monkeypatch: pytest.MonkeyPatch, control: _FakeControl | None) -> None:
    monkeypatch.setattr(os, "name", "nt")
    fake = types.ModuleType("uiautomation")
    fake.ControlFromHandle = lambda hwnd: control  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "uiautomation", fake)
    monkeypatch.setattr(uia, "require_allowed_hwnd", lambda hwnd, allowed: None)


# --------------------------------------------------------------------------
# availability / binding
# --------------------------------------------------------------------------


def test_uia_available_is_false_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "posix")
    assert uia_available() is False


def test_uia_available_is_false_without_the_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.delitem(sys.modules, "uiautomation", raising=False)
    assert uia_available() is False


def test_uia_available_is_true_with_the_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeControl())
    assert uia_available() is True


def test_require_uia_is_unsupported_off_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(os, "name", "posix")
    with pytest.raises(UiPidBoundaryError) as info:
        _require_uia()
    assert info.value.code == "unsupported_on_platform"


def test_control_binding_requires_a_resolvable_hwnd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, None)
    with pytest.raises(UiPidBoundaryError) as info:
        click_hwnd_uia(5, _ALLOWED)
    assert info.value.code == "not_found"


def test_control_binding_rejects_a_foreign_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _FakeControl(pid=999))
    with pytest.raises(UiPidBoundaryError) as info:
        click_hwnd_uia(5, _ALLOWED)
    assert info.value.code == "permission_denied"
    assert info.value.details["process_id"] == 999


# --------------------------------------------------------------------------
# _describe_control
# --------------------------------------------------------------------------


def test_describe_control_reads_the_full_shape() -> None:
    ctrl = _FakeControl(bounding=SimpleNamespace(left=1, top=2, right=3, bottom=4), native=42)
    described = _describe_control(ctrl)
    assert described["rect"] == {"left": 1, "top": 2, "right": 3, "bottom": 4}
    assert described["hwnd"] == 42
    assert described["name"] == "btn"
    assert described["control_type"] == "Button"


def test_describe_control_swallows_broken_properties() -> None:
    ctrl = _FakeControl(bounding=object(), native=object())
    described = _describe_control(ctrl)
    assert described["rect"] is None
    assert described["hwnd"] == 0


# --------------------------------------------------------------------------
# build_uia_tree
# --------------------------------------------------------------------------


def test_tree_rejects_a_bad_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeControl())
    with pytest.raises(UiPidBoundaryError, match="max_depth"):
        build_uia_tree(5, _ALLOWED, max_depth=9)


def test_tree_rejects_a_bad_node_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeControl())
    with pytest.raises(UiPidBoundaryError, match="max_nodes"):
        build_uia_tree(5, _ALLOWED, max_nodes=0)


def test_tree_walks_children_and_skips_foreign_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = _FakeControl(pid=999, name="foreign")
    child = _FakeControl(name="child")
    root = _FakeControl(name="root", children=[foreign, child])
    _install(monkeypatch, root)
    tree = build_uia_tree(5, _ALLOWED, max_depth=3)
    assert tree["count"] == 2
    assert tree["truncated"] is False
    names = [node["name"] for node in tree["nodes"][0]["children"]]
    assert names == ["child"]


def test_tree_stops_descending_at_max_depth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grandchild = _FakeControl(name="grandchild")
    child = _FakeControl(name="child", children=[grandchild])
    root = _FakeControl(name="root", children=[child])
    _install(monkeypatch, root)
    tree = build_uia_tree(5, _ALLOWED, max_depth=1)
    assert tree["count"] == 2
    assert tree["nodes"][0]["children"][0]["children"] == []


def test_tree_truncates_at_the_node_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    children = [_FakeControl(name=f"c{i}") for i in range(3)]
    root = _FakeControl(name="root", children=children)
    _install(monkeypatch, root)
    tree = build_uia_tree(5, _ALLOWED, max_nodes=2)
    assert tree["count"] == 2
    assert tree["truncated"] is True


def test_tree_tolerates_a_failing_child_enumeration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _FakeControl(name="root", children_raise=True)
    _install(monkeypatch, root)
    tree = build_uia_tree(5, _ALLOWED)
    assert tree["count"] == 1
    assert tree["nodes"][0]["children"] == []


# --------------------------------------------------------------------------
# click_hwnd_uia
# --------------------------------------------------------------------------


def test_click_prefers_the_invoke_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    ctrl = _FakeControl()
    _install(monkeypatch, ctrl)
    result = click_hwnd_uia(5, _ALLOWED)
    assert result["backend"] == "uia_invoke"
    assert ctrl.invoked == ["invoke"]


def test_click_falls_back_when_invoke_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrl = _FakeControl(invoke_raises=True)
    _install(monkeypatch, ctrl)
    result = click_hwnd_uia(5, _ALLOWED)
    assert result["backend"] == "uia_click"
    assert ctrl.invoked == ["click"]


def test_click_falls_back_when_no_invoke_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ctrl = _FakeControl(invoke_pattern=None)
    _install(monkeypatch, ctrl)
    result = click_hwnd_uia(5, _ALLOWED)
    assert result["backend"] == "uia_click"


def test_click_maps_a_total_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    ctrl = _FakeControl(invoke_pattern=None, click_raises=True)
    _install(monkeypatch, ctrl)
    with pytest.raises(UiPidBoundaryError) as info:
        click_hwnd_uia(5, _ALLOWED)
    assert info.value.code == "backend_error"


# --------------------------------------------------------------------------
# set_value_uia
# --------------------------------------------------------------------------


def test_set_value_requires_a_string(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeControl())
    with pytest.raises(UiPidBoundaryError, match="must be a string"):
        set_value_uia(5, 12, _ALLOWED)  # type: ignore[arg-type]


def test_set_value_bounds_the_text(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeControl())
    with pytest.raises(UiPidBoundaryError, match="4096"):
        set_value_uia(5, "x" * 4097, _ALLOWED)


def test_set_value_uses_the_value_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    ctrl = _FakeControl()
    _install(monkeypatch, ctrl)
    result = set_value_uia(5, "hello", _ALLOWED)
    assert result["backend"] == "uia_value"
    assert ctrl.invoked == ["set"]


def test_set_value_retries_when_the_first_pattern_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[str] = []
    second = SimpleNamespace(SetValue=lambda text: written.append(text))
    ctrl = _FakeControl(value_patterns=[None, second])
    _install(monkeypatch, ctrl)
    result = set_value_uia(5, "again", _ALLOWED)
    assert result["action"] == "text.set"
    assert written == ["again"]


def test_set_value_maps_a_total_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    ctrl = _FakeControl(value_raises=True)
    _install(monkeypatch, ctrl)
    with pytest.raises(UiPidBoundaryError) as info:
        set_value_uia(5, "nope", _ALLOWED)
    assert info.value.code == "backend_error"
