"""UI Automation backend, driven on a faked uiautomation surface.

``ui_uia`` binds a debuggee window through UI Automation and walks/clicks/sets
it, all behind the same PID boundary the rest of the UI surface enforces. It
needs the Windows-only ``uiautomation`` COM package, so on a hosted platform
every path past the import guard was dark (10%). Faking ``_require_uia`` (the
COM entry point) and ``require_allowed_hwnd`` (the boundary check), plus control
objects that answer the UIA methods, drives the real bind/describe/tree/click/
set-value logic across success and every fallback: a control bound outside the
allowed PIDs, a tree that truncates, an InvokePattern that is missing, and a
ValuePattern whose first probe fails but whose retry lands.
"""

from __future__ import annotations

import os
import sys
import types
from types import SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_uia as ui_uia
from headless_re_mcp.core.ui_uia import (
    _describe_control,
    build_uia_tree,
    click_hwnd_uia,
    set_value_uia,
    uia_available,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

_PIDS = frozenset({100})


class _FakeControl:
    """A UIA control whose method behaviours are scripted per test."""

    def __init__(
        self,
        *,
        process_id: int = 100,
        name: str = "btn",
        native: Any = 0x10,
        rect: Any = (1, 2, 3, 4),
        children: list[_FakeControl] | None = None,
        children_raises: bool = False,
        invoke: str = "ok",  # ok | none | raise
        click_raises: bool = False,
        value: Any = "ok",  # ok | none | raise | list of behaviours
    ) -> None:
        self.ProcessId = process_id
        self.Name = name
        self.AutomationId = "auto-id"
        self.ClassName = "Button"
        self.ControlTypeName = "ButtonControl"
        self._native = native
        self._rect = rect
        self._children = children or []
        self._children_raises = children_raises
        self._invoke = invoke
        self._click_raises = click_raises
        self._value_seq = list(value) if isinstance(value, list) else [value]
        self._value_idx = 0
        self.set_values: list[str] = []
        self.clicked = False

    @property
    def NativeWindowHandle(self) -> int:
        if self._native == "raise":
            raise RuntimeError("no native handle")
        return int(self._native)

    @property
    def BoundingRectangle(self) -> Any:
        if self._rect == "raise":
            raise RuntimeError("no rect")
        left, top, right, bottom = self._rect
        return SimpleNamespace(left=left, top=top, right=right, bottom=bottom)

    def GetChildren(self) -> list[_FakeControl]:
        if self._children_raises:
            raise RuntimeError("children unavailable")
        return self._children

    def GetInvokePattern(self) -> Any:
        if self._invoke == "raise":
            raise RuntimeError("no invoke pattern")
        if self._invoke == "none":
            return None
        return SimpleNamespace(Invoke=self._do_invoke)

    def _do_invoke(self) -> None:
        self.invoked = True

    def Click(self, simulateMove: bool = False) -> None:
        del simulateMove
        if self._click_raises:
            raise RuntimeError("click failed")
        self.clicked = True

    def GetValuePattern(self) -> Any:
        behaviour = (
            self._value_seq[self._value_idx]
            if self._value_idx < len(self._value_seq)
            else self._value_seq[-1]
        )
        self._value_idx += 1
        if behaviour == "raise":
            raise RuntimeError("no value pattern")
        if behaviour == "none":
            return None
        return SimpleNamespace(SetValue=self.set_values.append)


def _bind(monkeypatch: pytest.MonkeyPatch, control: _FakeControl | None) -> None:
    """Route _control_from_hwnd to `control`, bypassing COM and the real boundary."""
    monkeypatch.setattr(ui_uia, "require_allowed_hwnd", lambda *a, **k: None)
    monkeypatch.setattr(
        ui_uia, "_require_uia", lambda: SimpleNamespace(ControlFromHandle=lambda _hwnd: control)
    )


# ---------------------------------------------------------------------------
# uia_available / _require_uia


def test_uia_available_is_false_off_windows() -> None:
    assert uia_available() is False


def test_uia_available_true_when_the_package_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setitem(sys.modules, "uiautomation", types.ModuleType("uiautomation"))
    assert uia_available() is True


def test_uia_available_false_when_the_package_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    monkeypatch.setitem(sys.modules, "uiautomation", None)  # import raises
    assert uia_available() is False


def test_require_uia_refuses_off_windows() -> None:
    with pytest.raises(UiPidBoundaryError, match="requires Windows"):
        ui_uia._require_uia()


def test_require_uia_returns_the_module_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "name", "nt")
    fake = types.ModuleType("uiautomation")
    monkeypatch.setitem(sys.modules, "uiautomation", fake)
    assert ui_uia._require_uia() is fake


# ---------------------------------------------------------------------------
# _control_from_hwnd


def test_control_from_hwnd_binds_a_matching_process(monkeypatch: pytest.MonkeyPatch) -> None:
    ctrl = _FakeControl(process_id=100)
    _bind(monkeypatch, ctrl)
    assert ui_uia._control_from_hwnd(0x10, _PIDS) is ctrl


def test_control_from_hwnd_rejects_a_null_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    _bind(monkeypatch, None)
    with pytest.raises(UiPidBoundaryError, match="could not bind hwnd"):
        ui_uia._control_from_hwnd(0x10, _PIDS)


def test_control_from_hwnd_rejects_a_foreign_process(monkeypatch: pytest.MonkeyPatch) -> None:
    _bind(monkeypatch, _FakeControl(process_id=999))
    with pytest.raises(UiPidBoundaryError, match="outside allowed PIDs"):
        ui_uia._control_from_hwnd(0x10, _PIDS)


# ---------------------------------------------------------------------------
# _describe_control


def test_describe_control_reads_rect_and_handle() -> None:
    described = _describe_control(_FakeControl(native=0x55, rect=(1, 2, 3, 4)))
    assert described["hwnd"] == 0x55
    assert described["rect"] == {"left": 1, "top": 2, "right": 3, "bottom": 4}
    assert described["control_type"] == "ButtonControl"


def test_describe_control_tolerates_missing_rect_and_handle() -> None:
    described = _describe_control(_FakeControl(native="raise", rect="raise"))
    assert described["rect"] is None
    assert described["hwnd"] == 0


# ---------------------------------------------------------------------------
# build_uia_tree


def test_build_tree_rejects_bad_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    _bind(monkeypatch, _FakeControl())
    with pytest.raises(UiPidBoundaryError, match="max_depth"):
        build_uia_tree(0x10, _PIDS, max_depth=99)


def test_build_tree_rejects_bad_node_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    _bind(monkeypatch, _FakeControl())
    with pytest.raises(UiPidBoundaryError, match="max_nodes"):
        build_uia_tree(0x10, _PIDS, max_nodes=0)


def test_build_tree_walks_children(monkeypatch: pytest.MonkeyPatch) -> None:
    child = _FakeControl(process_id=100, name="child")
    root = _FakeControl(process_id=100, name="root", children=[child])
    _bind(monkeypatch, root)
    tree = build_uia_tree(0x10, _PIDS, max_depth=3, max_nodes=256)
    assert tree["count"] == 2
    assert tree["truncated"] is False
    assert tree["nodes"][0]["name"] == "root"
    assert tree["nodes"][0]["children"][0]["name"] == "child"


def test_build_tree_stops_at_max_depth(monkeypatch: pytest.MonkeyPatch) -> None:
    child = _FakeControl(process_id=100)
    root = _FakeControl(process_id=100, children=[child])
    _bind(monkeypatch, root)
    tree = build_uia_tree(0x10, _PIDS, max_depth=0)
    assert tree["count"] == 1  # root only; depth budget stops the descent
    assert tree["nodes"][0]["children"] == []


def test_build_tree_truncates_at_the_node_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    root = _FakeControl(process_id=100, children=[_FakeControl(), _FakeControl()])
    _bind(monkeypatch, root)
    tree = build_uia_tree(0x10, _PIDS, max_depth=3, max_nodes=1)
    assert tree["count"] == 1
    assert tree["truncated"] is True


def test_build_tree_skips_a_foreign_child(monkeypatch: pytest.MonkeyPatch) -> None:
    foreign = _FakeControl(process_id=999, name="foreign")
    root = _FakeControl(process_id=100, children=[foreign])
    _bind(monkeypatch, root)
    tree = build_uia_tree(0x10, _PIDS, max_depth=3)
    assert tree["count"] == 1
    assert tree["nodes"][0]["children"] == []  # foreign child dropped


def test_build_tree_tolerates_a_children_read_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    root = _FakeControl(process_id=100, children_raises=True)
    _bind(monkeypatch, root)
    tree = build_uia_tree(0x10, _PIDS, max_depth=3)
    assert tree["count"] == 1
    assert tree["nodes"][0]["children"] == []


# ---------------------------------------------------------------------------
# click_hwnd_uia


def test_click_prefers_the_invoke_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    _bind(monkeypatch, _FakeControl(invoke="ok"))
    result = click_hwnd_uia(0x10, _PIDS)
    assert result["backend"] == "uia_invoke"


def test_click_falls_back_to_mouse_click_without_a_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _bind(monkeypatch, _FakeControl(invoke="none"))
    result = click_hwnd_uia(0x10, _PIDS)
    assert result["backend"] == "uia_click"


def test_click_reports_a_failed_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    _bind(monkeypatch, _FakeControl(invoke="raise", click_raises=True))
    with pytest.raises(UiPidBoundaryError, match="UIA click/invoke failed"):
        click_hwnd_uia(0x10, _PIDS)


# ---------------------------------------------------------------------------
# set_value_uia


def test_set_value_rejects_a_non_string() -> None:
    with pytest.raises(UiPidBoundaryError, match="text must be a string"):
        set_value_uia(0x10, 123, _PIDS)  # type: ignore[arg-type]


def test_set_value_rejects_an_oversized_string() -> None:
    with pytest.raises(UiPidBoundaryError, match="exceeds 4096"):
        set_value_uia(0x10, "x" * 4097, _PIDS)


def test_set_value_uses_the_value_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    ctrl = _FakeControl(value="ok")
    _bind(monkeypatch, ctrl)
    result = set_value_uia(0x10, "hello", _PIDS)
    assert result["backend"] == "uia_value"
    assert ctrl.set_values == ["hello"]


def test_set_value_retries_when_the_first_probe_lands_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A first ValuePattern probe of None still succeeds on the direct retry."""
    ctrl = _FakeControl(value=["none", "ok"])
    _bind(monkeypatch, ctrl)
    result = set_value_uia(0x10, "world", _PIDS)
    assert result["backend"] == "uia_value"
    assert ctrl.set_values == ["world"]


def test_set_value_reports_a_failed_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    ctrl = _FakeControl(value=["raise", "raise"])
    _bind(monkeypatch, ctrl)
    with pytest.raises(UiPidBoundaryError, match="ValuePattern SetValue failed"):
        set_value_uia(0x10, "nope", _PIDS)
