"""Deterministic coverage for the optional UIA backend (``core.ui_uia``).

``uiautomation`` is imported lazily, so a fake module in ``sys.modules`` plus
an ``os.name`` pin drives every Windows-only path on any host: control
binding, the PID re-check inside the tree walk, node/depth budgets, and the
Invoke/Value pattern fallbacks.
"""

from __future__ import annotations

import os
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

import headless_re_mcp.core.ui_uia as uia
from headless_re_mcp.core.windows import UiPidBoundaryError

ALLOWED = frozenset({100})


class _OsProxy:
    name = "nt"

    def __getattr__(self, attribute: str) -> Any:
        return getattr(os, attribute)


class _Control:
    """A cooperative UIA control; behaviors are injected per test."""

    def __init__(
        self,
        *,
        pid: int = 100,
        hwnd: int = 5,
        name: str = "OK",
        children: list[_Control] | None = None,
    ) -> None:
        self.ProcessId = pid
        self.NativeWindowHandle = hwnd
        self.Name = name
        self.AutomationId = "btn-ok"
        self.ClassName = "Button"
        self.ControlTypeName = "ButtonControl"
        self.BoundingRectangle = SimpleNamespace(left=1, top=2, right=30, bottom=40)
        self._children = list(children or [])

    def GetChildren(self) -> list[_Control]:
        return list(self._children)


def _pin(
    monkeypatch: pytest.MonkeyPatch,
    *,
    controls: dict[int, Any] | None = None,
) -> None:
    module = ModuleType("uiautomation")
    table = dict(controls or {})
    module.ControlFromHandle = lambda hwnd: table.get(int(hwnd))  # type: ignore[attr-defined]
    monkeypatch.setattr(uia, "os", _OsProxy())
    monkeypatch.setitem(sys.modules, "uiautomation", module)
    monkeypatch.setattr(uia, "require_allowed_hwnd", lambda hwnd, allowed: None)


# ---------------------------------------------------------------------------
# Availability and the platform / dependency gates.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name == "nt", reason="the refusal only exists off Windows")
def test_uia_is_unavailable_and_refused_off_windows() -> None:
    assert uia.uia_available() is False
    with pytest.raises(UiPidBoundaryError) as refused:
        uia._require_uia()
    assert refused.value.code == "unsupported_on_platform"


def test_uia_availability_follows_the_import(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch)
    assert uia.uia_available() is True

    monkeypatch.delitem(sys.modules, "uiautomation")
    assert uia.uia_available() is False, "a missing package must read as unavailable"


def test_a_missing_package_is_a_named_capability_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(uia, "os", _OsProxy())
    monkeypatch.setattr(uia, "require_allowed_hwnd", lambda hwnd, allowed: None)
    monkeypatch.delitem(sys.modules, "uiautomation", raising=False)

    with pytest.raises(UiPidBoundaryError) as refused:
        uia.click_hwnd_uia(5, ALLOWED)

    assert refused.value.code == "capability_unavailable"


# ---------------------------------------------------------------------------
# Control binding and the PID boundary.
# ---------------------------------------------------------------------------


def test_an_unbindable_hwnd_is_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    _pin(monkeypatch, controls={})
    with pytest.raises(UiPidBoundaryError) as refused:
        uia.click_hwnd_uia(5, ALLOWED)
    assert refused.value.code == "not_found"


def test_a_control_owned_by_another_process_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _pin(monkeypatch, controls={5: _Control(pid=999)})
    with pytest.raises(UiPidBoundaryError) as refused:
        uia.click_hwnd_uia(5, ALLOWED)
    assert refused.value.code == "permission_denied"
    assert refused.value.details["process_id"] == 999
    assert refused.value.details["allowed_pids"] == [100]


def test_describe_control_survives_hostile_properties() -> None:
    class _Hostile:
        Name = None
        ProcessId = None

        @property
        def BoundingRectangle(self) -> Any:
            raise OSError("COM went away")

        @property
        def NativeWindowHandle(self) -> Any:
            raise OSError("COM went away")

    described = uia._describe_control(_Hostile())

    assert described["rect"] is None and described["hwnd"] == 0
    assert described["name"] == "" and described["process_id"] == 0
    assert described["automation_id"] == "" and described["control_type"] == ""


# ---------------------------------------------------------------------------
# Tree building: budgets, depth, and the in-walk PID re-check.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "message_part"),
    [
        ({"max_depth": -1}, "max_depth"),
        ({"max_depth": 9}, "max_depth"),
        ({"max_nodes": 0}, "max_nodes"),
        ({"max_nodes": 257}, "max_nodes"),
    ],
)
def test_tree_budgets_are_validated_before_binding(
    monkeypatch: pytest.MonkeyPatch,
    kwargs: dict[str, int],
    message_part: str,
) -> None:
    bound: list[int] = []
    _pin(monkeypatch, controls={5: _Control()})
    monkeypatch.setattr(uia, "require_allowed_hwnd", lambda hwnd, allowed: bound.append(hwnd))

    with pytest.raises(UiPidBoundaryError) as refused:
        uia.build_uia_tree(5, ALLOWED, **kwargs)

    assert refused.value.code == "invalid_params"
    assert message_part in refused.value.message
    assert bound == [], "no hwnd may be touched with hostile budgets"


def test_tree_walk_descends_within_depth_and_skips_foreign_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grandchild = _Control(pid=100, hwnd=8, name="grandchild")
    foreign = _Control(pid=999, hwnd=9, name="intruder")
    child = _Control(pid=100, hwnd=7, name="child", children=[grandchild])
    root = _Control(pid=100, hwnd=5, name="root", children=[child, foreign])
    _pin(monkeypatch, controls={5: root})

    tree = uia.build_uia_tree(5, ALLOWED, max_depth=1)

    assert tree["count"] == 2 and tree["truncated"] is False
    top = tree["nodes"][0]
    assert top["name"] == "root"
    assert [node["name"] for node in top["children"]] == ["child"], (
        "the foreign-PID sibling must not appear in the tree"
    )
    assert top["children"][0]["children"] == [], "max_depth=1 stops before the grandchild"
    assert top["rect"] == {"left": 1, "top": 2, "right": 30, "bottom": 40}


def test_tree_walk_truncates_at_the_node_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    children = [_Control(pid=100, hwnd=10 + index) for index in range(4)]
    root = _Control(pid=100, hwnd=5, children=children)
    _pin(monkeypatch, controls={5: root})

    tree = uia.build_uia_tree(5, ALLOWED, max_depth=2, max_nodes=3)

    assert tree["truncated"] is True and tree["count"] == 3
    assert len(tree["nodes"][0]["children"]) == 2, "root plus two children exhaust the budget"


def test_tree_walk_survives_a_children_query_crash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _Control(pid=100, hwnd=5)
    monkeypatch.setattr(root, "GetChildren", lambda: (_ for _ in ()).throw(OSError("COM died")))
    _pin(monkeypatch, controls={5: root})

    tree = uia.build_uia_tree(5, ALLOWED)

    assert tree["count"] == 1 and tree["nodes"][0]["children"] == []


def test_a_root_whose_pid_flips_after_binding_yields_an_empty_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The walk re-reads ProcessId: a post-bind flip must not be described."""

    class _Flipping:
        Name = "flipper"
        NativeWindowHandle = 5

        def __init__(self) -> None:
            self._reads = 0

        @property
        def ProcessId(self) -> int:
            self._reads += 1
            return 100 if self._reads == 1 else 999

        def GetChildren(self) -> list[Any]:
            return []

    _pin(monkeypatch, controls={5: _Flipping()})

    tree = uia.build_uia_tree(5, ALLOWED)

    assert tree["nodes"] == [] and tree["count"] == 0


# ---------------------------------------------------------------------------
# Click: InvokePattern first, legacy click second, then a named failure.
# ---------------------------------------------------------------------------


def test_click_prefers_the_invoke_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    invoked: list[str] = []
    control = _Control(name="Run")
    control.GetInvokePattern = lambda: SimpleNamespace(  # type: ignore[attr-defined]
        Invoke=lambda: invoked.append("invoke")
    )
    _pin(monkeypatch, controls={5: control})

    envelope = uia.click_hwnd_uia(5, ALLOWED)

    assert invoked == ["invoke"]
    assert envelope["backend"] == "uia_invoke" and envelope["name"] == "Run"


def test_click_falls_back_to_the_legacy_click(monkeypatch: pytest.MonkeyPatch) -> None:
    clicks: list[bool] = []
    control = _Control()
    control.GetInvokePattern = lambda: None  # type: ignore[attr-defined]
    control.Click = lambda simulateMove: clicks.append(simulateMove)  # type: ignore[attr-defined]
    _pin(monkeypatch, controls={5: control})

    envelope = uia.click_hwnd_uia(5, ALLOWED)

    assert clicks == [False], "the fallback must not simulate cursor movement"
    assert envelope["backend"] == "uia_click"


def test_click_failure_of_both_paths_names_the_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _Control()

    def broken(*args: Any, **kwargs: Any) -> Any:
        raise OSError("element is gone")

    control.GetInvokePattern = broken  # type: ignore[attr-defined]
    control.Click = broken  # type: ignore[attr-defined]
    _pin(monkeypatch, controls={5: control})

    with pytest.raises(UiPidBoundaryError) as refused:
        uia.click_hwnd_uia(5, ALLOWED)

    assert refused.value.code == "backend_error"
    assert "element is gone" in str(refused.value.details["detail"])


# ---------------------------------------------------------------------------
# set_value: guards, the happy pattern, the retry, and the named failure.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("text", [42, None, "x" * 4097])
def test_hostile_set_value_text_is_refused_before_binding(
    monkeypatch: pytest.MonkeyPatch,
    text: Any,
) -> None:
    bound: list[int] = []
    _pin(monkeypatch, controls={5: _Control()})
    monkeypatch.setattr(uia, "require_allowed_hwnd", lambda hwnd, allowed: bound.append(hwnd))

    with pytest.raises(UiPidBoundaryError) as refused:
        uia.set_value_uia(5, text, ALLOWED)

    assert refused.value.code == "invalid_params"
    assert bound == []


def test_set_value_writes_through_the_value_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[str] = []
    control = _Control()
    control.GetValuePattern = lambda: SimpleNamespace(SetValue=written.append)  # type: ignore[attr-defined]
    _pin(monkeypatch, controls={5: control})

    envelope = uia.set_value_uia(5, "flag{}", ALLOWED)

    assert written == ["flag{}"]
    assert envelope["backend"] == "uia_value" and envelope["text"] == "flag{}"


def test_set_value_retries_once_when_the_first_pattern_query_crashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    written: list[str] = []
    control = _Control()
    state = {"calls": 0}

    def flaky_pattern() -> Any:
        state["calls"] += 1
        if state["calls"] == 1:
            raise OSError("COM hiccup")
        return SimpleNamespace(SetValue=written.append)

    control.GetValuePattern = flaky_pattern  # type: ignore[attr-defined]
    _pin(monkeypatch, controls={5: control})

    envelope = uia.set_value_uia(5, "retry", ALLOWED)

    assert written == ["retry"], "the retry path must still deliver the text"
    assert envelope["backend"] == "uia_value"


def test_set_value_failure_of_both_attempts_is_a_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _Control()
    control.GetValuePattern = lambda: None  # type: ignore[attr-defined]
    _pin(monkeypatch, controls={5: control})

    with pytest.raises(UiPidBoundaryError) as refused:
        uia.set_value_uia(5, "text", ALLOWED)

    assert refused.value.code == "backend_error"
