"""Coverage for the optional UI Automation backend and its PID boundary.

ui_uia.py is pure decision logic over the third-party ``uiautomation`` package,
which is not installed off Windows. Injecting a fake ``uiautomation`` module and
a fake control tree lets every arm run anywhere: availability probing, the
capability/platform guards, the allowed-PID binding, control description with
its best-effort rect/handle reads, bounded tree walking (depth, node cap,
foreign-PID pruning), and the invoke/click/set-value fallbacks with their
fail-closed error mapping.
"""

from __future__ import annotations

import os
import sys
import types
from typing import Any

import pytest

import headless_re_mcp.core.ui_uia as uia
from headless_re_mcp.core.windows import UiPidBoundaryError

JsonObject = dict[str, Any]


class _NtOsProxy:
    name = "nt"

    def __getattr__(self, attr: str) -> Any:
        return getattr(os, attr)


class _Boom:
    """A descriptor-like sentinel that raises when its value is read."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    def __get__(self, obj: Any, owner: Any) -> Any:
        raise self._exc


class _Rect:
    def __init__(self, left: int, top: int, right: int, bottom: int) -> None:
        self.left, self.top, self.right, self.bottom = left, top, right, bottom


class _FakeControl:
    def __init__(
        self,
        *,
        process_id: int = 4242,
        name: str = "OK",
        automation_id: str = "btnOk",
        class_name: str = "Button",
        control_type: str = "ButtonControl",
        native_handle: int = 99,
        rect: _Rect | None = None,
        children: list[_FakeControl] | None = None,
        invoke_pattern: Any = "unset",
        value_pattern: Any = "unset",
        children_raises: bool = False,
    ) -> None:
        self.ProcessId = process_id
        self.Name = name
        self.AutomationId = automation_id
        self.ClassName = class_name
        self.ControlTypeName = control_type
        self.NativeWindowHandle = native_handle
        self.BoundingRectangle = rect if rect is not None else _Rect(0, 0, 10, 10)
        self._children = children or []
        self._invoke_pattern = invoke_pattern
        self._value_pattern = value_pattern
        self._children_raises = children_raises
        self.clicked = False

    def GetChildren(self) -> list[_FakeControl]:  # noqa: N802
        if self._children_raises:
            raise RuntimeError("tree walk failed")
        return self._children

    def GetInvokePattern(self) -> Any:  # noqa: N802
        if self._invoke_pattern == "unset":
            raise RuntimeError("no invoke pattern")
        return self._invoke_pattern

    def GetValuePattern(self) -> Any:  # noqa: N802
        if self._value_pattern == "unset":
            raise RuntimeError("no value pattern")
        return self._value_pattern

    def Click(self, *, simulateMove: bool = True) -> None:  # noqa: N802, N803
        self.clicked = True


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    control: _FakeControl | None = None,
    control_from_handle: Any = "default",
) -> types.SimpleNamespace:
    monkeypatch.setattr(uia, "os", _NtOsProxy())
    monkeypatch.setattr(uia, "require_allowed_hwnd", lambda hwnd, pids: hwnd)

    if control_from_handle == "default":

        def control_from_handle(handle: int) -> Any:
            return control

    module = types.SimpleNamespace(ControlFromHandle=control_from_handle)
    monkeypatch.setitem(sys.modules, "uiautomation", module)
    return module


# --------------------------------------------------------------------------- #
# availability and capability guards
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(os.name == "nt", reason="the platform guard only fires off Windows")
def test_uia_is_unavailable_and_guarded_off_windows() -> None:
    assert uia.uia_available() is False
    with pytest.raises(UiPidBoundaryError) as exc:
        uia._require_uia()
    assert exc.value.code == "unsupported_on_platform"


def test_uia_available_is_true_when_the_package_imports(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(uia, "os", _NtOsProxy())
    monkeypatch.setitem(sys.modules, "uiautomation", types.SimpleNamespace())
    assert uia.uia_available() is True


def test_uia_available_is_false_when_the_import_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(uia, "os", _NtOsProxy())
    monkeypatch.setitem(sys.modules, "uiautomation", None)
    assert uia.uia_available() is False


def test_require_uia_reports_a_missing_package(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(uia, "os", _NtOsProxy())
    monkeypatch.setitem(sys.modules, "uiautomation", None)
    with pytest.raises(UiPidBoundaryError) as exc:
        uia._require_uia()
    assert exc.value.code == "capability_unavailable"


def test_require_uia_returns_the_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _install(monkeypatch, control=_FakeControl())
    assert uia._require_uia() is module


# --------------------------------------------------------------------------- #
# _control_from_hwnd binding and PID boundary
# --------------------------------------------------------------------------- #


def test_control_from_hwnd_reports_a_failed_bind(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, control=None)
    with pytest.raises(UiPidBoundaryError) as exc:
        uia._control_from_hwnd(5, frozenset({4242}))
    assert exc.value.code == "not_found"


def test_control_from_hwnd_refuses_a_foreign_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, control=_FakeControl(process_id=999))
    with pytest.raises(UiPidBoundaryError) as exc:
        uia._control_from_hwnd(5, frozenset({4242}))
    assert exc.value.code == "permission_denied"
    assert exc.value.details["process_id"] == 999


def test_control_from_hwnd_binds_an_allowed_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _FakeControl(process_id=4242)
    _install(monkeypatch, control=control)
    assert uia._control_from_hwnd(5, frozenset({4242})) is control


# --------------------------------------------------------------------------- #
# _describe_control best-effort reads
# --------------------------------------------------------------------------- #


def test_describe_control_projects_the_full_shape() -> None:
    control = _FakeControl(rect=_Rect(1, 2, 3, 4), native_handle=77)
    described = uia._describe_control(control)
    assert described["hwnd"] == 77
    assert described["name"] == "OK"
    assert described["automation_id"] == "btnOk"
    assert described["class_name"] == "Button"
    assert described["control_type"] == "ButtonControl"
    assert described["process_id"] == 4242
    assert described["rect"] == {"left": 1, "top": 2, "right": 3, "bottom": 4}


def test_describe_control_tolerates_unreadable_rect_and_handle() -> None:
    class _Prickly:
        Name = "Edgy"
        AutomationId = ""
        ClassName = "Ctl"
        ControlTypeName = "PaneControl"
        ProcessId = 4242
        BoundingRectangle = _Boom(RuntimeError("no rect"))
        NativeWindowHandle = _Boom(RuntimeError("no handle"))

    described = uia._describe_control(_Prickly())
    assert described["rect"] is None
    assert described["hwnd"] == 0
    assert described["name"] == "Edgy"


# --------------------------------------------------------------------------- #
# build_uia_tree
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("max_depth", "max_nodes"),
    [(-1, 8), (9, 8), (3, 0), (3, 257)],
)
def test_build_tree_bounds_its_limits(
    monkeypatch: pytest.MonkeyPatch, max_depth: int, max_nodes: int
) -> None:
    _install(monkeypatch, control=_FakeControl())
    with pytest.raises(UiPidBoundaryError) as exc:
        uia.build_uia_tree(5, frozenset({4242}), max_depth=max_depth, max_nodes=max_nodes)
    assert exc.value.code == "invalid_params"


def test_build_tree_walks_children_and_prunes_foreign_pids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foreign = _FakeControl(process_id=999, name="Foreign")
    kept = _FakeControl(process_id=4242, name="Child")
    root = _FakeControl(process_id=4242, name="Root", children=[foreign, kept])
    _install(monkeypatch, control=root)

    tree = uia.build_uia_tree(5, frozenset({4242}), max_depth=3)

    assert tree["backend"] == "uia"
    assert tree["count"] == 2, "the foreign-PID child is pruned from the count"
    (root_node,) = tree["nodes"]
    assert root_node["name"] == "Root"
    assert [child["name"] for child in root_node["children"]] == ["Child"]
    assert tree["truncated"] is False


def test_build_tree_stops_descending_at_max_depth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    grandchild = _FakeControl(name="Grandchild")
    child = _FakeControl(name="Child", children=[grandchild])
    root = _FakeControl(name="Root", children=[child])
    _install(monkeypatch, control=root)

    tree = uia.build_uia_tree(5, frozenset({4242}), max_depth=1)

    (root_node,) = tree["nodes"]
    (child_node,) = root_node["children"]
    assert child_node["name"] == "Child"
    assert child_node["children"] == [], "max_depth stops the walk before grandchildren"


def test_build_tree_truncates_at_the_node_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    children = [_FakeControl(name=f"c{i}") for i in range(5)]
    root = _FakeControl(name="Root", children=children)
    _install(monkeypatch, control=root)

    tree = uia.build_uia_tree(5, frozenset({4242}), max_depth=3, max_nodes=2)

    assert tree["truncated"] is True
    assert tree["count"] == 2


def test_build_tree_tolerates_a_failing_get_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _FakeControl(name="Root", children_raises=True)
    _install(monkeypatch, control=root)
    tree = uia.build_uia_tree(5, frozenset({4242}), max_depth=3)
    (root_node,) = tree["nodes"]
    assert root_node["children"] == []


# --------------------------------------------------------------------------- #
# click_hwnd_uia
# --------------------------------------------------------------------------- #


def test_click_prefers_the_invoke_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    invoked: list[bool] = []
    pattern = types.SimpleNamespace(Invoke=lambda: invoked.append(True))
    control = _FakeControl(invoke_pattern=pattern)
    _install(monkeypatch, control=control)

    result = uia.click_hwnd_uia(5, frozenset({4242}))

    assert result["backend"] == "uia_invoke"
    assert invoked == [True]
    assert control.clicked is False


def test_click_falls_back_to_a_legacy_click(monkeypatch: pytest.MonkeyPatch) -> None:
    # GetInvokePattern raises (caught), so the legacy Click path runs.
    control = _FakeControl(invoke_pattern="unset")
    _install(monkeypatch, control=control)

    result = uia.click_hwnd_uia(5, frozenset({4242}))

    assert result["backend"] == "uia_click"
    assert control.clicked is True


def test_click_falls_back_when_the_invoke_pattern_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = _FakeControl(invoke_pattern=None)
    _install(monkeypatch, control=control)
    result = uia.click_hwnd_uia(5, frozenset({4242}))
    assert result["backend"] == "uia_click"


def test_click_maps_a_total_failure_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Unclickable(_FakeControl):
        def Click(self, *, simulateMove: bool = True) -> None:  # noqa: N802, N803
            raise RuntimeError("click refused")

    _install(monkeypatch, control=_Unclickable(invoke_pattern=None))
    with pytest.raises(UiPidBoundaryError) as exc:
        uia.click_hwnd_uia(5, frozenset({4242}))
    assert exc.value.code == "backend_error"


# --------------------------------------------------------------------------- #
# set_value_uia
# --------------------------------------------------------------------------- #


def test_set_value_rejects_a_non_string(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, control=_FakeControl())
    with pytest.raises(UiPidBoundaryError, match="must be a string"):
        uia.set_value_uia(5, 123, frozenset({4242}))  # type: ignore[arg-type]


def test_set_value_bounds_the_length(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, control=_FakeControl())
    with pytest.raises(UiPidBoundaryError, match="exceeds 4096"):
        uia.set_value_uia(5, "x" * 4097, frozenset({4242}))


def test_set_value_uses_the_value_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    written: list[str] = []
    pattern = types.SimpleNamespace(SetValue=lambda text: written.append(text))
    control = _FakeControl(value_pattern=pattern)
    _install(monkeypatch, control=control)

    result = uia.set_value_uia(5, "hello", frozenset({4242}))

    assert result["backend"] == "uia_value"
    assert result["text"] == "hello"
    assert written == ["hello"]


def test_set_value_retries_the_pattern_after_a_first_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first ValuePattern.SetValue raises (caught), and the retry through a
    # freshly fetched pattern succeeds and reports the uia_value backend.
    written: list[str] = []
    failing = types.SimpleNamespace(
        SetValue=lambda text: (_ for _ in ()).throw(RuntimeError("busy"))
    )
    working = types.SimpleNamespace(SetValue=lambda text: written.append(text))
    patterns = iter([failing, working])

    class _RetryControl(_FakeControl):
        def GetValuePattern(self) -> Any:  # noqa: N802
            return next(patterns)

    _install(monkeypatch, control=_RetryControl())

    result = uia.set_value_uia(5, "again", frozenset({4242}))

    assert result["backend"] == "uia_value"
    assert result["text"] == "again"
    assert written == ["again"]


def test_set_value_maps_a_failing_pattern_to_backend_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first GetValuePattern returns None (skip), the fallback path then calls
    # GetValuePattern().SetValue which raises and is mapped to backend_error.
    class _NoValue(_FakeControl):
        def GetValuePattern(self) -> Any:  # noqa: N802
            return None

    _install(monkeypatch, control=_NoValue())
    with pytest.raises(UiPidBoundaryError) as exc:
        uia.set_value_uia(5, "hello", frozenset({4242}))
    assert exc.value.code == "backend_error"
