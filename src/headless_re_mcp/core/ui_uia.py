"""UI Automation backend (optional) with PID boundary checks."""

from __future__ import annotations

import os
from typing import Any

from headless_re_mcp.core.ui_win32 import require_allowed_hwnd
from headless_re_mcp.core.windows import UiPidBoundaryError

JsonObject = dict[str, Any]

_MAX_TREE_NODES = 256
_MAX_TREE_DEPTH = 8


def uia_available() -> bool:
    if os.name != "nt":
        return False
    try:
        import uiautomation  # noqa: F401

        return True
    except Exception:
        return False


def _require_uia() -> Any:
    if os.name != "nt":
        raise UiPidBoundaryError(
            "unsupported_on_platform",
            "UI Automation requires Windows",
        )
    try:
        import uiautomation as auto
    except Exception as exc:  # pragma: no cover - optional dep
        raise UiPidBoundaryError(
            "capability_unavailable",
            "uiautomation package is not installed",
            detail=str(exc),
        ) from exc
    return auto


def _control_from_hwnd(hwnd: int, allowed_pids: frozenset[int]) -> Any:
    require_allowed_hwnd(hwnd, allowed_pids)
    auto = _require_uia()
    ctrl = auto.ControlFromHandle(int(hwnd))
    if ctrl is None:
        raise UiPidBoundaryError(
            "not_found",
            "UI Automation could not bind hwnd",
            hwnd=hwnd,
        )
    pid = int(getattr(ctrl, "ProcessId", 0) or 0)
    if pid not in allowed_pids:
        raise UiPidBoundaryError(
            "permission_denied",
            "UIA control ProcessId is outside allowed PIDs",
            hwnd=hwnd,
            process_id=pid,
            allowed_pids=sorted(allowed_pids),
        )
    return ctrl


def _describe_control(ctrl: Any) -> JsonObject:
    rect = None
    try:
        bounding = ctrl.BoundingRectangle
        rect = {
            "left": int(bounding.left),
            "top": int(bounding.top),
            "right": int(bounding.right),
            "bottom": int(bounding.bottom),
        }
    except Exception:
        rect = None
    hwnd = 0
    try:
        hwnd = int(ctrl.NativeWindowHandle or 0)
    except Exception:
        hwnd = 0
    return {
        "hwnd": hwnd,
        "name": str(getattr(ctrl, "Name", "") or ""),
        "automation_id": str(getattr(ctrl, "AutomationId", "") or ""),
        "class_name": str(getattr(ctrl, "ClassName", "") or ""),
        "control_type": str(getattr(ctrl, "ControlTypeName", "") or ""),
        "process_id": int(getattr(ctrl, "ProcessId", 0) or 0),
        "rect": rect,
    }


def build_uia_tree(
    root_hwnd: int,
    allowed_pids: frozenset[int],
    *,
    max_depth: int = 3,
    max_nodes: int = _MAX_TREE_NODES,
) -> JsonObject:
    if max_depth < 0 or max_depth > _MAX_TREE_DEPTH:
        raise UiPidBoundaryError(
            "invalid_params",
            f"max_depth must be 0..{_MAX_TREE_DEPTH}",
            max_depth=max_depth,
        )
    if max_nodes < 1 or max_nodes > _MAX_TREE_NODES:
        raise UiPidBoundaryError(
            "invalid_params",
            f"max_nodes must be 1..{_MAX_TREE_NODES}",
            max_nodes=max_nodes,
        )
    root = _control_from_hwnd(root_hwnd, allowed_pids)
    nodes = 0
    truncated = False

    def walk(ctrl: Any, depth: int) -> JsonObject | None:
        nonlocal nodes, truncated
        if nodes >= max_nodes:
            truncated = True
            return None
        pid = int(getattr(ctrl, "ProcessId", 0) or 0)
        if pid not in allowed_pids:
            return None
        nodes += 1
        item = _describe_control(ctrl)
        item["children"] = []
        try:
            children = ctrl.GetChildren()
        except Exception:
            children = []
        children = children or []
        if depth >= max_depth:
            # Stopping at the depth bound. A bare children: [] here reads as a
            # genuine leaf; if this control actually has children in scope, say
            # so with children_truncated and flip the top-level truncated flag
            # rather than passing the depth cut off as the bottom of the tree.
            # Children outside allowed_pids would not have been shown anyway, so
            # only an in-scope child counts as hidden.
            if any(int(getattr(c, "ProcessId", 0) or 0) in allowed_pids for c in children):
                item["children_truncated"] = True
                truncated = True
            return item
        for child in children:
            if nodes >= max_nodes:
                truncated = True
                break
            child_item = walk(child, depth + 1)
            if child_item is not None:
                item["children"].append(child_item)
        return item

    tree_root = walk(root, 0)
    return {
        "nodes": [tree_root] if tree_root is not None else [],
        "count": nodes,
        "max_depth": max_depth,
        "max_nodes": max_nodes,
        "truncated": truncated,
        "backend": "uia",
    }


def click_hwnd_uia(
    hwnd: int,
    allowed_pids: frozenset[int],
) -> JsonObject:
    ctrl = _control_from_hwnd(hwnd, allowed_pids)
    # Prefer InvokePattern; fall back to legacy mouse click via UIA helpers.
    try:
        pattern = ctrl.GetInvokePattern()
        if pattern is not None:
            pattern.Invoke()
            return {
                "hwnd": hwnd,
                "action": "click",
                "backend": "uia_invoke",
                "name": str(getattr(ctrl, "Name", "") or ""),
            }
    except Exception:
        pass
    try:
        ctrl.Click(simulateMove=False)
        return {
            "hwnd": hwnd,
            "action": "click",
            "backend": "uia_click",
            "name": str(getattr(ctrl, "Name", "") or ""),
        }
    except Exception as exc:
        raise UiPidBoundaryError(
            "backend_error",
            "UIA click/invoke failed",
            hwnd=hwnd,
            detail=str(exc),
        ) from exc


def set_value_uia(
    hwnd: int,
    text: str,
    allowed_pids: frozenset[int],
) -> JsonObject:
    if not isinstance(text, str):
        raise UiPidBoundaryError("invalid_params", "text must be a string")
    if len(text) > 4096:
        raise UiPidBoundaryError("invalid_params", "text exceeds 4096 characters")
    ctrl = _control_from_hwnd(hwnd, allowed_pids)
    try:
        pattern = ctrl.GetValuePattern()
        if pattern is not None:
            pattern.SetValue(text)
            return {
                "hwnd": hwnd,
                "action": "text.set",
                "text": text,
                "backend": "uia_value",
            }
    except Exception:
        pass
    try:
        ctrl.GetValuePattern().SetValue(text)
    except Exception as exc:
        raise UiPidBoundaryError(
            "backend_error",
            "UIA ValuePattern SetValue failed",
            hwnd=hwnd,
            detail=str(exc),
        ) from exc
    return {
        "hwnd": hwnd,
        "action": "text.set",
        "text": text,
        "backend": "uia_value",
    }
