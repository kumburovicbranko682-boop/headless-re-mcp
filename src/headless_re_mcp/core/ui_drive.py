from __future__ import annotations

from collections.abc import Mapping, Sequence
from time import monotonic
from typing import Any

from headless_re_mcp.core.ui_win32 import (
    click_hwnd,
    click_hwnd_at,
    close_hwnd,
    invoke_hwnd,
    resolve_hwnd,
    send_key,
    set_window_text,
    wait_for_window,
)
from headless_re_mcp.core.windows import UiPidBoundaryError

JsonObject = dict[str, Any]
_MAX_STEPS = 32
_ALLOWED_ACTIONS = frozenset(
    {"resolve", "click", "click_at", "close", "text.set", "key", "invoke", "wait"}
)


def normalize_drive_steps(steps: Sequence[Mapping[str, Any]] | None) -> list[JsonObject]:
    if steps is None:
        return []
    if not isinstance(steps, (list, tuple)) or len(steps) > _MAX_STEPS:
        raise UiPidBoundaryError(
            "invalid_params",
            f"steps must be a list of at most {_MAX_STEPS} items",
        )
    out: list[JsonObject] = []
    for index, raw in enumerate(steps):
        if not isinstance(raw, Mapping):
            raise UiPidBoundaryError(
                "invalid_params", "each step must be an object", index=index
            )
        action = str(raw.get("action", "")).strip().casefold()
        if action not in _ALLOWED_ACTIONS:
            raise UiPidBoundaryError(
                "invalid_params",
                "unsupported drive step action",
                index=index,
                action=action,
                allowed=sorted(_ALLOWED_ACTIONS),
            )
        item = dict(raw)
        item["action"] = action
        out.append(item)
    return out


def run_drive_step(
    step: JsonObject,
    *,
    allowed_pids: frozenset[int],
    handles: dict[str, int],
) -> JsonObject:
    action = str(step["action"])
    hwnd = step.get("hwnd")
    if hwnd is None and action in {
        "click",
        "click_at",
        "close",
        "text.set",
        "key",
        "invoke",
    }:
        hwnd = handles.get("last")
    if action == "resolve":
        parent = step.get("parent_hwnd")
        if parent is None and step.get("parent_from") == "root":
            parent = handles.get("root")
        if parent is None and step.get("parent_from") == "last":
            parent = handles.get("last")
        window = resolve_hwnd(
            allowed_pids,
            hwnd=int(hwnd) if isinstance(hwnd, int) else None,
            parent_hwnd=int(parent) if isinstance(parent, int) else None,
            class_name=step.get("class_name"),
            title=step.get("title"),
            title_contains=step.get("title_contains"),
            control_id=step.get("control_id"),
        )
        handles["last"] = int(window["hwnd"])
        if step.get("as_root") or not handles.get("root"):
            handles["root"] = int(window["hwnd"])
        return {"action": "resolve", "window": window}
    if action == "wait":
        parent = step.get("parent_hwnd")
        if parent is None and step.get("parent_from") == "root":
            parent = handles.get("root")
        if parent is None and step.get("parent_from") == "last":
            parent = handles.get("last")
        # Do not default parent to root: top-level title waits must scan the process.
        result = wait_for_window(
            allowed_pids,
            timeout=float(step.get("timeout", 10.0)),
            poll_interval=float(step.get("poll_interval", 0.1)),
            class_name=step.get("class_name"),
            title=step.get("title"),
            title_contains=step.get("title_contains"),
            control_id=step.get("control_id"),
            parent_hwnd=int(parent) if isinstance(parent, int) else None,
        )
        waited = result.get("window")
        if isinstance(waited, dict) and isinstance(waited.get("hwnd"), int):
            handles["last"] = int(waited["hwnd"])
        return {"action": "wait", **result}
    if not isinstance(hwnd, int):
        raise UiPidBoundaryError(
            "invalid_params",
            "step requires hwnd or prior resolve",
            action=action,
        )
    if action == "click":
        return click_hwnd(
            hwnd, allowed_pids, timeout_ms=int(step.get("timeout_ms", 5000))
        )
    if action == "click_at":
        x = step.get("x")
        y = step.get("y")
        if type(x) is not int or type(y) is not int:
            raise UiPidBoundaryError(
                "invalid_params", "click_at requires integer x/y client coords"
            )
        return click_hwnd_at(
            hwnd,
            allowed_pids,
            x=x,
            y=y,
            timeout_ms=int(step.get("timeout_ms", 5000)),
        )
    if action == "close":
        return close_hwnd(
            hwnd,
            allowed_pids,
            method=str(step.get("method", "nc_close")),
            timeout_ms=int(step.get("timeout_ms", 5000)),
        )
    if action == "text.set":
        text = step.get("text")
        if not isinstance(text, str):
            raise UiPidBoundaryError("invalid_params", "text.set requires text")
        return set_window_text(
            hwnd, text, allowed_pids, timeout_ms=int(step.get("timeout_ms", 5000))
        )
    if action == "key":
        return send_key(
            hwnd,
            allowed_pids=allowed_pids,
            text=step.get("text"),
            vk=step.get("vk"),
            timeout_ms=int(step.get("timeout_ms", 5000)),
        )
    if action == "invoke":
        return invoke_hwnd(
            hwnd,
            allowed_pids,
            action=str(step.get("invoke_action", "click")),
            text=step.get("text"),
            control_id=step.get("control_id"),
            timeout_ms=int(step.get("timeout_ms", 5000)),
        )
    raise UiPidBoundaryError("invalid_params", "unsupported drive step", action=action)


def drive_deadline(timeout: float) -> float:
    return monotonic() + float(timeout)
