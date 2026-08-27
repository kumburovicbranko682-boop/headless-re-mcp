"""Bounded UI automation against the debuggee, and hidden-desktop capture.

Split out of AnalysisService. Every entry point here is PID-bounded: the target
process and its direct children are the only windows this may touch, which is
what keeps a debugger that drives GUIs from being a remote-control tool for the
whole desktop. That boundary is enforced in ui_win32/windows, not here; this is
the service-level surface over it.

Behaviour is unchanged by the move. The members below are supplied by
AnalysisService, and mypy checks these declarations against the real
definitions.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from headless_re_mcp.backends.x64dbg.client import XdbgRpcError
from headless_re_mcp.core.models import BackendKind, Result
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _register_capture
from headless_re_mcp.core.service_static import _FATAL_WORKER_ERRORS
from headless_re_mcp.core.ui_ocr import ocr_hwnd
from headless_re_mcp.core.ui_sendinput import click_hwnd_sendinput, send_key_sendinput
from headless_re_mcp.core.ui_uia import (
    build_uia_tree,
    click_hwnd_uia,
    set_value_uia,
    uia_available,
)
from headless_re_mcp.core.ui_win32 import (
    build_window_tree,
    capture_hwnd_screenshot,
    click_hwnd,
    click_hwnd_at,
    close_hwnd,
    invoke_hwnd,
    resolve_hwnd,
    send_key,
    set_window_text,
    wait_for_window,
)
from headless_re_mcp.core.windows import (
    UiPidBoundaryError,
    is_pid_alive,
    list_windows_for_pids,
    resolve_allowed_ui_pids,
    window_capture_rank,
)
from headless_re_mcp.platform_support import unsupported_on_platform_details

if TYPE_CHECKING:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.application_services import ApplicationServices
    from headless_re_mcp.core.service import DynamicWorker, _BackendRuntime

JsonObject = dict[str, Any]

# ui.process_tree is a read-only "which pid/window do I drive" probe. Both the
# child list and each child's window list are bounded so a Chromium-style tree
# cannot balloon the reply; the counts and flags below exist so a bounded reply
# says it is bounded rather than posing as the whole tree.
_UI_CHILD_ROW_LIMIT = 16
_UI_CHILD_WINDOW_LIMIT = 16


def _ui_child_process_rows(debuggee_pid: int) -> tuple[list[JsonObject], bool]:
    """Bounded direct-child rows for ui.process_tree, plus a truncation flag.

    Enumerates one past the row cap so an exact-cap tree is distinguishable
    from a larger one, and tags each child's window list with its true total
    so a page of a child's windows does not read as the whole set. Kept as a
    module helper because the surrounding call path is Windows-gated; this is
    the part whose honesty is worth exercising on any platform.
    """
    from headless_re_mcp.core.process_tree import (
        enumerate_direct_children,
        process_image_path,
    )

    probed = enumerate_direct_children(debuggee_pid, max_pids=_UI_CHILD_ROW_LIMIT + 1)
    children_truncated = len(probed) > _UI_CHILD_ROW_LIMIT
    rows: list[JsonObject] = []
    for child in probed[:_UI_CHILD_ROW_LIMIT]:
        wins = list_windows_for_pids([child])
        rows.append(
            {
                "pid": child,
                "image": process_image_path(child),
                "alive": is_pid_alive(child),
                "top_level_windows": wins[:_UI_CHILD_WINDOW_LIMIT],
                "top_level_windows_total": len(wins),
                "top_level_windows_truncated": len(wins) > _UI_CHILD_WINDOW_LIMIT,
            }
        )
    return rows, children_truncated


def _unsupported_ui(session_id: str, capability: str) -> Result[JsonObject]:
    return _failure(
        XdbgRpcError(
            "unsupported_on_platform",
            f"{capability} requires Windows",
            details=unsupported_on_platform_details(capability),
        ),
        session_id=session_id,
    )


def _as_positive_pid(value: object) -> int | None:
    if type(value) is int and value > 0:
        return value
    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        if parsed > 0:
            return parsed
    return None


def _desktop_monitor_pids(state: JsonObject) -> tuple[frozenset[int], int | None]:
    """Resolve a bounded target process set for passive desktop monitoring."""
    value = _as_positive_pid(state.get("process_id") or state.get("debuggee_pid"))
    if value is None or not is_pid_alive(value):
        return frozenset(), None
    from headless_re_mcp.core.process_tree import enumerate_direct_children

    allowed = {value}
    for child in enumerate_direct_children(value):
        if is_pid_alive(child):
            allowed.add(child)
    return frozenset(allowed), value


def _annotate_virtual_desktop_snapshot(
    snapshot: JsonObject,
    *,
    session_id: str,
    state: JsonObject,
    allowed: frozenset[int],
    debuggee_pid: int | None,
    debugger_pid: int | None,
) -> JsonObject:
    """Attach debuggee pause/idle context so a 0-window snapshot is not 'empty desktop'."""
    payload = dict(snapshot)
    windows = payload.get("windows")
    if not isinstance(windows, list):
        windows = []
    window_count = len(windows)
    desktop_count = payload.get("desktop_window_count")
    if type(desktop_count) is not int:
        desktop_count = window_count
    debug_state = str(state.get("state") or "idle")
    payload.update(
        {
            "session_id": session_id,
            "debuggee_pid": debuggee_pid,
            "debugger_pid": debugger_pid,
            "allowed_pids": sorted(allowed),
            "capture_mode": "passive",
            "debuggee_state": debug_state,
            "window_count": window_count,
            "desktop_window_count": desktop_count,
            "windows": windows,
        }
    )
    if window_count == 0 and "hint" not in payload:
        if debug_state == "paused":
            payload["hint"] = "paused_before_gui"
            payload["suggestion"] = (
                "The debuggee is paused (typically at the system or entry "
                "breakpoint) and has not created windows yet. Call "
                "dynamic.resume, then snapshot again. A live PID after "
                "dynamic.launch is not a GUI."
            )
        elif debug_state == "running":
            payload["hint"] = "no_debuggee_windows"
            payload["suggestion"] = (
                "The debuggee is running but has no top-level window on this desktop yet."
            )
        else:
            payload["hint"] = "debuggee_idle"
            payload["suggestion"] = "No debuggee is running. Launch or attach first."
    return payload


def _select_desktop_window(
    windows: list[JsonObject],
    requested_hwnd: int | None,
) -> JsonObject:
    if requested_hwnd is not None:
        if type(requested_hwnd) is not int or requested_hwnd <= 0:
            raise ValueError("hwnd must be a positive integer")
        for row in windows:
            if row.get("hwnd") == requested_hwnd:
                return row
        raise XdbgRpcError(
            "not_found",
            "requested hwnd is not on the authorized hidden desktop",
            details={"hwnd": requested_hwnd},
        )
    if not windows:
        raise XdbgRpcError(
            "not_found",
            "the debuggee has no capturable hidden-desktop window",
        )
    return max(windows, key=window_capture_rank)


def _ui_finalize_windows(
    payload: JsonObject,
    ctx: JsonObject,
    *,
    hidden_desktop: bool = False,
) -> JsonObject:
    allowed = ctx["allowed"]
    windows = payload.get("windows")
    if not isinstance(windows, list):
        windows = []
    assert isinstance(allowed, frozenset)
    for window in windows:
        if not isinstance(window, dict):
            continue
        owner = window.get("pid")
        if owner not in allowed:
            raise UiPidBoundaryError(
                "permission_denied",
                "window enumeration escaped allowed PID set",
                pid=owner,
                allowed_pids=sorted(allowed),
            )
    payload["windows"] = windows
    payload["count"] = len(windows)
    if len(windows) == 0:
        debuggee_pid = ctx.get("debuggee_pid")
        if isinstance(debuggee_pid, int) and debuggee_pid > 0 and is_pid_alive(debuggee_pid):
            try:
                from headless_re_mcp.core.process_tree import probe_child_window_candidates

                children = probe_child_window_candidates(debuggee_pid, list_windows_fn=None)
            except Exception:
                children = []
            if children:
                payload["hint"] = "windows_on_child_pids"
                payload["child_candidates"] = children
                payload["suggested_child_pids"] = [int(c["pid"]) for c in children]
                payload["suggestion"] = (
                    "Pass allow_child_pids=suggested_child_pids or "
                    "include_same_image_children=true"
                )
    if len(windows) == 0 and hidden_desktop and "hint" not in payload:
        # This enumerates the desktop the service itself runs on. Under
        # hidden_desktop the debuggee's windows belong to a different Win32
        # desktop object, so an empty list here means "not on this desktop",
        # not "this program has no GUI". A caller that cannot tell those apart
        # concludes the sample is headless and stops looking, so name the two
        # tools that can actually see it.
        payload["hint"] = "windows_on_hidden_desktop"
        payload["suggestion"] = (
            "This session runs on a hidden desktop, which this enumeration "
            "cannot reach. Use ui.virtual_desktop.snapshot to list its windows "
            "and ui.virtual_desktop.capture to image one."
        )
    return payload


class UiAutomationMixin:
    """PID-bounded window inspection, interaction and capture."""

    settings: Settings
    services: ApplicationServices

    if TYPE_CHECKING:

        def _runtime(self, session_id: str, kind: BackendKind) -> _BackendRuntime: ...

        def _require_current_runtime(
            self,
            session_id: str,
            kind: BackendKind,
            runtime: _BackendRuntime,
        ) -> None: ...

        def _fail_runtime(
            self,
            session_id: str,
            kind: BackendKind,
            *,
            failure: BaseException | None = None,
        ) -> None: ...

        def _observe_debuggee_state(self, session_id: str, state: JsonObject) -> JsonObject: ...

        def _annotate_debuggee_pids(self, session_id: str, state: JsonObject) -> JsonObject: ...

    def virtual_desktop_snapshot(self, session_id: str) -> Result[JsonObject]:
        """Return a passive, PID-bounded snapshot of the session desktop."""
        if os.name != "nt":
            return _unsupported_ui(session_id, "ui.virtual_desktop.snapshot")
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            snapshot_fn = getattr(runtime.worker, "desktop_snapshot", None)
            if not callable(snapshot_fn):
                raise XdbgRpcError(
                    "capability_unavailable",
                    "x64dbg worker does not expose desktop monitoring",
                )
            with runtime.lock:
                state = runtime.worker.request("debug.state", timeout=5.0)
                allowed, debuggee_pid = _desktop_monitor_pids(state)
                snapshot = snapshot_fn(allowed_pids=allowed)
            if not isinstance(snapshot, dict):
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "desktop monitor returned a non-object snapshot",
                )
            payload = _annotate_virtual_desktop_snapshot(
                snapshot,
                session_id=session_id,
                state=state,
                allowed=allowed,
                debuggee_pid=debuggee_pid,
                debugger_pid=runtime.worker.pid,
            )
            return _success(
                payload,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(
                exc,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
    def virtual_desktop_capture(
        self,
        session_id: str,
        *,
        hwnd: int | None = None,
    ) -> Result[JsonObject]:
        """Capture one authorized hidden-desktop window without switching desktops."""
        if os.name != "nt":
            return _unsupported_ui(session_id, "ui.virtual_desktop.capture")
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            snapshot_fn = getattr(runtime.worker, "desktop_snapshot", None)
            capture_fn = getattr(runtime.worker, "desktop_capture", None)
            if not callable(snapshot_fn) or not callable(capture_fn):
                raise XdbgRpcError(
                    "capability_unavailable",
                    "x64dbg worker does not expose hidden-desktop capture",
                )
            with runtime.lock:
                state = runtime.worker.request("debug.state", timeout=5.0)
                allowed, debuggee_pid = _desktop_monitor_pids(state)
                snapshot = snapshot_fn(allowed_pids=allowed)
                windows = snapshot.get("windows") if isinstance(snapshot, dict) else None
                rows = [row for row in windows or [] if isinstance(row, dict)]
                selected = _select_desktop_window(rows, hwnd)
                selected_hwnd = int(selected["hwnd"])
                output = (
                    self.settings.artifact_root.expanduser().resolve()
                    / "sessions"
                    / session_id
                    / "desktop"
                    / f"window-{selected_hwnd}.bmp"
                )
                capture = capture_fn(
                    selected_hwnd,
                    allowed_pids=allowed,
                    output_path=output,
                )
            if not isinstance(capture, dict):
                raise XdbgRpcError(
                    "rpc_protocol_error",
                    "desktop capture returned a non-object payload",
                )
            return _success(
                {
                    **capture,
                    "session_id": session_id,
                    "debuggee_pid": debuggee_pid,
                    "window": selected,
                    "intrusion": "on_demand_printwindow",
                },
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        except BaseException as exc:
            return _failure(
                exc,
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
    def ui_windows_list(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        return self.services.interaction.windows_list(
            session_id,
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
        )
    def _ui_windows_list(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        """List top-level windows owned by the session debuggee (PID-bounded)."""
        return self._ui_call(
            session_id,
            capability="ui.windows.list",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=lambda ctx: {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(ctx["allowed"]),
                "blocked_pids": sorted(ctx["blocked"]),
                "windows": list_windows_for_pids(sorted(ctx["allowed"])),
                "count": 0,  # filled below
                "note": (
                    "windows are filtered to debuggee_pid "
                    "(plus explicit allow_child_pids); "
                    "debugger_pid/host are blocked"
                ),
            },
            finalize=lambda payload, ctx: _ui_finalize_windows(
                payload, ctx, hidden_desktop=bool(self.settings.hidden_desktop)
            ),
        )
    def ui_process_tree(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
    ) -> Result[JsonObject]:
        """Read-only process tree + window probe for debuggee (does not grant UI rights)."""

        def action(ctx: JsonObject) -> JsonObject:
            from headless_re_mcp.core.process_tree import (
                probe_child_window_candidates,
                process_image_path,
            )

            debuggee_pid = int(ctx["debuggee_pid"])
            child_rows, children_truncated = _ui_child_process_rows(debuggee_pid)
            return {
                "debuggee_pid": debuggee_pid,
                "debugger_pid": ctx["debugger_pid"],
                "debuggee_image": process_image_path(debuggee_pid),
                "debuggee_windows": list_windows_for_pids([debuggee_pid]),
                "children": child_rows,
                "children_count": len(child_rows),
                # True means the debuggee has more direct children than this
                # page; interact by pid rather than assuming the list is whole.
                "children_truncated": children_truncated,
                "child_candidates": probe_child_window_candidates(
                    debuggee_pid, list_windows_fn=None
                ),
                "note": (
                    "Read-only probe; pass allow_child_pids or "
                    "include_same_image_children to interact"
                ),
            }

        return self._ui_call(
            session_id,
            capability="ui.process_tree",
            allow_child_pids=allow_child_pids,
            ensure_running_for_interact=False,
            action=action,
        )
    def ui_tree(
        self,
        session_id: str,
        *,
        allow_child_pids: list[int] | None = None,
        max_depth: int = 3,
        max_nodes: int = 256,
        root_hwnd: int | None = None,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"uia", "uiautomation"}:
                if root_hwnd is None:
                    raise UiPidBoundaryError(
                        "invalid_params",
                        "ui.tree backend=uia requires root_hwnd",
                    )
                tree = build_uia_tree(
                    root_hwnd,
                    allowed,
                    max_depth=max_depth,
                    max_nodes=max_nodes,
                )
                return {
                    "debuggee_pid": ctx["debuggee_pid"],
                    "debugger_pid": ctx["debugger_pid"],
                    "allowed_pids": sorted(allowed),
                    "blocked_pids": sorted(ctx["blocked"]),
                    **tree,
                }
            if root_hwnd is not None:
                roots = [resolve_hwnd(allowed, hwnd=root_hwnd)]
            else:
                roots = list_windows_for_pids(sorted(allowed))
            tree = build_window_tree(
                roots,
                allowed,
                max_depth=max_depth,
                max_nodes=max_nodes,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(allowed),
                "blocked_pids": sorted(ctx["blocked"]),
                **tree,
                "backend": "win32_enum",
                "uia_available": uia_available(),
            }

        return self._ui_call(
            session_id,
            capability="ui.tree",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_resolve(
        self,
        session_id: str,
        *,
        hwnd: int | None = None,
        parent_hwnd: int | None = None,
        class_name: str | None = None,
        title: str | None = None,
        title_contains: str | None = None,
        control_id: int | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            window = resolve_hwnd(
                allowed,
                hwnd=hwnd,
                parent_hwnd=parent_hwnd,
                class_name=class_name,
                title=title,
                title_contains=title_contains,
                control_id=control_id,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "window": window,
                "backend": "win32_enum",
            }

        return self._ui_call(
            session_id,
            capability="ui.resolve",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_click(
        self,
        session_id: str,
        hwnd: int,
        *,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"uia", "uiautomation"}:
                result = click_hwnd_uia(hwnd, allowed)
            elif key in {"sendinput", "input"}:
                result = click_hwnd_sendinput(hwnd, allowed)
            else:
                result = click_hwnd(hwnd, allowed, timeout_ms=timeout_ms)
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.click",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_click_at(
        self,
        session_id: str,
        hwnd: int,
        x: int,
        y: int,
        *,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        """Background client-area click (PostMessage); does not steal foreground."""

        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = click_hwnd_at(
                hwnd, allowed, x=x, y=y, timeout_ms=timeout_ms
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.click_at",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_window_close(
        self,
        session_id: str,
        hwnd: int,
        *,
        method: str = "nc_close",
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        include_same_image_children: bool = False,
    ) -> Result[JsonObject]:
        """Close window via posted NC-click/WM_CLOSE; never SetForegroundWindow."""

        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = close_hwnd(
                hwnd, allowed, method=method, timeout_ms=timeout_ms
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.window.close",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_text_set(
        self,
        session_id: str,
        hwnd: int,
        text: str,
        *,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"uia", "uiautomation"}:
                result = set_value_uia(hwnd, text, allowed)
            else:
                result = set_window_text(hwnd, text, allowed, timeout_ms=timeout_ms)
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.text.set",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_key(
        self,
        session_id: str,
        hwnd: int,
        *,
        text: str | None = None,
        vk: int | None = None,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        backend: str = "win32",
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            key = (backend or "win32").strip().casefold()
            if key in {"sendinput", "input"}:
                result = send_key_sendinput(
                    hwnd,
                    allowed_pids=allowed,
                    text=text,
                    vk=vk,
                )
            else:
                result = send_key(
                    hwnd,
                    allowed_pids=allowed,
                    text=text,
                    vk=vk,
                    timeout_ms=timeout_ms,
                )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.key",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_invoke(
        self,
        session_id: str,
        hwnd: int,
        *,
        action_name: str = "click",
        text: str | None = None,
        control_id: int | None = None,
        allow_child_pids: list[int] | None = None,
        timeout_ms: int = 5_000,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = invoke_hwnd(
                hwnd,
                allowed,
                action=action_name,
                text=text,
                control_id=control_id,
                timeout_ms=timeout_ms,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
            }

        return self._ui_call(
            session_id,
            capability="ui.invoke",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def ui_wait(
        self,
        session_id: str,
        *,
        timeout: float = 10.0,
        poll_interval: float = 0.1,
        class_name: str | None = None,
        title: str | None = None,
        title_contains: str | None = None,
        control_id: int | None = None,
        parent_hwnd: int | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        def action(ctx: JsonObject) -> JsonObject:
            allowed = frozenset(ctx["allowed"])
            result = wait_for_window(
                allowed,
                timeout=timeout,
                poll_interval=poll_interval,
                class_name=class_name,
                title=title,
                title_contains=title_contains,
                control_id=control_id,
                parent_hwnd=parent_hwnd,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                **result,
                "backend": "win32_poll",
            }

        return self._ui_call(
            session_id,
            capability="ui.wait",
            allow_child_pids=allow_child_pids,
            include_same_image_children=include_same_image_children,
            action=action,
        )
    def _register_ui_capture(
        self,
        result: Result[JsonObject],
        session_id: str,
        path: Path,
        *,
        kind: str,
        source: str,
    ) -> Result[JsonObject]:
        """Register a captured bitmap in place, leaving the payload otherwise as is.

        These are uncompressed BMPs -- a full window is megabytes -- written per
        call under a fresh uuid, and until now they were registered nowhere. That
        made them both unreadable, because no tool opens a bare path, and
        unreclaimable, because retention only collects what the repository knows
        about. A UI-driving loop left behind gigabytes that nothing could see.
        """
        if not result.ok or result.data is None or not path.is_file():
            return result
        result.data.update(
            _register_capture(self, session_id, path, kind=kind, source=source, payload={})
        )
        return result

    def ui_screenshot(
        self,
        session_id: str,
        hwnd: int,
        *,
        allow_child_pids: list[int] | None = None,
        client_only: bool = False,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        """Capture a PID-bounded hwnd to a BMP under artifact_root/ui/<session>."""
        from headless_re_mcp.core.service import _is_safe_session_segment

        # Hostile input is rejected before the platform gate: a path-escaping
        # session id must read as invalid_request on every platform, not as a
        # platform limitation on Linux. The shared segment guard, not a bare
        # Path(...).name check: ".." passes the name comparison and collapses
        # the capture directory <root>/ui/<id> into the artifact root itself.
        if not _is_safe_session_segment(session_id):
            return _failure(
                ValueError("invalid session id for UI capture path"),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        if os.name != "nt":
            return _unsupported_ui(session_id, "ui.screenshot")
        directory = self.settings.artifact_root.expanduser().resolve() / "ui" / session_id
        artifact_path = directory / f"screenshot-{uuid4().hex}.bmp"

        def action(ctx: JsonObject) -> JsonObject:
            directory.mkdir(parents=True, exist_ok=True)
            allowed = frozenset(ctx["allowed"])
            result = capture_hwnd_screenshot(
                hwnd,
                allowed,
                artifact_path,
                client_only=client_only,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(allowed),
                **result,
            }

        return self._register_ui_capture(
            self._ui_call(
                session_id,
                capability="ui.screenshot",
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                action=action,
            ),
            session_id,
            artifact_path,
            kind="ui_screenshot",
            source="ui.screenshot",
        )
    def ui_ocr(
        self,
        session_id: str,
        hwnd: int,
        *,
        allow_child_pids: list[int] | None = None,
        backend: str = "auto",
        language: str = "en-US",
        client_only: bool = False,
        include_same_image_children: bool = False
    ) -> Result[JsonObject]:
        """OCR a PID-bounded hwnd via screenshot + Windows OCR / tesseract."""
        from headless_re_mcp.core.service import _is_safe_session_segment

        # Same ordering as ui_screenshot: reject hostile input before the
        # platform gate so invalid_request is platform-independent, and the
        # same shared segment guard so a lone ".." cannot collapse the capture
        # directory into the artifact root.
        if not _is_safe_session_segment(session_id):
            return _failure(
                ValueError("invalid session id for UI capture path"),
                session_id=session_id,
                backend=BackendKind.X64DBG.value,
            )
        if os.name != "nt":
            return _unsupported_ui(session_id, "ui.ocr")
        directory = self.settings.artifact_root.expanduser().resolve() / "ui" / session_id
        artifact_path = directory / f"ocr-{uuid4().hex}.bmp"

        def action(ctx: JsonObject) -> JsonObject:
            directory.mkdir(parents=True, exist_ok=True)
            allowed = frozenset(ctx["allowed"])
            result = ocr_hwnd(
                hwnd,
                allowed,
                artifact_path,
                backend=backend,
                language=language,
                client_only=client_only,
            )
            return {
                "debuggee_pid": ctx["debuggee_pid"],
                "debugger_pid": ctx["debugger_pid"],
                "allowed_pids": sorted(allowed),
                **result,
            }

        return self._register_ui_capture(
            self._ui_call(
                session_id,
                capability="ui.ocr",
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                action=action,
            ),
            session_id,
            artifact_path,
            kind="ui_ocr_capture",
            source="ui.ocr",
        )

    def _ui_call(
        self,
        session_id: str,
        *,
        capability: str,
        allow_child_pids: list[int] | None,
        action: Callable[[JsonObject], JsonObject],
        finalize: Callable[[JsonObject, JsonObject], JsonObject] | None = None,
        include_same_image_children: bool = False,
        ensure_running_for_interact: bool = True,
    ) -> Result[JsonObject]:
        if os.name != "nt":
            return _unsupported_ui(session_id, capability)
        _INTERACT = {
            "ui.click",
            "ui.click_at",
            "ui.window.close",
            "ui.text.set",
            "ui.key",
            "ui.invoke",
            "ui.drive_to_event",
            "ui.drive_to_breakpoint",
        }
        try:
            runtime = self._runtime(session_id, BackendKind.X64DBG)
            with runtime.lock:
                self._require_current_runtime(session_id, BackendKind.X64DBG, runtime)
                if "debug.state" not in runtime.worker.capabilities:
                    raise XdbgRpcError(
                        "capability_unavailable",
                        "backend does not provide debug.state",
                        details={"capability": "debug.state"},
                    )
                state = runtime.worker.request("debug.state", {})
                self._observe_debuggee_state(session_id, state)
                annotated = self._annotate_debuggee_pids(session_id, dict(state))
                debuggee_pid = annotated.get("debuggee_pid")
                debugger_pid = annotated.get("debugger_pid")
                if not isinstance(debuggee_pid, int) or debuggee_pid <= 0:
                    raise XdbgRpcError(
                        "invalid_state",
                        "no active debuggee; refuse UI automation",
                        details={
                            "process_id": annotated.get("process_id"),
                            "debuggee_pid": debuggee_pid,
                            "capability": capability,
                        },
                    )
                # Interact needs a live message pump; resume when paused.
                # Keep the wait short: PostMessage clicks only need the pump alive,
                # not a long running-state barrier (old 15s wait dominated UI latency).
                if (
                    ensure_running_for_interact
                    and capability in _INTERACT
                    and annotated.get("state") == "paused"
                    and "debug.resume" in runtime.worker.capabilities
                ):
                    runtime.worker.request("debug.resume", {}, timeout=5.0)
                    # Quoted so the protocol stays a typing-only import: it lives
                    # in service.py, which imports this module.
                    dynamic = cast("DynamicWorker", runtime.worker)
                    try:
                        running_state = dynamic.wait_for_state({"running"}, timeout=2.0)
                        self._observe_debuggee_state(session_id, running_state)
                        annotated = self._annotate_debuggee_pids(session_id, dict(running_state))
                        debuggee_pid = annotated.get("debuggee_pid") or debuggee_pid
                        debugger_pid = annotated.get("debugger_pid") or debugger_pid
                    except XdbgRpcError as exc:
                        # Still paused (e.g. immediate rebreak) — continue; click uses PostMessage.
                        if exc.code not in {"timeout", "wait_timeout", "debug_state_timeout"}:
                            raise XdbgRpcError(
                                "resume_failed",
                                f"failed to resume debuggee before {capability}: {exc}",
                                details={"capability": capability, "cause": exc.code},
                            ) from exc
                        state = runtime.worker.request("debug.state", {})
                        self._observe_debuggee_state(session_id, state)
                        annotated = self._annotate_debuggee_pids(session_id, dict(state))
                        debuggee_pid = annotated.get("debuggee_pid") or debuggee_pid
                        debugger_pid = annotated.get("debugger_pid") or debugger_pid
                try:
                    allowed, blocked = resolve_allowed_ui_pids(
                        debuggee_pid=int(debuggee_pid),
                        debugger_pid=(debugger_pid if isinstance(debugger_pid, int) else None),
                        allow_child_pids=allow_child_pids or (),
                        include_same_image_children=include_same_image_children,
                    )
                except UiPidBoundaryError as exc:
                    raise XdbgRpcError(exc.code, exc.message, details=dict(exc.details)) from exc
                ctx: JsonObject = {
                    "debuggee_pid": debuggee_pid,
                    "debugger_pid": debugger_pid,
                    "allowed": allowed,
                    "blocked": blocked,
                    "include_same_image_children": include_same_image_children,
                }
                try:
                    payload = action(ctx)
                except UiPidBoundaryError as exc:
                    details = dict(exc.details)
                    details.setdefault("debuggee_pid", debuggee_pid)
                    details.setdefault("allowed_pids", sorted(allowed))
                    raise XdbgRpcError(exc.code, exc.message, details=details) from exc
                if finalize is not None:
                    payload = finalize(payload, ctx)
                return _success(
                    payload,
                    session_id=session_id,
                    backend=BackendKind.X64DBG.value,
                    capability=capability,
                )
        except XdbgRpcError as exc:
            if exc.code in _FATAL_WORKER_ERRORS:
                self._fail_runtime(session_id, BackendKind.X64DBG, failure=exc)
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend=BackendKind.X64DBG.value)
