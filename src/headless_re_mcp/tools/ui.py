from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_ui_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="ui.windows.list")
    def ui_windows_list(
        session_id: str,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> dict[str, Any]:
        """List top-level windows for the session debuggee PID (opt-in children).

        Answers with windows, plus count, debuggee_pid, debugger_pid,
        allowed_pids, blocked_pids and note. There is no items field and
        no tree field. Child-process windows require allow_child_pids or
        include_same_image_children. The headless debugger PID and MCP host PID
        are always blocked.
        """
        return _dump(
            analysis.ui_windows_list(
                session_id,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
            )
        )

    @tools.tool(name="ui.process_tree")
    def ui_process_tree(
        session_id: str,
        allow_child_pids: list[int] | None = None,
    ) -> dict[str, Any]:
        """Read-only process-tree + window probe (does not grant UI rights).

        Answers with debuggee_windows, children, child_candidates, debuggee_pid,
        debugger_pid, debuggee_image and note. There is no tree field and
        no processes field.
        """
        return _dump(
            analysis.ui_process_tree(
                session_id,
                allow_child_pids=allow_child_pids,
            )
        )

    @tools.tool(name="ui.tree")
    def ui_tree(
        session_id: str,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        max_depth: Annotated[int, Field(ge=0, le=8)] = 3,
        max_nodes: Annotated[int, Field(ge=1, le=256)] = 256,
        root_hwnd: int | None = None,
        backend: str = "win32",
    ) -> dict[str, Any]:
        """Window/control tree for the debuggee PID (win32 or uia).

        Answers with nodes (each carrying children), count, truncated,
        max_depth and max_nodes. There is no tree or windows field.
        """
        return _dump(
            analysis.ui_tree(
                session_id,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                max_depth=max_depth,
                max_nodes=max_nodes,
                root_hwnd=root_hwnd,
                backend=backend,
            )
        )

    @tools.tool(name="ui.resolve")
    def ui_resolve(
        session_id: str,
        hwnd: int | None = None,
        parent_hwnd: int | None = None,
        class_name: str | None = None,
        title: str | None = None,
        title_contains: str | None = None,
        control_id: int | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> dict[str, Any]:
        """Resolve one window/control inside the debuggee PID boundary.

        Answers with window (hwnd, pid, class_name, title, visible, control_id,
        enabled), plus debuggee_pid, debugger_pid and backend.
        There is no hwnd field at the top level.
        """
        return _dump(
            analysis.ui_resolve(
                session_id,
                hwnd=hwnd,
                parent_hwnd=parent_hwnd,
                class_name=class_name,
                title=title,
                title_contains=title_contains,
                control_id=control_id,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
            )
        )

    @tools.tool(name="ui.click")
    def ui_click(
        session_id: str,
        hwnd: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
        backend: str = "win32",
    ) -> dict[str, Any]:
        """Click a control via win32/uia/sendinput (PID-bounded; SendInput rechecks FG PID).

        Answers with hwnd, action, backend, foreground_required and
        injection_required, plus debuggee_pid and debugger_pid.
        There is no clicked field.
        """
        return _dump(
            analysis.ui_click(
                session_id,
                hwnd,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                timeout_ms=timeout_ms,
                backend=backend,
            )
        )

    @tools.tool(name="ui.click_at")
    def ui_click_at(
        session_id: str,
        hwnd: int,
        x: int,
        y: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
    ) -> dict[str, Any]:
        """Background client-area click via PostMessage (no foreground steal, no injection).

        Answers with hwnd, action, x, y, backend, foreground_required and
        injection_required, plus debuggee_pid and debugger_pid. There is no
        clicked field.
        """
        return _dump(
            analysis.ui_click_at(
                session_id,
                hwnd,
                x,
                y,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                timeout_ms=timeout_ms,
            )
        )

    @tools.tool(name="ui.window.close")
    def ui_window_close(
        session_id: str,
        hwnd: int,
        method: str = "nc_close",
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
    ) -> dict[str, Any]:
        """Close via background NC X-click/SC_CLOSE/WM_CLOSE; never foreground it.

        Answers with hwnd, action, method, backend, shown_noactivate,
        foreground_required and injection_required, plus debuggee_pid and
        debugger_pid. There is no closed field.
        """
        return _dump(
            analysis.ui_window_close(
                session_id,
                hwnd,
                method=method,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                timeout_ms=timeout_ms,
            )
        )

    @tools.tool(name="ui.text.set")
    def ui_text_set(
        session_id: str,
        hwnd: int,
        text: Annotated[str, Field(max_length=4096)],
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
        backend: str = "win32",
    ) -> dict[str, Any]:
        """Set window text via WM_SETTEXT or UIA ValuePattern (PID-bounded).

        Answers with hwnd, action, text and backend, plus debuggee_pid and
        debugger_pid. There is no set field.
        """
        return _dump(
            analysis.ui_text_set(
                session_id,
                hwnd,
                text,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                timeout_ms=timeout_ms,
                backend=backend,
            )
        )

    @tools.tool(name="ui.key")
    def ui_key(
        session_id: str,
        hwnd: int,
        text: Annotated[str, Field(min_length=1, max_length=32)] | None = None,
        vk: Annotated[int, Field(ge=1, le=0xFE)] | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
        backend: str = "win32",
    ) -> dict[str, Any]:
        """Send key via WM_* or SendInput (PID-bounded; SendInput rechecks FG PID)."""
        return _dump(
            analysis.ui_key(
                session_id,
                hwnd,
                text=text,
                vk=vk,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                timeout_ms=timeout_ms,
                backend=backend,
            )
        )

    @tools.tool(name="ui.invoke")
    def ui_invoke(
        session_id: str,
        hwnd: int,
        action: str = "click",
        text: str | None = None,
        control_id: int | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
    ) -> dict[str, Any]:
        """Invoke a whitelisted Win32 action (click/set_text/command)."""
        return _dump(
            analysis.ui_invoke(
                session_id,
                hwnd,
                action_name=action,
                text=text,
                control_id=control_id,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                timeout_ms=timeout_ms,
            )
        )

    @tools.tool(name="ui.wait")
    def ui_wait(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 10.0,
        poll_interval: Annotated[float, Field(gt=0, le=5.0)] = 0.1,
        class_name: str | None = None,
        title: str | None = None,
        title_contains: str | None = None,
        control_id: int | None = None,
        parent_hwnd: int | None = None,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> dict[str, Any]:
        """Wait until a PID-bounded window matches the given selectors.

        Answers with matched, window (hwnd nested there), waited_ms and
        backend. There is no hwnd field at the top level and no found field.
        """
        return _dump(
            analysis.ui_wait(
                session_id,
                timeout=timeout,
                poll_interval=poll_interval,
                class_name=class_name,
                title=title,
                title_contains=title_contains,
                control_id=control_id,
                parent_hwnd=parent_hwnd,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
            )
        )

    @tools.tool(name="ui.screenshot")
    def ui_screenshot(
        session_id: str,
        hwnd: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        client_only: bool = False,
    ) -> dict[str, Any]:
        """Capture a debuggee-owned hwnd to BMP (PrintWindow/BitBlt, PID-bounded).

        Answers with format bmp, path, artifact, width, height, artifact_id,
        hwnd and action. There is no png field.
        """
        return _dump(
            analysis.ui_screenshot(
                session_id,
                hwnd,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                client_only=client_only,
            )
        )

    @tools.tool(name="ui.ocr")
    def ui_ocr(
        session_id: str,
        hwnd: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        backend: str = "auto",
        language: str = "en-US",
        client_only: bool = False,
    ) -> dict[str, Any]:
        """OCR a debuggee hwnd via screenshot + Windows OCR / tesseract (PID-bounded).

        Answers with text, lines, ocr_backend, artifact_id, format bmp and path.
        There is no ocr_text field.
        """
        return _dump(
            analysis.ui_ocr(
                session_id,
                hwnd,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                backend=backend,
                language=language,
                client_only=client_only,
            )
        )

    @tools.tool(name="ui.drive_to_event")
    def ui_drive_to_event(
        session_id: str,
        kind: str,
        fields: dict[str, Any] | None = None,
        steps: list[dict[str, Any]] | None = None,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
        event_budget: Annotated[int, Field(ge=1, le=100_000)] = 1024,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        accept_ui_goal: bool = True,
    ) -> dict[str, Any]:
        """Drive PID-bounded UI steps until a debug event or UI wait goal.

        Answers with ui_goal, steps, matched_event, events_seen, stopped and
        stop_reason. There is no matched field at the top level and no event
        field. A UI-goal finish can leave matched_event null.
        """
        return _dump(
            analysis.ui_drive_to_event(
                session_id,
                kind,
                fields=fields,
                steps=steps,
                timeout=timeout,
                event_budget=event_budget,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                accept_ui_goal=accept_ui_goal,
            )
        )

    @tools.tool(name="ui.drive_to_breakpoint")
    def ui_drive_to_breakpoint(
        session_id: str,
        intent_id: str,
        steps: list[dict[str, Any]] | None = None,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
        event_budget: Annotated[int, Field(ge=1, le=100_000)] = 1024,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        accept_ui_goal: bool = True,
    ) -> dict[str, Any]:
        """Drive UI until a workflow breakpoint intent hits (or UI goal)."""
        return _dump(
            analysis.ui_drive_to_breakpoint(
                session_id,
                intent_id,
                steps=steps,
                timeout=timeout,
                event_budget=event_budget,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                accept_ui_goal=accept_ui_goal,
            )
        )

    @tools.tool(name="ui.virtual_desktop.snapshot")
    def ui_virtual_desktop_snapshot(session_id: str) -> dict[str, Any]:
        """Passive PID-bounded snapshot of the session's hidden Win32 desktop.

        Lists debuggee-owned windows without switching the input desktop; requires
        the x64dbg worker started under HEADLESS_RE_HIDDEN_DESKTOP.
        """
        return _dump(analysis.virtual_desktop_snapshot(session_id))

    @tools.tool(name="ui.virtual_desktop.capture")
    def ui_virtual_desktop_capture(
        session_id: str,
        hwnd: int | None = None,
    ) -> dict[str, Any]:
        """Capture one authorized hidden-desktop window to BMP on demand.

        Never switches the input desktop and flags degraded (blank/uniform) frames
        instead of silently falling back; selects the top visible window when hwnd
        is omitted.
        """
        return _dump(analysis.virtual_desktop_capture(session_id, hwnd=hwnd))
    return tools.bindings
