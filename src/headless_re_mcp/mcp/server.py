from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from headless_re_mcp.core.events import DEFAULT_DEBUG_EVENT_BATCH, MAX_DEBUG_EVENT_BATCH
from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.detection.models import ScanMode
from headless_re_mcp.mcp.registry import (
    register_core_session_tools,
    register_detect_tools,
    register_dotnet_tools,
    register_static_core_tools,
    register_static_extended_tools,
    register_workflow_tools,
)


def create_server(service: AnalysisService | None = None) -> FastMCP[None]:
    analysis = service or AnalysisService()
    server: FastMCP[None] = FastMCP(
        "Headless RE-MCP",
        instructions=(
            "Create a session for an authorized local PE, then open its static IDA "
            "backend, dynamic x64dbg backend, or both. Dynamic tools expose only "
            "bounded debugger operations; arbitrary x64dbg commands are unavailable. "
            "Every tool returns an ok/data/error/meta envelope. Close sessions when finished."
        ),
    )
    register_core_session_tools(server, analysis)
    register_static_core_tools(server, analysis)

    register_detect_tools(server, analysis)
    register_static_extended_tools(server, analysis)
    register_workflow_tools(server, analysis)
    register_dotnet_tools(server, analysis)




    @server.tool(name="unpack.upx.test", structured_output=True)
    def unpack_upx_test(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
    ) -> dict[str, Any]:
        """Run official ``upx -t`` on the session binary without modifying the input."""
        return _dump(analysis.unpack_upx_test(session_id, timeout=timeout))

    @server.tool(name="unpack.upx.unpack", structured_output=True)
    def unpack_upx_unpack(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
        open_ida: bool = False,
    ) -> dict[str, Any]:
        """Decompress with official ``upx -d`` into a session artifact path."""
        return _dump(
            analysis.unpack_upx_unpack(
                session_id,
                timeout=timeout,
                open_ida=open_ida,
            )
        )

    @server.tool(name="unpack.external.probe", structured_output=True)
    def unpack_external_probe(session_id: str) -> dict[str, Any]:
        """Probe optional user-configured XVLKC / VMP dumper / Scylla without running them."""
        return _dump(analysis.unpack_external_probe(session_id))

    @server.tool(name="unpack.xvlkc.unpack", structured_output=True)
    def unpack_xvlkc_unpack(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0,
    ) -> dict[str, Any]:
        """Optional XVLKC unpack into a session artifact; never overwrite input."""
        return _dump(analysis.unpack_xvlkc_unpack(session_id, timeout=timeout))

    @server.tool(name="unpack.vmp.dump", structured_output=True)
    def unpack_vmp_dump(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0,
        module_name: str | None = None,
        entry_point_rva: int | None = None,
        disable_reloc: bool = False,
        pid: int | None = None,
    ) -> dict[str, Any]:
        """Optional upstream VMPDump (0xnobody/vmpdump, GPL-3.0, x64) against live debuggee.

        Requires HEADLESS_RE_VMP_DUMPER and an active debuggee PID. Reports
        dump_ok/imports_rebuilt/vm_restored separately; never claims universal unpack.
        """
        return _dump(
            analysis.unpack_vmp_dump(
                session_id,
                timeout=timeout,
                module_name=module_name,
                entry_point_rva=entry_point_rva,
                disable_reloc=disable_reloc,
                pid=pid,
            )
        )
    @server.tool(name="unpack.scylla.rebuild", structured_output=True)
    def unpack_scylla_rebuild(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0,
    ) -> dict[str, Any]:
        """Optional Scylla IAT/dump helper into a session artifact; never overwrite input."""
        return _dump(analysis.unpack_scylla_rebuild(session_id, timeout=timeout))

    @server.tool(name="unpack.auto", structured_output=True)
    def unpack_auto(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
        open_ida: bool = False,
    ) -> dict[str, Any]:
        """Route detection to official UPX unpack when appropriate; never fake success."""
        return _dump(
            analysis.unpack_auto(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
                open_ida=open_ida,
            )
        )

    @server.tool(name="unpack.plan", structured_output=True)
    def unpack_plan(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
        force_route: str | None = None,
    ) -> dict[str, Any]:
        """Build a non-authoritative unpack plan without executing side effects."""
        return _dump(
            analysis.unpack_plan(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
                force_route=force_route,
            )
        )

    @server.tool(name="unpack.start", structured_output=True)
    def unpack_start(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 300.0,
        open_ida: bool = False,
        execute_upx: bool = True,
        replace: bool = False,
        force_route: str | None = None,
    ) -> dict[str, Any]:
        """Start unpack orchestration (UPX executes; dynamic routes wait for OEP confirm).

        Active sessions are not overwritten unless replace=True.
        Optional force_route overrides detection (e.g. bounded_dynamic when DIE misses VMP).
        """
        return _dump(
            analysis.unpack_start(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
                open_ida=open_ida,
                execute_upx=execute_upx,
                replace=replace,
                force_route=force_route,
            )
        )

    @server.tool(name="unpack.status", structured_output=True)
    def unpack_status(session_id: str) -> dict[str, Any]:
        """Return the current unpack orchestration state and timeline summary."""
        return _dump(analysis.unpack_status(session_id))

    @server.tool(name="unpack.cancel", structured_output=True)
    def unpack_cancel(
        session_id: str,
        reason: str = "cancelled by caller",
    ) -> dict[str, Any]:
        """Cancel unpack orchestration; original input is never overwritten."""
        return _dump(analysis.unpack_cancel(session_id, reason=reason))

    @server.tool(name="unpack.artifacts", structured_output=True)
    def unpack_artifacts(session_id: str) -> dict[str, Any]:
        """List unpack session artifacts and timeline/state paths."""
        return _dump(analysis.unpack_artifacts(session_id))

    @server.tool(name="unpack.score_oep", structured_output=True)
    def unpack_score_oep(
        session_id: str,
        module_base: int,
        module_size: int,
        observations: list[dict[str, Any]] | None = None,
        max_candidates: int = 8,
        imports_resolved_hint: bool = False,
    ) -> dict[str, Any]:
        """Score multi-signal OEP candidates; never treats a single heuristic as confirmed.

        When observations are omitted/empty, attempts auto-collection from the dynamic
        backend (registers + memory regions). Never auto-confirms OEP.
        """
        return _dump(
            analysis.unpack_score_oep(
                session_id,
                module_base=module_base,
                module_size=module_size,
                observations=observations,
                max_candidates=max_candidates,
                imports_resolved_hint=imports_resolved_hint,
            )
        )

    @server.tool(name="unpack.confirm_oep", structured_output=True)
    def unpack_confirm_oep(
        session_id: str,
        oep_rva: int,
        candidate_id: str | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        module_base: int | None = None,
        auto_dump: bool = False,
        dump_timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Record caller-confirmed OEP; set auto_dump to also dump and enter dumped phase."""
        return _dump(
            analysis.unpack_confirm_oep(
                session_id,
                oep_rva=oep_rva,
                candidate_id=candidate_id,
                iat_va=iat_va,
                iat_size=iat_size,
                module_base=module_base,
                auto_dump=auto_dump,
                dump_timeout=dump_timeout,
            )
        )

    @server.tool(name="dynamic.open", structured_output=True)
    def dynamic_open(session_id: str) -> dict[str, Any]:
        """Open the matching x86/x64 official x64dbg headless RPC backend."""
        return _dump(analysis.open_dynamic(session_id))

    @server.tool(name="dynamic.state", structured_output=True)
    def dynamic_state(session_id: str) -> dict[str, Any]:
        """Return idle/running/paused state plus debuggee_pid vs debugger_pid."""
        return _dump(analysis.dynamic_state(session_id))

    @server.tool(name="ui.windows.list", structured_output=True)
    def ui_windows_list(
        session_id: str,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
    ) -> dict[str, Any]:
        """List top-level windows for the session debuggee PID (opt-in children).

        Child-process windows require allow_child_pids or include_same_image_children.
        The headless debugger PID and MCP host PID are always blocked.
        """
        return _dump(
            analysis.ui_windows_list(
                session_id,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
            )
        )

    @server.tool(name="ui.process_tree", structured_output=True)
    def ui_process_tree(
        session_id: str,
        allow_child_pids: list[int] | None = None,
    ) -> dict[str, Any]:
        """Read-only process-tree + window probe (does not grant UI rights)."""
        return _dump(
            analysis.ui_process_tree(
                session_id,
                allow_child_pids=allow_child_pids,
            )
        )

    @server.tool(name="ui.tree", structured_output=True)
    def ui_tree(
        session_id: str,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        max_depth: Annotated[int, Field(ge=0, le=8)] = 3,
        max_nodes: Annotated[int, Field(ge=1, le=256)] = 256,
        root_hwnd: int | None = None,
        backend: str = "win32",
    ) -> dict[str, Any]:
        """Return a bounded window/control tree (win32 or uia) for the debuggee PID."""
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

    @server.tool(name="ui.resolve", structured_output=True)
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
        """Resolve one window/control inside the debuggee PID boundary."""
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

    @server.tool(name="ui.click", structured_output=True)
    def ui_click(
        session_id: str,
        hwnd: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
        backend: str = "win32",
    ) -> dict[str, Any]:
        """Click a control via win32/uia/sendinput (PID-bounded; SendInput rechecks FG PID)."""
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

    @server.tool(name="ui.click_at", structured_output=True)
    def ui_click_at(
        session_id: str,
        hwnd: int,
        x: int,
        y: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
    ) -> dict[str, Any]:
        """Background client-area click via PostMessage (no foreground steal, no injection)."""
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

    @server.tool(name="ui.window.close", structured_output=True)
    def ui_window_close(
        session_id: str,
        hwnd: int,
        method: str = "nc_close",
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
    ) -> dict[str, Any]:
        """Close a window in background (NC X-click / SC_CLOSE / WM_CLOSE); no SetForegroundWindow."""
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

    @server.tool(name="ui.text.set", structured_output=True)
    def ui_text_set(
        session_id: str,
        hwnd: int,
        text: str,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        timeout_ms: Annotated[int, Field(ge=1, le=30_000)] = 5_000,
        backend: str = "win32",
    ) -> dict[str, Any]:
        """Set window text via WM_SETTEXT or UIA ValuePattern (PID-bounded)."""
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

    @server.tool(name="ui.key", structured_output=True)
    def ui_key(
        session_id: str,
        hwnd: int,
        text: str | None = None,
        vk: int | None = None,
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

    @server.tool(name="ui.invoke", structured_output=True)
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

    @server.tool(name="ui.wait", structured_output=True)
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
        """Wait until a PID-bounded window matches the given selectors."""
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

    @server.tool(name="ui.screenshot", structured_output=True)
    def ui_screenshot(
        session_id: str,
        hwnd: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        client_only: bool = False,
    ) -> dict[str, Any]:
        """Capture a debuggee-owned hwnd to BMP (PrintWindow/BitBlt, PID-bounded)."""
        return _dump(
            analysis.ui_screenshot(
                session_id,
                hwnd,
                allow_child_pids=allow_child_pids,
                include_same_image_children=include_same_image_children,
                client_only=client_only,
            )
        )

    @server.tool(name="ui.ocr", structured_output=True)
    def ui_ocr(
        session_id: str,
        hwnd: int,
        allow_child_pids: list[int] | None = None,
        include_same_image_children: bool = False,
        backend: str = "auto",
        language: str = "en-US",
        client_only: bool = False,
    ) -> dict[str, Any]:
        """OCR a debuggee hwnd via screenshot + Windows OCR / tesseract (PID-bounded)."""
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

    @server.tool(name="dynamic.events", structured_output=True)
    def dynamic_events(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=MAX_DEBUG_EVENT_BATCH)] = (
            DEFAULT_DEBUG_EVENT_BATCH
        ),
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 10.0,
    ) -> dict[str, Any]:
        """Read the next bounded debugger callback batch for this session."""
        return _dump(
            analysis.dynamic_events(session_id, limit=limit, timeout=timeout)
        )

    @server.tool(name="dynamic.wait", structured_output=True)
    def dynamic_wait(
        session_id: str,
        state: str,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Wait with a bound until the debugger reaches idle, running, or paused."""
        return _dump(analysis.dynamic_wait(session_id, state, timeout=timeout))

    @server.tool(name="dynamic.launch", structured_output=True)
    def dynamic_launch(
        session_id: str,
        arguments: str = "",
        working_directory: str | None = None,
        timeout: float = 30.0,
        pass_system_breakpoint: bool = False,
    ) -> dict[str, Any]:
        """Launch the session binary and wait for its initial debugger pause.

        When pass_system_breakpoint is true, resume once after the first pause
        (typical system/entry breakpoint) so unpack workflows can continue.
        """
        return _dump(
            analysis.dynamic_launch(
                session_id,
                arguments=arguments,
                working_directory=working_directory,
                timeout=timeout,
                pass_system_breakpoint=pass_system_breakpoint,
            )
        )

    @server.tool(name="dynamic.attach", structured_output=True)
    def dynamic_attach(
        session_id: str,
        pid: int,
        timeout: float = 30.0,
        pause_after_attach: bool = False,
    ) -> dict[str, Any]:
        """Attach to an authorized process; default waits for paused|running (GUI-friendly)."""
        return _dump(
            analysis.dynamic_attach(
                session_id,
                pid,
                timeout=timeout,
                pause_after_attach=pause_after_attach,
            )
        )

    @server.tool(name="dynamic.stop", structured_output=True)
    def dynamic_stop(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Stop the active debuggee and wait until the backend is idle."""
        return _dump(analysis.dynamic_stop(session_id, timeout=timeout))

    @server.tool(name="dynamic.pause", structured_output=True)
    def dynamic_pause(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Pause the active debuggee and wait for a stable paused state."""
        return _dump(analysis.dynamic_pause(session_id, timeout=timeout))

    @server.tool(name="dynamic.resume", structured_output=True)
    def dynamic_resume(
        session_id: str,
        wait_for_pause: bool = False,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Resume the debuggee, optionally waiting for its next pause or exit."""
        return _dump(
            analysis.dynamic_resume(
                session_id,
                wait_for_pause=wait_for_pause,
                timeout=timeout,
            )
        )

    @server.tool(name="dynamic.step_into", structured_output=True)
    def dynamic_step_into(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Execute one step into and wait for the next pause or process exit."""
        return _dump(analysis.dynamic_step_into(session_id, timeout=timeout))

    @server.tool(name="dynamic.step_over", structured_output=True)
    def dynamic_step_over(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Execute one step over and wait for the next pause or process exit."""
        return _dump(analysis.dynamic_step_over(session_id, timeout=timeout))

    @server.tool(name="dynamic.registers.read", structured_output=True)
    def dynamic_registers_read(session_id: str) -> dict[str, Any]:
        """Read the bounded general-purpose register set from a paused debuggee."""
        return _dump(analysis.dynamic_registers_read(session_id))

    @server.tool(name="dynamic.registers.write", structured_output=True)
    def dynamic_registers_write(
        session_id: str,
        name: str,
        value: int,
    ) -> dict[str, Any]:
        """Write one allowlisted architecture register on a paused debuggee."""
        return _dump(analysis.dynamic_register_write(session_id, name, value))

    @server.tool(name="dynamic.memory.read", structured_output=True)
    def dynamic_memory_read(
        session_id: str,
        address: int,
        size: int,
    ) -> dict[str, Any]:
        """Read up to 2 MiB from a paused debuggee as hexadecimal bytes."""
        return _dump(analysis.dynamic_memory_read(session_id, address, size))

    @server.tool(name="dynamic.memory.write", structured_output=True)
    def dynamic_memory_write(
        session_id: str,
        address: int,
        data: str,
    ) -> dict[str, Any]:
        """Write bounded hexadecimal bytes to an authorized paused debuggee."""
        return _dump(analysis.dynamic_memory_write(session_id, address, data))

    @server.tool(name="memory.regions", structured_output=True)
    def memory_regions(
        session_id: str,
        offset: int = 0,
        limit: int | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """List paused-only VirtualQuery-style memory regions with pagination."""
        return _dump(
            analysis.memory_regions(
                session_id,
                offset=offset,
                limit=limit,
                timeout=timeout,
            )
        )

    @server.tool(name="memory.protect.query", structured_output=True)
    def memory_protect_query(
        session_id: str,
        address: int,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Query the memory region containing one address on a paused debuggee."""
        return _dump(
            analysis.memory_protect_query(session_id, address, timeout=timeout)
        )

    @server.tool(name="memory.protection", structured_output=True)
    def memory_protection(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        rights: str | None = None,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Query memory protection or optionally set allowlisted page rights."""
        return _dump(
            analysis.memory_protection(
                session_id, address, rights=rights, timeout=timeout
            )
        )

    @server.tool(name="threads.list", structured_output=True)
    def threads_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List debuggee threads."""
        return _dump(analysis.threads_list(session_id, timeout=timeout))

    @server.tool(name="threads.current", structured_output=True)
    def threads_current(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Return the current debuggee thread."""
        return _dump(analysis.threads_current(session_id, timeout=timeout))

    @server.tool(name="threads.context.read", structured_output=True)
    def threads_context_read(
        session_id: str,
        tid: Annotated[int, Field(ge=1)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read allowlisted registers for one thread, restoring the prior TID."""
        return _dump(analysis.threads_context_read(session_id, tid, timeout=timeout))

    @server.tool(name="threads.context.write", structured_output=True)
    def threads_context_write(
        session_id: str,
        tid: Annotated[int, Field(ge=1)],
        name: str,
        value: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Write one allowlisted register on a thread, restoring the prior TID."""
        return _dump(
            analysis.threads_context_write(
                session_id, tid, name, value, timeout=timeout
            )
        )

    @server.tool(name="stack.read", structured_output=True)
    def stack_read(
        session_id: str,
        address: Annotated[int, Field(ge=0)] | None = None,
        count: Annotated[int, Field(ge=1, le=256)] = 32,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read pointer-sized stack words from CSP or an explicit address."""
        return _dump(
            analysis.stack_read(
                session_id, address=address, count=count, timeout=timeout
            )
        )

    @server.tool(name="stack.trace", structured_output=True)
    def stack_trace(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=256)] = 256,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Return a bounded call stack for the paused debuggee."""
        return _dump(analysis.stack_trace(session_id, limit=limit, timeout=timeout))

    @server.tool(name="disassembly.read", structured_output=True)
    def disassembly_read(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        count: Annotated[int, Field(ge=1, le=256)] = 32,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble a bounded instruction range starting at address."""
        return _dump(
            analysis.disassembly_read(
                session_id, address, count=count, timeout=timeout
            )
        )

    @server.tool(name="symbols.list", structured_output=True)
    def symbols_list(
        session_id: str,
        module_base: Annotated[int, Field(ge=1)],
        limit: Annotated[int, Field(ge=1, le=4096)] = 256,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Enumerate a bounded symbol list for one loaded module."""
        return _dump(
            analysis.symbols_list(
                session_id, module_base, limit=limit, timeout=timeout
            )
        )

    @server.tool(name="symbols.resolve", structured_output=True)
    def symbols_resolve(
        session_id: str,
        expression: Annotated[str, Field(min_length=1, max_length=512)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Resolve a structured expression/symbol to an address."""
        return _dump(
            analysis.symbols_resolve(session_id, expression, timeout=timeout)
        )

    @server.tool(name="modules.dump", structured_output=True)
    def modules_dump(
        session_id: str,
        base: int,
        size: int | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Dump one loaded module into a session artifact path (no raw bytes over MCP)."""
        return _dump(
            analysis.modules_dump(session_id, base, size=size, timeout=timeout)
        )

    @server.tool(name="pe.headers.runtime", structured_output=True)
    def pe_headers_runtime(
        session_id: str,
        base: int,
        save_artifact: bool = True,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Read paused-only runtime PE headers and optionally keep a header artifact."""
        return _dump(
            analysis.pe_headers_runtime(
                session_id,
                base,
                save_artifact=save_artifact,
                timeout=timeout,
            )
        )

    @server.tool(name="imports.scan", structured_output=True)
    def imports_scan(
        session_id: str,
        module_base: int,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int = 8,
        mode: str = "all",
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Scan IAT candidates (consecutive/sparse/call_site/all); never blind-selects."""
        return _dump(
            analysis.imports_scan(
                session_id,
                module_base,
                search_start=search_start,
                search_size=search_size,
                max_candidates=max_candidates,
                mode=mode,
                timeout=timeout,
            )
        )

    @server.tool(name="imports.read", structured_output=True)
    def imports_read(
        session_id: str,
        iat_va: int,
        size: int,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Read one confirmed IAT range and resolve thunks against loaded exports."""
        return _dump(
            analysis.imports_read(session_id, iat_va, size, timeout=timeout)
        )

    @server.tool(name="unpack.dump_module", structured_output=True)
    def unpack_dump_module(
        session_id: str,
        base: int,
        size: int | None = None,
        save_headers: bool = True,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Dump module by runtime size and preserve PE headers for later rebuild."""
        return _dump(
            analysis.unpack_dump_module(
                session_id,
                base,
                size=size,
                save_headers=save_headers,
                timeout=timeout,
            )
        )

    @server.tool(name="unpack.stub_coupling", structured_output=True)
    def unpack_stub_coupling(
        session_id: str,
        dump_path: str,
        iat_va: int | None = None,
        iat_size: int | None = None,
        module_base: int | None = None,
    ) -> dict[str, Any]:
        """Count E8→VMP stub calls vs FF15/FF25 API sites on a dump (fail-closed hint)."""
        return _dump(
            analysis.unpack_stub_coupling(
                session_id,
                dump_path,
                iat_va=iat_va,
                iat_size=iat_size,
                module_base=module_base,
            )
        )

    @server.tool(name="unpack.iat.scan", structured_output=True)
    def unpack_iat_scan(
        session_id: str,
        module_base: int,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int = 8,
        mode: str = "all",
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """List IAT candidates (consecutive/sparse/call_site); caller must confirm before rebuild."""
        return _dump(
            analysis.unpack_iat_scan(
                session_id,
                module_base,
                search_start=search_start,
                search_size=search_size,
                max_candidates=max_candidates,
                mode=mode,
                timeout=timeout,
            )
        )

    @server.tool(name="unpack.iat.validate", structured_output=True)
    def unpack_iat_validate(
        session_id: str,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        module_base: int | None = None,
        dump_path: str | None = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Validate a caller-confirmed IAT VA/size and optional OEP RVA."""
        return _dump(
            analysis.unpack_iat_validate(
                session_id,
                iat_va=iat_va,
                size=size,
                oep_rva=oep_rva,
                module_base=module_base,
                dump_path=dump_path,
                timeout=timeout,
            )
        )

    @server.tool(name="unpack.iat.rebuild", structured_output=True)
    def unpack_iat_rebuild(
        session_id: str,
        dump_path: str,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Rebuild import tables on a dumped PE using a confirmed IAT range."""
        return _dump(
            analysis.unpack_iat_rebuild(
                session_id,
                dump_path,
                iat_va=iat_va,
                size=size,
                oep_rva=oep_rva,
                timeout=timeout,
            )
        )

    @server.tool(name="unpack.pe.rebuild", structured_output=True)
    def unpack_pe_rebuild(
        session_id: str,
        dump_path: str,
        entry_point_rva: int | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        timeout: float = 60.0,
    ) -> dict[str, Any]:
        """Remap a runtime dump to file layout and optionally rebuild imports."""
        return _dump(
            analysis.unpack_pe_rebuild(
                session_id,
                dump_path,
                entry_point_rva=entry_point_rva,
                iat_va=iat_va,
                iat_size=iat_size,
                timeout=timeout,
            )
        )

    @server.tool(name="unpack.verify", structured_output=True)
    def unpack_verify(
        session_id: str,
        path: str,
        use_die: bool = True,
        open_ida: bool = False,
        baseline_session_id: str | None = None,
        timeout: float = 60.0,
        expect_window_title: str | None = None,
        expect_window_class: str | None = None,
        ui_pid: int | None = None,
    ) -> dict[str, Any]:
        """Verify a rebuilt PE; optional UI title/class gates need ui_pid or live debuggee."""
        return _dump(
            analysis.unpack_verify(
                session_id,
                path,
                use_die=use_die,
                open_ida=open_ida,
                baseline_session_id=baseline_session_id,
                timeout=timeout,
                expect_window_title=expect_window_title,
                expect_window_class=expect_window_class,
                ui_pid=ui_pid,
            )
        )

    @server.tool(name="dynamic.modules", structured_output=True)
    def dynamic_modules(session_id: str) -> dict[str, Any]:
        """List loaded image modules for a paused debuggee."""
        return _dump(analysis.dynamic_modules(session_id))

    @server.tool(name="modules.list", structured_output=True)
    def modules_list(session_id: str) -> dict[str, Any]:
        """Return the validated current runtime module catalog without hashing files."""
        return _dump(analysis.module_catalog(session_id))

    @server.tool(name="modules.resolve", structured_output=True)
    def modules_resolve(
        session_id: str,
        selector: ModuleSelector,
    ) -> dict[str, Any]:
        """Resolve one loaded module and verify its PE identity and rebase metadata."""
        return _dump(analysis.module_resolve(session_id, selector))

    @server.tool(name="dynamic.breakpoints", structured_output=True)
    def dynamic_breakpoints(session_id: str) -> dict[str, Any]:
        """List debugger breakpoints for the active debuggee."""
        return _dump(analysis.dynamic_breakpoints(session_id))

    @server.tool(name="dynamic.breakpoint.set", structured_output=True)
    def dynamic_breakpoint_set(session_id: str, address: int) -> dict[str, Any]:
        """Set a software breakpoint at an address in a paused debuggee."""
        return _dump(analysis.dynamic_breakpoint_set(session_id, address))

    @server.tool(name="dynamic.breakpoint.remove", structured_output=True)
    def dynamic_breakpoint_remove(session_id: str, address: int) -> dict[str, Any]:
        """Remove a software breakpoint from an address in a paused debuggee."""
        return _dump(analysis.dynamic_breakpoint_remove(session_id, address))

    @server.tool(name="breakpoints.hardware.set", structured_output=True)
    def breakpoints_hardware_set(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        bp_type: Annotated[str, Field(pattern="^(r|w|x|rw|access|write|execute)$")] = "x",
        size: Annotated[int, Field(ge=1, le=8)] = 1,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Set a hardware breakpoint with structured type/size enums only."""
        return _dump(
            analysis.breakpoints_hardware_set(
                session_id,
                address,
                bp_type=bp_type,
                size=size,
                timeout=timeout,
            )
        )

    @server.tool(name="breakpoints.hardware.remove", structured_output=True)
    def breakpoints_hardware_remove(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Remove a hardware breakpoint."""
        return _dump(
            analysis.breakpoints_hardware_remove(session_id, address, timeout=timeout)
        )

    @server.tool(name="breakpoints.hardware.list", structured_output=True)
    def breakpoints_hardware_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List hardware breakpoints."""
        return _dump(analysis.breakpoints_hardware_list(session_id, timeout=timeout))

    @server.tool(name="breakpoints.memory.set", structured_output=True)
    def breakpoints_memory_set(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        bp_type: Annotated[
            str, Field(pattern="^(a|r|w|x|access|read|write|execute|rwx)$")
        ] = "a",
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Set a memory breakpoint with structured type enum only."""
        return _dump(
            analysis.breakpoints_memory_set(
                session_id, address, bp_type=bp_type, timeout=timeout
            )
        )

    @server.tool(name="breakpoints.memory.remove", structured_output=True)
    def breakpoints_memory_remove(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Remove a memory breakpoint."""
        return _dump(
            analysis.breakpoints_memory_remove(session_id, address, timeout=timeout)
        )

    @server.tool(name="breakpoints.memory.list", structured_output=True)
    def breakpoints_memory_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List memory breakpoints."""
        return _dump(analysis.breakpoints_memory_list(session_id, timeout=timeout))

    @server.tool(name="breakpoints.condition.set", structured_output=True)
    def breakpoints_condition_set(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        expression: Annotated[str, Field(min_length=1, max_length=512)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Set a sanitized break condition on an existing breakpoint."""
        return _dump(
            analysis.breakpoints_condition_set(
                session_id, address, expression, timeout=timeout
            )
        )

    @server.tool(name="breakpoints.condition.get", structured_output=True)
    def breakpoints_condition_get(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read the break condition for an existing breakpoint."""
        return _dump(
            analysis.breakpoints_condition_get(session_id, address, timeout=timeout)
        )

    @server.tool(name="patches.list", structured_output=True)
    def patches_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List recorded memory patches."""
        return _dump(analysis.patches_list(session_id, timeout=timeout))

    @server.tool(name="patches.apply", structured_output=True)
    def patches_apply(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        data: Annotated[str, Field(min_length=2, max_length=512)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Apply a bounded hex patch through MemPatch."""
        return _dump(
            analysis.patches_apply(session_id, address, data, timeout=timeout)
        )

    @server.tool(name="patches.restore", structured_output=True)
    def patches_restore(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Restore one recorded patch."""
        return _dump(analysis.patches_restore(session_id, address, timeout=timeout))

    @server.tool(name="trace.start", structured_output=True)
    def trace_start(
        session_id: str,
        path: Annotated[str, Field(min_length=1, max_length=32767)],
        max_events: Annotated[int, Field(ge=1, le=1_000_000)] = 10_000,
        timeout_ms: Annotated[int, Field(ge=1, le=3_600_000)] = 60_000,
        max_file_bytes: Annotated[int, Field(ge=1, le=268_435_456)] = 16_777_216,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Start run-trace recording to an absolute path with quotas."""
        return _dump(
            analysis.trace_start(
                session_id,
                path,
                max_events=max_events,
                timeout_ms=timeout_ms,
                max_file_bytes=max_file_bytes,
                timeout=timeout,
            )
        )

    @server.tool(name="trace.stop", structured_output=True)
    def trace_stop(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Stop run-trace recording."""
        return _dump(analysis.trace_stop(session_id, timeout=timeout))

    @server.tool(name="trace.status", structured_output=True)
    def trace_status(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Report run-trace recording status and quotas."""
        return _dump(analysis.trace_status(session_id, timeout=timeout))

    @server.tool(name="sync.static_to_runtime", structured_output=True)
    def sync_static_to_runtime(session_id: str, address: int) -> dict[str, Any]:
        """Map an IDA address to the matching loaded main-module runtime address."""
        return _dump(analysis.sync_static_to_runtime(session_id, address))

    @server.tool(name="sync.runtime_to_static", structured_output=True)
    def sync_runtime_to_static(session_id: str, address: int) -> dict[str, Any]:
        """Map a loaded main-module runtime address back to its IDA address."""
        return _dump(analysis.sync_runtime_to_static(session_id, address))

    @server.tool(name="sync.module_preferred_to_runtime", structured_output=True)
    def sync_module_preferred_to_runtime(
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> dict[str, Any]:
        """Map an explicitly selected PE preferred VA to its current runtime VA."""
        return _dump(
            analysis.sync_module_preferred_to_runtime(session_id, selector, address)
        )

    @server.tool(name="sync.module_runtime_to_preferred", structured_output=True)
    def sync_module_runtime_to_preferred(
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> dict[str, Any]:
        """Map an explicitly selected runtime VA back to its PE preferred VA."""
        return _dump(
            analysis.sync_module_runtime_to_preferred(session_id, selector, address)
        )


    @server.tool(name="ui.drive_to_event", structured_output=True)
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
        """Drive PID-bounded UI steps until a debug event or UI wait goal."""
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

    @server.tool(name="ui.drive_to_breakpoint", structured_output=True)
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

    @server.tool(name="capabilities.search", structured_output=True)
    def capabilities_search(
        backend: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        """Search discovered backend capabilities and readiness."""
        return _dump(analysis.capabilities_search(backend=backend, status=status))

    @server.tool(name="capabilities.describe", structured_output=True)
    def capabilities_describe(capability_id: str) -> dict[str, Any]:
        """Describe one capability id from the catalog."""
        return _dump(analysis.capabilities_describe(capability_id))

    @server.tool(name="r2.info", structured_output=True)
    def r2_info(session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0) -> dict[str, Any]:
        return _dump(analysis.r2_info(session_id, timeout=timeout))

    @server.tool(name="r2.open", structured_output=True)
    def r2_open(session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0) -> dict[str, Any]:
        return _dump(analysis.r2_open(session_id, timeout=timeout))

    @server.tool(name="r2.functions", structured_output=True)
    def r2_functions(session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0) -> dict[str, Any]:
        return _dump(analysis.r2_functions(session_id, timeout=timeout))

    @server.tool(name="r2.strings", structured_output=True)
    def r2_strings(session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0) -> dict[str, Any]:
        return _dump(analysis.r2_strings(session_id, timeout=timeout))

    @server.tool(name="r2.imports", structured_output=True)
    def r2_imports(session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0) -> dict[str, Any]:
        return _dump(analysis.r2_imports(session_id, timeout=timeout))

    @server.tool(name="r2.exports", structured_output=True)
    def r2_exports(session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0) -> dict[str, Any]:
        return _dump(analysis.r2_exports(session_id, timeout=timeout))

    @server.tool(name="r2.disasm", structured_output=True)
    def r2_disasm(
        session_id: str,
        address: int,
        count: Annotated[int, Field(ge=1, le=512)] = 32,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        return _dump(analysis.r2_disasm(session_id, address, count=count, timeout=timeout))

    @server.tool(name="r2.xrefs", structured_output=True)
    def r2_xrefs(
        session_id: str,
        address: int,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        return _dump(analysis.r2_xrefs(session_id, address, timeout=timeout))

    @server.tool(name="ghidra.analyze", structured_output=True)
    def ghidra_analyze(session_id: str, timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0) -> dict[str, Any]:
        return _dump(analysis.ghidra_analyze(session_id, timeout=timeout))

    @server.tool(name="ghidra.functions", structured_output=True)
    def ghidra_functions(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_functions(session_id, limit=limit, timeout=timeout))

    @server.tool(name="ghidra.symbols", structured_output=True)
    def ghidra_symbols(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_symbols(session_id, limit=limit, timeout=timeout))

    @server.tool(name="ghidra.xrefs", structured_output=True)
    def ghidra_xrefs(
        session_id: str,
        address: str,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_xrefs(session_id, address, limit=limit, timeout=timeout))

    @server.tool(name="ghidra.decompile", structured_output=True)
    def ghidra_decompile(
        session_id: str,
        address: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 180.0,
    ) -> dict[str, Any]:
        return _dump(analysis.ghidra_decompile(session_id, address, timeout=timeout))

    @server.tool(name="frida.attach", structured_output=True)
    def frida_attach(session_id: str) -> dict[str, Any]:
        return _dump(analysis.frida_attach(session_id))

    @server.tool(name="frida.modules", structured_output=True)
    def frida_modules(session_id: str, limit: Annotated[int, Field(ge=1, le=256)] = 64) -> dict[str, Any]:
        return _dump(analysis.frida_modules(session_id, limit=limit))

    @server.tool(name="frida.exports", structured_output=True)
    def frida_exports(
        session_id: str,
        module_name: str,
        limit: Annotated[int, Field(ge=1, le=512)] = 64,
    ) -> dict[str, Any]:
        return _dump(analysis.frida_exports(session_id, module_name, limit=limit))

    @server.tool(name="frida.memory.read", structured_output=True)
    def frida_memory_read(session_id: str, address: int, size: Annotated[int, Field(ge=1, le=262144)] = 16) -> dict[str, Any]:
        return _dump(analysis.frida_memory_read(session_id, address, size))

    @server.tool(name="frida.hook.template", structured_output=True)
    def frida_hook_template(session_id: str, template: str = "noop") -> dict[str, Any]:
        return _dump(analysis.frida_hook_template(session_id, template=template))

    @server.tool(name="windbg.open_dump", structured_output=True)
    def windbg_open_dump(
        dump_path: str,
        commands: list[str] | None = None,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
        kernel: bool = False,
    ) -> dict[str, Any]:
        return _dump(analysis.windbg_open_dump(dump_path, commands=commands, timeout=timeout, kernel=kernel))

    @server.tool(name="windbg.threads", structured_output=True)
    def windbg_threads(dump_path: str, timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0) -> dict[str, Any]:
        return _dump(analysis.windbg_threads(dump_path, timeout=timeout))

    @server.tool(name="windbg.modules", structured_output=True)
    def windbg_modules(dump_path: str, timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0) -> dict[str, Any]:
        return _dump(analysis.windbg_modules(dump_path, timeout=timeout))

    @server.tool(name="windbg.disasm", structured_output=True)
    def windbg_disasm(
        dump_path: str,
        address: str,
        length: Annotated[int, Field(ge=1, le=256)] = 16,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
    ) -> dict[str, Any]:
        return _dump(analysis.windbg_disasm(dump_path, address, length=length, timeout=timeout))

    
    @server.tool(name="windbg.attach", structured_output=True)
    def windbg_attach(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        return _dump(analysis.windbg_attach(session_id, timeout=timeout))

    @server.tool(name="windbg.live_threads", structured_output=True)
    def windbg_live_threads(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        return _dump(analysis.windbg_live_threads(session_id, timeout=timeout))

    @server.tool(name="windbg.live_modules", structured_output=True)
    def windbg_live_modules(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        return _dump(analysis.windbg_live_modules(session_id, timeout=timeout))

    @server.tool(name="windbg.live_disasm", structured_output=True)
    def windbg_live_disasm(
        session_id: str,
        address: Annotated[str | int, Field(description="disassembly address")],
        length: Annotated[int, Field(ge=1, le=256)] = 16,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        return _dump(analysis.windbg_live_disasm(session_id, address, length=length, timeout=timeout))

    @server.tool(name="artifacts.list", structured_output=True)
    def artifacts_list(session_id: str | None = None, offset: int = 0, limit: Annotated[int, Field(ge=1, le=256)] = 50) -> dict[str, Any]:
        return _dump(analysis.artifacts_list(session_id, offset=offset, limit=limit))

    @server.tool(name="artifacts.describe", structured_output=True)
    def artifacts_describe(artifact_id: str) -> dict[str, Any]:
        return _dump(analysis.artifacts_describe(artifact_id))

    @server.tool(name="artifacts.read", structured_output=True)
    def artifacts_read(artifact_id: str, offset: int = 0, limit: Annotated[int, Field(ge=1, le=262144)] = 4096) -> dict[str, Any]:
        return _dump(analysis.artifacts_read(artifact_id, offset=offset, limit=limit))

    @server.tool(name="artifacts.gc", structured_output=True)
    def artifacts_gc(max_total_bytes: int = 512 * 1024 * 1024) -> dict[str, Any]:
        return _dump(analysis.artifacts_gc(max_total_bytes=max_total_bytes))

    @server.tool(name="timeline.list", structured_output=True)
    def timeline_list(session_id: str, offset: int = 0, limit: Annotated[int, Field(ge=1, le=256)] = 100) -> dict[str, Any]:
        return _dump(analysis.timeline_list(session_id, offset=offset, limit=limit))

    @server.tool(name="sessions.unclean", structured_output=True)
    def sessions_unclean() -> dict[str, Any]:
        return _dump(analysis.sessions_unclean())

    @server.tool(name="audit.list", structured_output=True)
    def audit_list(
        session_id: str | None = None,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 50,
    ) -> dict[str, Any]:
        return _dump(analysis.audit_list(session_id, offset=offset, limit=limit))


    _install_cursor_underscore_aliases(server)
    return server


def _install_cursor_underscore_aliases(server: FastMCP[None]) -> None:
    """Cursor exposes dotted MCP names as underscores and calls them back that way.

    FastMCP registers ``session.create``; Cursor invokes ``session_create``. Remap
    on ``get_tool`` so CallTool works without duplicating ListTools entries.
    """
    tm = server._tool_manager
    dotted_by_underscore = {
        name.replace(".", "_"): name for name in list(tm._tools) if "." in name
    }
    if not dotted_by_underscore:
        return
    original_get = tm.get_tool

    def get_tool(name: str):  # type: ignore[no-untyped-def]
        tool = original_get(name)
        if tool is None:
            dotted = dotted_by_underscore.get(name)
            if dotted is not None:
                tool = original_get(dotted)
        return tool

    tm.get_tool = get_tool  # type: ignore[method-assign]


def run_stdio(service: AnalysisService | None = None) -> None:
    analysis = service or AnalysisService()
    try:
        create_server(analysis).run(transport="stdio")
    finally:
        analysis.close_all()


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value
