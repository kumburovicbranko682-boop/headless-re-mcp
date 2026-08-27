from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.events import DEFAULT_DEBUG_EVENT_BATCH, MAX_DEBUG_EVENT_BATCH
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder
from headless_re_mcp.tools.limits import RunControlTimeout


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_dynamic_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="dynamic.open")
    def dynamic_open(session_id: str) -> dict[str, Any]:
        """Open the matching x86/x64 official x64dbg headless RPC backend.

        Answers with backend, reused and session. reused is true when this
        session already had the debugger open.
        """
        return _dump(analysis.open_dynamic(session_id))

    @tools.tool(name="dynamic.state")
    def dynamic_state(session_id: str) -> dict[str, Any]:
        """Return idle/running/paused state plus debuggee_pid vs debugger_pid.

        Answers with state, running, debugging, process_id, thread_id,
        debuggee_pid, debugger_pid and pid_note. process_id is 0 when idle;
        debuggee_pid is the target and is null until something is launched.
        """
        return _dump(analysis.dynamic_state(session_id))

    @tools.tool(name="dynamic.events")
    def dynamic_events(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=MAX_DEBUG_EVENT_BATCH)] = (DEFAULT_DEBUG_EVENT_BATCH),
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 10.0,
    ) -> dict[str, Any]:
        """Read the next bounded debugger callback batch for this session.

        Answers with events, each carrying sequence, timestamp_unix_ms, source,
        kind and data, plus count, cursor, next_cursor, dropped, dropped_total,
        has_more and capacity. There is no items field.
        """
        return _dump(analysis.dynamic_events(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="dynamic.wait")
    def dynamic_wait(
        session_id: str,
        state: str,
        timeout: RunControlTimeout = 30.0,
    ) -> dict[str, Any]:
        """Wait with a bound until the debugger reaches idle, running, or paused.

        Answers with state and submitted. There is no reached or ok field
        besides the envelope.
        """
        return _dump(analysis.dynamic_wait(session_id, state, timeout=timeout))

    @tools.tool(name="dynamic.launch")
    def dynamic_launch(
        session_id: str,
        arguments: str = "",
        working_directory: str | None = None,
        timeout: RunControlTimeout = 30.0,
        pass_system_breakpoint: bool = False,
        stealth_profile: str | None = None,
    ) -> dict[str, Any]:
        """Launch the session binary and wait for its initial debugger pause.

        Answers with state, submitted, pass_system_breakpoint, stealth_profile,
        stealth_applied, stealth_ready and stealth_enabled. When
        pass_system_breakpoint is true, resume once after the first pause
        (typical system/entry breakpoint) so unpack workflows can continue.
        Default leaves the debuggee paused; ui.virtual_desktop.snapshot
        window_count stays 0 until dynamic.resume lets it create windows.
        stealth_profile is a ScyllaHide whitelist id (vmp/themida/obsidium/
        armadillo/basic/off) or an alias (tmd/winlicense/oreans/vmprotect).
        Omit it to apply packer.classify's stealth_profile automatically.
        If the debugger is not open, the profile is written then the backend
        is opened; if it is already open and the requested profile differs,
        the call is refused.
        """
        return _dump(
            analysis.dynamic_launch(
                session_id,
                arguments=arguments,
                working_directory=working_directory,
                timeout=timeout,
                pass_system_breakpoint=pass_system_breakpoint,
                stealth_profile=stealth_profile,
            )
        )

    @tools.tool(name="dynamic.attach")
    def dynamic_attach(
        session_id: str,
        pid: Annotated[int, Field(ge=1, le=0xFFFFFFFF)],
        timeout: RunControlTimeout = 30.0,
        pause_after_attach: bool = False,
    ) -> dict[str, Any]:
        """Attach to an authorized process; default waits for paused|running (GUI-friendly).

        Answers with submitted and state, the same shape as dynamic.wait, plus
        child_windows_hint, suggested_child_pids and child_candidates when the
        debuggee has child windows. There is no attached or top-level pid field.
        """
        return _dump(
            analysis.dynamic_attach(
                session_id,
                pid,
                timeout=timeout,
                pause_after_attach=pause_after_attach,
            )
        )

    @tools.tool(name="dynamic.stop")
    def dynamic_stop(session_id: str, timeout: RunControlTimeout = 30.0) -> dict[str, Any]:
        """Stop the active debuggee and wait until the backend is idle.

        Answers with state and submitted, the same shape as dynamic.wait.
        """
        return _dump(analysis.dynamic_stop(session_id, timeout=timeout))

    @tools.tool(name="dynamic.pause")
    def dynamic_pause(session_id: str, timeout: RunControlTimeout = 30.0) -> dict[str, Any]:
        """Pause the active debuggee and wait for a stable paused state.

        Answers with state and submitted, the same shape as dynamic.wait.
        """
        return _dump(analysis.dynamic_pause(session_id, timeout=timeout))

    @tools.tool(name="dynamic.resume")
    def dynamic_resume(
        session_id: str,
        wait_for_pause: bool = False,
        timeout: RunControlTimeout = 30.0,
    ) -> dict[str, Any]:
        """Resume the debuggee, optionally waiting for its next pause or exit.

        Answers with state, running, debugging, process_id and thread_id.
        There is no submitted field (unlike wait/launch/stop).
        """
        return _dump(
            analysis.dynamic_resume(
                session_id,
                wait_for_pause=wait_for_pause,
                timeout=timeout,
            )
        )

    @tools.tool(name="dynamic.step_into")
    def dynamic_step_into(session_id: str, timeout: RunControlTimeout = 30.0) -> dict[str, Any]:
        """Execute one step into and wait for the next pause or process exit.

        Answers with state and submitted, the same shape as dynamic.wait.
        """
        return _dump(analysis.dynamic_step_into(session_id, timeout=timeout))

    @tools.tool(name="dynamic.step_over")
    def dynamic_step_over(session_id: str, timeout: RunControlTimeout = 30.0) -> dict[str, Any]:
        """Execute one step over and wait for the next pause or process exit.

        Answers with state and submitted, the same shape as dynamic.wait.
        """
        return _dump(analysis.dynamic_step_over(session_id, timeout=timeout))

    @tools.tool(name="dynamic.registers.read")
    def dynamic_registers_read(session_id: str) -> dict[str, Any]:
        """Read the bounded general-purpose register set from a paused debuggee.

        Answers with registers holding rax..r15, rip, eflags and dr0-dr7 on
        x64 (eax..eip on x86). There is no top-level rip, gpr or context
        field.
        """
        return _dump(analysis.dynamic_registers_read(session_id))

    @tools.tool(name="dynamic.registers.write")
    def dynamic_registers_write(
        session_id: str,
        name: Annotated[str, Field(min_length=1, max_length=16)],
        value: int,
    ) -> dict[str, Any]:
        """Write one allowlisted architecture register on a paused debuggee.

        Answers with name and value of the register that was written. There
        is no written, ok or registers field.
        """
        return _dump(analysis.dynamic_register_write(session_id, name, value))

    @tools.tool(name="dynamic.memory.read")
    def dynamic_memory_read(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        size: Annotated[int, Field(ge=1, le=2 * 1024 * 1024)],
    ) -> dict[str, Any]:
        """Read up to 2 MiB from a paused debuggee as hexadecimal bytes.

        Answers with data holding the hex string and encoding naming the form,
        alongside the address and size that were read.
        """
        return _dump(analysis.dynamic_memory_read(session_id, address, size))

    @tools.tool(name="dynamic.memory.write")
    def dynamic_memory_write(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        data: Annotated[str, Field(min_length=2, max_length=4 * 1024 * 1024)],
    ) -> dict[str, Any]:
        """Write bounded hexadecimal bytes to an authorized paused debuggee.

        Answers with address and size of the range that was written. There is
        no written, ok, data or bytes field.
        """
        return _dump(analysis.dynamic_memory_write(session_id, address, data))

    @tools.tool(name="dynamic.modules")
    def dynamic_modules(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1024)] = 256,
    ) -> dict[str, Any]:
        """List loaded image modules for a paused debuggee.

        Answers with modules, each carrying base, size, name and path, plus
        count, total, offset, limit and has_more so a page that filled the
        limit is not read as the whole catalog.
        """
        return _dump(
            analysis.dynamic_modules(session_id, offset=offset, limit=limit)
        )

    @tools.tool(name="dynamic.breakpoints")
    def dynamic_breakpoints(session_id: str) -> dict[str, Any]:
        """List debugger breakpoints for the active debuggee.

        Answers with breakpoints, which includes the entry breakpoint the
        debugger sets itself, not only the ones that were asked for. An empty
        list here after a successful set means the debuggee is gone, not that
        the breakpoint was refused.
        """
        return _dump(analysis.dynamic_breakpoints(session_id))

    @tools.tool(name="dynamic.breakpoint.set")
    def dynamic_breakpoint_set(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        address_space: Annotated[str, Field(pattern="^(runtime|static|rva)$")] = "runtime",
    ) -> dict[str, Any]:
        """Set a software breakpoint at an address in a paused debuggee.

        Pass address_space=static for an IDA address or rva for a module offset;
        both are rebased through the live module base, so ASLR never reaches the
        caller. The default keeps treating address as an already-runtime VA.
        Answers with address and set (true). There is no ok or removed field.
        """
        return _dump(
            analysis.dynamic_breakpoint_set(
                session_id,
                address,
                address_space=address_space,
            )
        )

    @tools.tool(name="dynamic.analyze_function")
    def dynamic_analyze_function(
        session_id: str,
        address: int,
        address_space: Annotated[str, Field(pattern="^(runtime|static|rva)$")] = "static",
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
        decompile: bool = True,
    ) -> dict[str, Any]:
        """Decompile a function, arm it at runtime, resume, and report the stop.

        One call replaces decompile + rebase + breakpoint + resume + registers.
        address defaults to an IDA (static) coordinate and is rebased internally.
        Answers with function (static_address, runtime_address, rva,
        rebase_delta, module), static, breakpoint (address, armed), execution
        (resumed, instruction_pointer, stopped_at_breakpoint) and registers.
        There is no top-level rip, decompiled or ok field.
        """
        return _dump(
            analysis.analyze_function_dynamic(
                session_id,
                address,
                address_space=address_space,
                timeout=timeout,
                decompile=decompile,
            )
        )

    @tools.tool(name="dynamic.trace_api_arguments")
    def dynamic_trace_api_arguments(
        session_id: str,
        expression: str | None = None,
        address: int | None = None,
        max_hits: Annotated[int, Field(ge=1, le=64)] = 4,
        argument_count: Annotated[int, Field(ge=0, le=4)] = 4,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Break on an API and capture its integer arguments on each hit.

        Give either expression (for example kernel32.CreateFileW) or a runtime
        address. Answers with hits (instruction_pointer and arguments), hit_count,
        truncated, stopped_elsewhere, resume_interrupted, resume_error,
        convention, architecture, target and max_hits. resume_interrupted is true
        (with resume_error naming the code/message) when a resume did not re-pause
        before max_hits, so an incomplete capture is not read as complete. There
        is no top-level arguments, rip or ok field. The breakpoint is removed when
        the trace ends.
        """
        return _dump(
            analysis.trace_api_arguments(
                session_id,
                expression,
                address=address,
                max_hits=max_hits,
                argument_count=argument_count,
                timeout=timeout,
            )
        )

    @tools.tool(name="dynamic.breakpoint.remove")
    def dynamic_breakpoint_remove(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
    ) -> dict[str, Any]:
        """Remove a software breakpoint from an address in a paused debuggee.

        Answers with address and set (false). There is no removed, ok or
        cleared field. Looking for removed after success treats a live
        delete as still armed.
        """
        return _dump(analysis.dynamic_breakpoint_remove(session_id, address))

    @tools.tool(name="dynamic.stealth.status")
    def dynamic_stealth_status(session_id: str | None = None) -> dict[str, Any]:
        """Report ScyllaHide plugin files and the current profile per architecture.

        Answers with enabled, default_profile, allowed_profiles, ready,
        architectures (plugin_present, current_profile, plugins_dir) and
        live_sessions. Missing plugins set ready false; this does not claim
        injection succeeded. optional session_id adds session_architecture.
        """
        return _dump(analysis.dynamic_stealth_status(session_id=session_id))

    @tools.tool(name="dynamic.stealth.set")
    def dynamic_stealth_set(
        profile: str,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Write a whitelisted ScyllaHide profile before the debugger is opened.

        profile is vmp, themida, obsidium, armadillo, basic, or off
        (aliases: tmd/winlicense/oreans → themida, vmprotect → vmp).
        Writes CurrentProfile in the live headless plugins ini. Refused with
        debugger_already_open if any debugger of that architecture is already
        running. armadillo is x86-only. off writes Disabled so hide is actually
        turned off. Prefer calling this after packer.classify; open/launch will
        apply stealth_profile themselves if this is skipped.
        """
        return _dump(analysis.dynamic_stealth_set(profile, session_id=session_id))

    return tools.bindings
