from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.events import DEFAULT_DEBUG_EVENT_BATCH, MAX_DEBUG_EVENT_BATCH
from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_dynamic_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="dynamic.open")
    def dynamic_open(session_id: str) -> dict[str, Any]:
        """Open the matching x86/x64 official x64dbg headless RPC backend."""
        return _dump(analysis.open_dynamic(session_id))

    @tools.tool(name="dynamic.state")
    def dynamic_state(session_id: str) -> dict[str, Any]:
        """Return idle/running/paused state plus debuggee_pid vs debugger_pid."""
        return _dump(analysis.dynamic_state(session_id))

    @tools.tool(name="dynamic.events")
    def dynamic_events(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=MAX_DEBUG_EVENT_BATCH)] = (DEFAULT_DEBUG_EVENT_BATCH),
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 10.0,
    ) -> dict[str, Any]:
        """Read the next bounded debugger callback batch for this session."""
        return _dump(analysis.dynamic_events(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="dynamic.wait")
    def dynamic_wait(
        session_id: str,
        state: str,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Wait with a bound until the debugger reaches idle, running, or paused."""
        return _dump(analysis.dynamic_wait(session_id, state, timeout=timeout))

    @tools.tool(name="dynamic.launch")
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

    @tools.tool(name="dynamic.attach")
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

    @tools.tool(name="dynamic.stop")
    def dynamic_stop(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Stop the active debuggee and wait until the backend is idle."""
        return _dump(analysis.dynamic_stop(session_id, timeout=timeout))

    @tools.tool(name="dynamic.pause")
    def dynamic_pause(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Pause the active debuggee and wait for a stable paused state."""
        return _dump(analysis.dynamic_pause(session_id, timeout=timeout))

    @tools.tool(name="dynamic.resume")
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

    @tools.tool(name="dynamic.step_into")
    def dynamic_step_into(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Execute one step into and wait for the next pause or process exit."""
        return _dump(analysis.dynamic_step_into(session_id, timeout=timeout))

    @tools.tool(name="dynamic.step_over")
    def dynamic_step_over(session_id: str, timeout: float = 30.0) -> dict[str, Any]:
        """Execute one step over and wait for the next pause or process exit."""
        return _dump(analysis.dynamic_step_over(session_id, timeout=timeout))

    @tools.tool(name="dynamic.registers.read")
    def dynamic_registers_read(session_id: str) -> dict[str, Any]:
        """Read the bounded general-purpose register set from a paused debuggee."""
        return _dump(analysis.dynamic_registers_read(session_id))

    @tools.tool(name="dynamic.registers.write")
    def dynamic_registers_write(
        session_id: str,
        name: str,
        value: int,
    ) -> dict[str, Any]:
        """Write one allowlisted architecture register on a paused debuggee."""
        return _dump(analysis.dynamic_register_write(session_id, name, value))

    @tools.tool(name="dynamic.memory.read")
    def dynamic_memory_read(
        session_id: str,
        address: int,
        size: int,
    ) -> dict[str, Any]:
        """Read up to 2 MiB from a paused debuggee as hexadecimal bytes."""
        return _dump(analysis.dynamic_memory_read(session_id, address, size))

    @tools.tool(name="dynamic.memory.write")
    def dynamic_memory_write(
        session_id: str,
        address: int,
        data: str,
    ) -> dict[str, Any]:
        """Write bounded hexadecimal bytes to an authorized paused debuggee."""
        return _dump(analysis.dynamic_memory_write(session_id, address, data))

    @tools.tool(name="dynamic.modules")
    def dynamic_modules(session_id: str) -> dict[str, Any]:
        """List loaded image modules for a paused debuggee."""
        return _dump(analysis.dynamic_modules(session_id))

    @tools.tool(name="dynamic.breakpoints")
    def dynamic_breakpoints(session_id: str) -> dict[str, Any]:
        """List debugger breakpoints for the active debuggee."""
        return _dump(analysis.dynamic_breakpoints(session_id))

    @tools.tool(name="dynamic.breakpoint.set")
    def dynamic_breakpoint_set(session_id: str, address: int) -> dict[str, Any]:
        """Set a software breakpoint at an address in a paused debuggee."""
        return _dump(analysis.dynamic_breakpoint_set(session_id, address))

    @tools.tool(name="dynamic.breakpoint.remove")
    def dynamic_breakpoint_remove(session_id: str, address: int) -> dict[str, Any]:
        """Remove a software breakpoint from an address in a paused debuggee."""
        return _dump(analysis.dynamic_breakpoint_remove(session_id, address))
    return tools.bindings
