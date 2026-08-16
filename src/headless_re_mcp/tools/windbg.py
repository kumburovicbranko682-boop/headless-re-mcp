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


def build_windbg_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="windbg.open_dump")
    def windbg_open_dump(
        dump_path: str,
        commands: list[str] | None = None,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
        kernel: bool = False,
    ) -> dict[str, Any]:
        """Run whitelisted cdb commands against a crash dump file.

        For post-mortem work on a .dmp, not on a live debuggee. commands
        defaults to a general triage set. Kernel dumps need kernel=true and are
        refused unless HEADLESS_RE_WINDBG_ALLOW_KERNEL is set. The reply carries
        truncated when the session output was cut at the buffer.
        """
        return _dump(
            analysis.windbg_open_dump(dump_path, commands=commands, timeout=timeout, kernel=kernel)
        )

    @tools.tool(name="windbg.threads")
    def windbg_threads(
        dump_path: str, timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0
    ) -> dict[str, Any]:
        """Thread list of a crash dump; read truncated when the listing was cut."""
        return _dump(analysis.windbg_threads(dump_path, timeout=timeout))

    @tools.tool(name="windbg.modules")
    def windbg_modules(
        dump_path: str, timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0
    ) -> dict[str, Any]:
        """Loaded module list of a crash dump; a failed cdb is not an empty list.

        Read truncated when the listing was cut.
        """
        return _dump(analysis.windbg_modules(dump_path, timeout=timeout))

    @tools.tool(name="windbg.disasm")
    def windbg_disasm(
        dump_path: str,
        address: str,
        length: Annotated[int, Field(ge=1, le=256)] = 16,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
    ) -> dict[str, Any]:
        """Disassemble length instructions at address; read truncated when cut."""
        return _dump(analysis.windbg_disasm(dump_path, address, length=length, timeout=timeout))

    @tools.tool(name="windbg.attach")
    def windbg_attach(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Non-invasive cdb probe of this session's live debuggee.

        Reads the process without taking control, so x64dbg keeps it. Answers
        with the target's version and platform.
        """
        return _dump(analysis.windbg_attach(session_id, timeout=timeout))

    @tools.tool(name="windbg.live_threads")
    def windbg_live_threads(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Thread list of this session's live debuggee, read non-invasively."""
        return _dump(analysis.windbg_live_threads(session_id, timeout=timeout))

    @tools.tool(name="windbg.live_modules")
    def windbg_live_modules(
        session_id: str, timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0
    ) -> dict[str, Any]:
        """Loaded module list of this session's live debuggee, read non-invasively."""
        return _dump(analysis.windbg_live_modules(session_id, timeout=timeout))

    @tools.tool(name="windbg.live_disasm")
    def windbg_live_disasm(
        session_id: str,
        address: Annotated[str | int, Field(description="disassembly address")],
        length: Annotated[int, Field(ge=1, le=256)] = 16,
        timeout: Annotated[float, Field(gt=0, le=120.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble length instructions at address in this session's live debuggee."""
        return _dump(
            analysis.windbg_live_disasm(session_id, address, length=length, timeout=timeout)
        )
    return tools.bindings
