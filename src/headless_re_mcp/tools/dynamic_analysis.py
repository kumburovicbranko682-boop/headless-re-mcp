from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder
from headless_re_mcp.tools.limits import RunControlTimeout


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_dynamic_analysis_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="memory.regions")
    def memory_regions(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=8192)] | None = None,
        timeout: RunControlTimeout = 30.0,
    ) -> dict[str, Any]:
        """List paused-only VirtualQuery-style memory regions with pagination.

        Answers with regions, plus count, total, offset, limit and has_more so a
        page that filled the limit is not read as the whole map. There is no items
        field and no memory field.
        """
        return _dump(
            analysis.memory_regions(
                session_id,
                offset=offset,
                limit=limit,
                timeout=timeout,
            )
        )

    @tools.tool(name="memory.protect.query")
    def memory_protect_query(
        session_id: str,
        address: int,
        timeout: RunControlTimeout = 30.0,
    ) -> dict[str, Any]:
        """Query the memory region containing one address on a paused debuggee."""
        return _dump(analysis.memory_protect_query(session_id, address, timeout=timeout))

    @tools.tool(name="memory.protection")
    def memory_protection(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        rights: str | None = None,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Query memory protection or optionally set allowlisted page rights."""
        return _dump(
            analysis.memory_protection(session_id, address, rights=rights, timeout=timeout)
        )

    @tools.tool(name="threads.list")
    def threads_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List debuggee threads.

        Answers with threads, each carrying tid, entry, teb, cip and the
        suspend count.
        """
        return _dump(analysis.threads_list(session_id, timeout=timeout))

    @tools.tool(name="threads.current")
    def threads_current(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Return the current debuggee thread.

        Answers with tid, entry, teb, cip, name and suspend_count at the top
        level, plus current. There is no thread field.
        """
        return _dump(analysis.threads_current(session_id, timeout=timeout))

    @tools.tool(name="threads.context.read")
    def threads_context_read(
        session_id: str,
        tid: Annotated[int, Field(ge=1)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read allowlisted registers for one thread, restoring the prior TID."""
        return _dump(analysis.threads_context_read(session_id, tid, timeout=timeout))

    @tools.tool(name="threads.context.write")
    def threads_context_write(
        session_id: str,
        tid: Annotated[int, Field(ge=1)],
        name: str,
        value: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Write one allowlisted register on a thread, restoring the prior TID."""
        return _dump(analysis.threads_context_write(session_id, tid, name, value, timeout=timeout))

    @tools.tool(name="stack.read")
    def stack_read(
        session_id: str,
        address: Annotated[int, Field(ge=0)] | None = None,
        count: Annotated[int, Field(ge=1, le=256)] = 32,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read pointer-sized stack words from CSP or an explicit address.

        Answers with entries, each a pointer-sized value read at an address,
        plus base, count and pointer_size.
        """
        return _dump(analysis.stack_read(session_id, address=address, count=count, timeout=timeout))

    @tools.tool(name="stack.trace")
    def stack_trace(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=256)] = 256,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Return a bounded call stack for the paused debuggee.

        Answers with frames, plus count, total, limit and has_more so a page
        that filled the limit is not read as the whole stack. There is no stack field
        and no items field.
        """
        return _dump(analysis.stack_trace(session_id, limit=limit, timeout=timeout))

    @tools.tool(name="disassembly.read")
    def disassembly_read(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        count: Annotated[int, Field(ge=1, le=256)] = 32,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disassemble a bounded instruction range starting at address.

        Answers with instructions, each carrying address, size and instruction
        (not text), plus count. There is no disasm field, no items field and
        no text field.
        """
        return _dump(analysis.disassembly_read(session_id, address, count=count, timeout=timeout))

    @tools.tool(name="symbols.list")
    def symbols_list(
        session_id: str,
        module_base: Annotated[int, Field(ge=1)],
        limit: Annotated[int, Field(ge=1, le=4096)] = 256,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Enumerate a bounded symbol list for one loaded module.

        Answers with symbols, plus count and truncated, so a caller can tell a
        short module from a list that stopped at the limit.
        """
        return _dump(analysis.symbols_list(session_id, module_base, limit=limit, timeout=timeout))

    @tools.tool(name="symbols.resolve")
    def symbols_resolve(
        session_id: str,
        expression: Annotated[str, Field(min_length=1, max_length=512)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Resolve a structured expression/symbol to an address."""
        return _dump(analysis.symbols_resolve(session_id, expression, timeout=timeout))

    @tools.tool(name="modules.dump")
    def modules_dump(
        session_id: str,
        base: int,
        size: Annotated[int, Field(ge=1, le=64 * 1024 * 1024)] | None = None,
        timeout: RunControlTimeout = 30.0,
    ) -> dict[str, Any]:
        """Dump one loaded module into a session artifact path (no raw bytes over MCP)."""
        return _dump(analysis.modules_dump(session_id, base, size=size, timeout=timeout))

    @tools.tool(name="pe.headers.runtime")
    def pe_headers_runtime(
        session_id: str,
        base: int,
        save_artifact: bool = True,
        timeout: RunControlTimeout = 30.0,
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

    @tools.tool(name="imports.scan")
    def imports_scan(
        session_id: str,
        module_base: int,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: Annotated[int, Field(ge=1, le=32)] = 8,
        mode: str = "all",
        timeout: RunControlTimeout = 60.0,
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

    @tools.tool(name="imports.read")
    def imports_read(
        session_id: str,
        iat_va: int,
        size: int,
        timeout: RunControlTimeout = 30.0,
    ) -> dict[str, Any]:
        """Read one confirmed IAT range and resolve thunks against loaded exports."""
        return _dump(analysis.imports_read(session_id, iat_va, size, timeout=timeout))

    @tools.tool(name="modules.list")
    def modules_list(session_id: str) -> dict[str, Any]:
        """Return the validated current runtime module catalog without hashing files.

        Answers with modules, validated against the session target rather than
        taken from the debugger as-is.
        """
        return _dump(analysis.module_catalog(session_id))

    @tools.tool(name="modules.resolve")
    def modules_resolve(
        session_id: str,
        selector: ModuleSelector,
    ) -> dict[str, Any]:
        """Resolve one loaded module and verify its PE identity and rebase metadata."""
        return _dump(analysis.module_resolve(session_id, selector))

    @tools.tool(name="breakpoints.hardware.set")
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

    @tools.tool(name="breakpoints.hardware.remove")
    def breakpoints_hardware_remove(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Remove a hardware breakpoint."""
        return _dump(analysis.breakpoints_hardware_remove(session_id, address, timeout=timeout))

    @tools.tool(name="breakpoints.hardware.list")
    def breakpoints_hardware_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List hardware breakpoints."""
        return _dump(analysis.breakpoints_hardware_list(session_id, timeout=timeout))

    @tools.tool(name="breakpoints.memory.set")
    def breakpoints_memory_set(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        bp_type: Annotated[str, Field(pattern="^(a|r|w|x|access|read|write|execute|rwx)$")] = "a",
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Set a memory breakpoint with structured type enum only."""
        return _dump(
            analysis.breakpoints_memory_set(session_id, address, bp_type=bp_type, timeout=timeout)
        )

    @tools.tool(name="breakpoints.memory.remove")
    def breakpoints_memory_remove(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Remove a memory breakpoint."""
        return _dump(analysis.breakpoints_memory_remove(session_id, address, timeout=timeout))

    @tools.tool(name="breakpoints.memory.list")
    def breakpoints_memory_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List memory breakpoints."""
        return _dump(analysis.breakpoints_memory_list(session_id, timeout=timeout))

    @tools.tool(name="breakpoints.condition.set")
    def breakpoints_condition_set(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        expression: Annotated[str, Field(min_length=1, max_length=512)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Set a sanitized break condition on an existing breakpoint."""
        return _dump(
            analysis.breakpoints_condition_set(session_id, address, expression, timeout=timeout)
        )

    @tools.tool(name="breakpoints.condition.get")
    def breakpoints_condition_get(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Read the break condition for an existing breakpoint."""
        return _dump(analysis.breakpoints_condition_get(session_id, address, timeout=timeout))

    @tools.tool(name="patches.list")
    def patches_list(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """List recorded memory patches."""
        return _dump(analysis.patches_list(session_id, timeout=timeout))

    @tools.tool(name="patches.apply")
    def patches_apply(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        data: Annotated[str, Field(min_length=2, max_length=512)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Apply a bounded hex patch through MemPatch."""
        return _dump(analysis.patches_apply(session_id, address, data, timeout=timeout))

    @tools.tool(name="patches.restore")
    def patches_restore(
        session_id: str,
        address: Annotated[int, Field(ge=0)],
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 30.0,
    ) -> dict[str, Any]:
        """Restore one recorded patch."""
        return _dump(analysis.patches_restore(session_id, address, timeout=timeout))
    return tools.bindings
