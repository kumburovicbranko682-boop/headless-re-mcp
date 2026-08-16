"""Protocol-independent typed handlers for core analysis domains."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from headless_re_mcp.core.events import DEFAULT_DEBUG_EVENT_BATCH, MAX_DEBUG_EVENT_BATCH
from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.detection.models import ScanMode
from headless_re_mcp.tools.binding import BoundTool


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    return result.model_dump(mode="json")


def build_core_session_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    """Register doctor + session.* tools (table-driven entry point for further migration)."""

    def doctor() -> dict[str, Any]:
        """Probe configured reverse-engineering backends and local build tools."""
        return _dump(analysis.doctor())

    def session_create(
        binary: str,
        target: Annotated[
            Literal["pe", "apk", "web"] | None,
            Field(description="Force a target kind instead of inferring it"),
        ] = None,
    ) -> dict[str, Any]:
        """Create a session for a local PE, a local APK, or a web target.

        binary is a local file path, or an http(s) URL when target is web. The
        target kind is inferred from the extension and magic bytes when omitted,
        so a PE path behaves exactly as before. At most 64 sessions can be
        open at once; close one before opening another.
        """
        return _dump(analysis.create_session(binary, target))

    def session_get(session_id: str) -> dict[str, Any]:
        """Return one session, including target, state, architecture, and backends."""
        return _dump(analysis.get_session(session_id))

    def session_list(
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        """List sessions known to this MCP server process.

        Read `total` and `has_more` rather than assuming the page is complete.
        """
        return _dump(analysis.list_sessions(offset=offset, limit=limit))

    def session_close(session_id: str) -> dict[str, Any]:
        """Close a session and terminate its isolated backend worker."""
        return _dump(analysis.close_session(session_id))

    specs = [
        BoundTool("doctor", doctor),
        BoundTool("session.create", session_create),
        BoundTool("session.get", session_get),
        BoundTool("session.list", session_list),
        BoundTool("session.close", session_close),
    ]
    return tuple(specs)

def build_static_core_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    """Register high-traffic static.* tools via add_tool."""

    def static_open(session_id: str) -> dict[str, Any]:
        """Open the session binary in an isolated, zero-window IDA idalib worker."""
        return _dump(analysis.open_static(session_id))

    def static_functions(
        session_id: str,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List analyzed functions with addresses, names, ranges, and flags.

        The list is a window; read `total` and `has_more` rather than assuming
        the page is the whole database.
        """
        return _dump(analysis.static_functions(session_id, offset=offset, limit=limit))

    def static_strings(
        session_id: str,
        offset: int = 0,
        limit: int = 100,
        max_length: int = 4096,
    ) -> dict[str, Any]:
        """List analyzed strings with addresses, types, and bounded text values.

        The list is a window; read `total` and `has_more` rather than assuming
        the page is the whole database.
        """
        return _dump(
            analysis.static_strings(
                session_id,
                offset=offset,
                limit=limit,
                max_length=max_length,
            )
        )

    def static_decompile(
        session_id: str,
        address: int | None = None,
    ) -> dict[str, Any]:
        """Decompile the function containing address, or the first function when omitted.

        Oversized output is cut; read `truncated`/`bytes` rather than assuming
        `code` is the whole function.
        """
        return _dump(analysis.static_decompile(session_id, address=address))

    def static_metadata(session_id: str) -> dict[str, Any]:
        """Return idalib database metadata (image base, hashes, counts, capabilities)."""
        return _dump(analysis.static_metadata(session_id))

    specs: list[BoundTool] = []
    for name, fn in (
        ("static.open", static_open),
        ("static.functions", static_functions),
        ("static.strings", static_strings),
        ("static.decompile", static_decompile),
        ("static.metadata", static_metadata),
    ):
        specs.append(BoundTool(name, fn))
    return tuple(specs)


def build_detect_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    """Register detect.*/packer.classify/unpack.recommend via add_tool."""

    def detect_scan(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        use_exeinfope: bool = False,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Built-in PE detect plus optional DIE and optional Exeinfo PE second opinion.

        ``use_exeinfope`` defaults to false. When true, requires ``HEADLESS_RE_EXEINFOPE``;
        results are listed beside DIE/builtin and never merged into one authoritative verdict.
        """
        return _dump(
            analysis.detect_scan(
                session_id,
                mode=mode,
                use_die=use_die,
                use_exeinfope=use_exeinfope,
                timeout=timeout,
            )
        )

    def detect_explain(
        session_id: str,
        finding_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        use_exeinfope: bool = False,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Return evidence for one finding from a fresh bounded detection scan."""
        return _dump(
            analysis.detect_explain(
                session_id,
                finding_id,
                mode=mode,
                use_die=use_die,
                use_exeinfope=use_exeinfope,
                timeout=timeout,
            )
        )

    def packer_classify(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        use_exeinfope: bool = False,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Return non-authoritative packer/protector/obfuscator candidates."""
        return _dump(
            analysis.packer_classify(
                session_id,
                mode=mode,
                use_die=use_die,
                use_exeinfope=use_exeinfope,
                timeout=timeout,
            )
        )

    def unpack_recommend(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Suggest a non-authoritative unpack route (UPX/.NET/generic/none) without executing it."""
        return _dump(
            analysis.unpack_recommend(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
            )
        )

    specs: list[BoundTool] = []
    for name, fn in (
        ("detect.scan", detect_scan),
        ("detect.explain", detect_explain),
        ("packer.classify", packer_classify),
        ("unpack.recommend", unpack_recommend),
    ):
        specs.append(BoundTool(name, fn))
    return tuple(specs)

def build_static_extended_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    """Register remaining static.* tools via add_tool."""

    def static_segments(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List memory segments with names, ranges, and permissions."""
        return _dump(analysis.static_segments(session_id, offset=offset, limit=limit))

    def static_imports(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List imported symbols (module, name/ordinal, ea)."""
        return _dump(analysis.static_imports(session_id, offset=offset, limit=limit))

    def static_exports(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List exported entries."""
        return _dump(analysis.static_exports(session_id, offset=offset, limit=limit))

    def static_entrypoints(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List entry points (start IP and IDA entry table)."""
        return _dump(analysis.static_entrypoints(session_id, offset=offset, limit=limit))

    def static_disassemble(
        session_id: str,
        address: int,
        count: Annotated[int, Field(ge=1, le=512)] = 32,
        max_bytes: Annotated[int, Field(ge=1, le=65536)] = 4096,
    ) -> dict[str, Any]:
        """Bounded linear disassembly starting at address."""
        return _dump(
            analysis.static_disassemble(
                session_id,
                address=address,
                count=count,
                max_bytes=max_bytes,
            )
        )

    def static_xrefs_to(
        session_id: str,
        address: int,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List cross-references to an address."""
        return _dump(
            analysis.static_xrefs_to(
                session_id,
                address=address,
                offset=offset,
                limit=limit,
            )
        )

    def static_xrefs_from(
        session_id: str,
        address: int,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List cross-references from an address."""
        return _dump(
            analysis.static_xrefs_from(
                session_id,
                address=address,
                offset=offset,
                limit=limit,
            )
        )

    def static_callers(
        session_id: str,
        address: int,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List call-type callers of the function containing address (weak model)."""
        return _dump(
            analysis.static_callers(
                session_id,
                address=address,
                offset=offset,
                limit=limit,
            )
        )

    def static_callees(
        session_id: str,
        address: int,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List call-type callees from the function containing address (weak model)."""
        return _dump(
            analysis.static_callees(
                session_id,
                address=address,
                offset=offset,
                limit=limit,
            )
        )

    def static_basic_blocks(
        session_id: str,
        address: int,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List basic blocks for the function containing address."""
        return _dump(
            analysis.static_basic_blocks(
                session_id,
                address=address,
                offset=offset,
                limit=limit,
            )
        )

    def static_cfg(session_id: str, address: int) -> dict[str, Any]:
        """Return function-local CFG nodes and edges.

        Oversized graphs are cut; read `truncated`/`total_nodes` rather than
        assuming `nodes` is the whole function.
        """
        return _dump(analysis.static_cfg(session_id, address=address))

    def static_globals(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List named addresses outside functions (best-effort globals)."""
        return _dump(analysis.static_globals(session_id, offset=offset, limit=limit))

    def static_names(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List named addresses in the IDA database."""
        return _dump(analysis.static_names(session_id, offset=offset, limit=limit))

    def static_types(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List local type-library ordinals."""
        return _dump(analysis.static_types(session_id, offset=offset, limit=limit))

    def static_structs(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List struct/union types from the local type library."""
        return _dump(analysis.static_structs(session_id, offset=offset, limit=limit))

    def static_enums(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """List enum types from the local type library."""
        return _dump(analysis.static_enums(session_id, offset=offset, limit=limit))

    def static_bytes_read(
        session_id: str,
        address: int,
        size: Annotated[int, Field(ge=1, le=4096)] = 64,
    ) -> dict[str, Any]:
        """Read a bounded byte range from the IDA database.

        Read `size` against `requested`, and `truncated`, rather than assuming
        the hex is the whole range you asked for.
        """
        return _dump(analysis.static_bytes_read(session_id, address=address, size=size))

    def static_search_bytes(
        session_id: str,
        pattern: str,
        start: int | None = None,
        end: int | None = None,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Search for a binary pattern (IDA bin-string syntax)."""
        return _dump(
            analysis.static_search_bytes(
                session_id,
                pattern=pattern,
                start=start,
                end=end,
                offset=offset,
                limit=limit,
            )
        )

    def static_search_text(
        session_id: str,
        text: str,
        start: int | None = None,
        end: int | None = None,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Search for text in the IDA database."""
        return _dump(
            analysis.static_search_text(
                session_id,
                text=text,
                start=start,
                end=end,
                offset=offset,
                limit=limit,
            )
        )

    def static_search_immediate(
        session_id: str,
        value: int,
        start: int | None = None,
        end: int | None = None,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=1000)] = 100,
    ) -> dict[str, Any]:
        """Search for an immediate operand value."""
        return _dump(
            analysis.static_search_immediate(
                session_id,
                value=value,
                start=start,
                end=end,
                offset=offset,
                limit=limit,
            )
        )

    def static_name_set(
        session_id: str,
        address: int,
        name: str,
    ) -> dict[str, Any]:
        """Set a name at an address inside the current IDA database."""
        return _dump(analysis.static_name_set(session_id, address=address, name=name))

    def static_comment_set(
        session_id: str,
        address: int,
        comment: str,
        repeatable: bool = False,
    ) -> dict[str, Any]:
        """Set a regular or repeatable comment at an address."""
        return _dump(
            analysis.static_comment_set(
                session_id,
                address=address,
                comment=comment,
                repeatable=repeatable,
            )
        )

    def static_type_apply(
        session_id: str,
        address: int,
        type: str,
    ) -> dict[str, Any]:
        """Apply a type string at an address."""
        return _dump(
            analysis.static_type_apply(session_id, address=address, type=type)
        )

    def static_function_create(session_id: str, address: int) -> dict[str, Any]:
        """Create a function at an address."""
        return _dump(analysis.static_function_create(session_id, address=address))

    def static_function_delete(session_id: str, address: int) -> dict[str, Any]:
        """Delete the function containing an address."""
        return _dump(analysis.static_function_delete(session_id, address=address))

    def static_bytes_patch(
        session_id: str,
        address: int,
        hex: str | None = None,
        base64: str | None = None,
    ) -> dict[str, Any]:
        """Patch database bytes (hex or base64); records a patch artifact."""
        return _dump(
            analysis.static_bytes_patch(
                session_id,
                address=address,
                hex=hex,
                base64=base64,
            )
        )

    def static_batch(
        session_id: str,
        commands: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Run up to 32 static worker commands in one round-trip."""
        return _dump(analysis.static_batch(session_id, commands=commands))

    specs: list[BoundTool] = []
    for name, fn in (
        ("static.segments", static_segments),
        ("static.imports", static_imports),
        ("static.exports", static_exports),
        ("static.entrypoints", static_entrypoints),
        ("static.disassemble", static_disassemble),
        ("static.xrefs_to", static_xrefs_to),
        ("static.xrefs_from", static_xrefs_from),
        ("static.callers", static_callers),
        ("static.callees", static_callees),
        ("static.basic_blocks", static_basic_blocks),
        ("static.cfg", static_cfg),
        ("static.globals", static_globals),
        ("static.names", static_names),
        ("static.types", static_types),
        ("static.structs", static_structs),
        ("static.enums", static_enums),
        ("static.bytes.read", static_bytes_read),
        ("static.search.bytes", static_search_bytes),
        ("static.search.text", static_search_text),
        ("static.search.immediate", static_search_immediate),
        ("static.name.set", static_name_set),
        ("static.comment.set", static_comment_set),
        ("static.type.apply", static_type_apply),
        ("static.function.create", static_function_create),
        ("static.function.delete", static_function_delete),
        ("static.bytes.patch", static_bytes_patch),
        ("static.batch", static_batch),
    ):
        specs.append(BoundTool(name, fn))
    return tuple(specs)

def build_workflow_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    """Register workflow.* tools via add_tool."""

    def workflow_status(session_id: str) -> dict[str, Any]:
        """Return the persistent workflow state attached to the x64dbg runtime."""
        return _dump(analysis.workflow_status(session_id))

    def workflow_reset(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Remove managed bindings and replace the workflow at the current event cursor."""
        return _dump(analysis.workflow_reset(session_id, timeout=timeout))

    def workflow_cancel(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Cancel active navigation and leave the debuggee stably paused when possible."""
        return _dump(analysis.workflow_cancel(session_id, timeout=timeout))

    def workflow_events_consume(
        session_id: str,
        limit: Annotated[int, Field(ge=1, le=MAX_DEBUG_EVENT_BATCH)] = (
            DEFAULT_DEBUG_EVENT_BATCH
        ),
        timeout: Annotated[float, Field(gt=0, le=30.0)] = 10.0,
    ) -> dict[str, Any]:
        """Consume the next shared event batch and apply workflow reconciliation."""
        return _dump(
            analysis.workflow_events_consume(
                session_id,
                limit=limit,
                timeout=timeout,
            )
        )

    def workflow_module_track(
        session_id: str,
        key: str,
        selector: ModuleSelector,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Track one explicit loaded module and its current rebased identity."""
        return _dump(
            analysis.workflow_module_track(
                session_id,
                key,
                selector,
                timeout=timeout,
            )
        )

    def workflow_module_untrack(
        session_id: str,
        key: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Stop tracking a module after removing managed native breakpoint bindings."""
        return _dump(
            analysis.workflow_module_untrack(
                session_id,
                key,
                timeout=timeout,
            )
        )

    def workflow_module_refresh(
        session_id: str,
        keys: list[str] | None = None,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Refresh selected tracked modules from one current modules.list snapshot."""
        return _dump(
            analysis.workflow_module_refresh(
                session_id,
                keys=keys,
                timeout=timeout,
            )
        )

    def workflow_breakpoint_put(
        session_id: str,
        intent_id: str,
        module_key: str,
        rva: Annotated[int, Field(ge=0)],
        enabled: bool = True,
        one_shot: bool = False,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Create or replace a managed RVA breakpoint intent and reconcile it."""
        return _dump(
            analysis.workflow_breakpoint_put(
                session_id,
                intent_id,
                module_key,
                rva,
                enabled=enabled,
                one_shot=one_shot,
                timeout=timeout,
            )
        )

    def workflow_breakpoint_disable(
        session_id: str,
        intent_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Disable an intent and remove its currently acknowledged binding."""
        return _dump(
            analysis.workflow_breakpoint_disable(
                session_id,
                intent_id,
                timeout=timeout,
            )
        )

    def workflow_breakpoint_remove(
        session_id: str,
        intent_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
    ) -> dict[str, Any]:
        """Remove a managed binding first, then delete its breakpoint intent."""
        return _dump(
            analysis.workflow_breakpoint_remove(
                session_id,
                intent_id,
                timeout=timeout,
            )
        )

    def workflow_breakpoint_list(session_id: str) -> dict[str, Any]:
        """List managed breakpoint intents and their acknowledged native bindings."""
        return _dump(analysis.workflow_breakpoint_list(session_id))

    def workflow_navigate_to_event(
        session_id: str,
        kind: str,
        fields: dict[str, str | int | bool] | None = None,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
        event_budget: Annotated[int, Field(ge=1, le=100_000)] = 1024,
    ) -> dict[str, Any]:
        """Resume and consume bounded events until a strict event pattern matches."""
        return _dump(
            analysis.workflow_navigate_to_event(
                session_id,
                kind,
                fields=fields,
                timeout=timeout,
                event_budget=event_budget,
            )
        )

    def workflow_navigate_to_breakpoint(
        session_id: str,
        intent_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
        event_budget: Annotated[int, Field(ge=1, le=100_000)] = 1024,
    ) -> dict[str, Any]:
        """Reconcile an intent, resume, and stop at its bounded breakpoint hit event."""
        return _dump(
            analysis.workflow_navigate_to_breakpoint(
                session_id,
                intent_id,
                timeout=timeout,
                event_budget=event_budget,
            )
        )

    specs: list[BoundTool] = []
    for name, fn in (
        ("workflow.status", workflow_status),
        ("workflow.reset", workflow_reset),
        ("workflow.cancel", workflow_cancel),
        ("workflow.events.consume", workflow_events_consume),
        ("workflow.module.track", workflow_module_track),
        ("workflow.module.untrack", workflow_module_untrack),
        ("workflow.module.refresh", workflow_module_refresh),
        ("workflow.breakpoint.put", workflow_breakpoint_put),
        ("workflow.breakpoint.disable", workflow_breakpoint_disable),
        ("workflow.breakpoint.remove", workflow_breakpoint_remove),
        ("workflow.breakpoint.list", workflow_breakpoint_list),
        ("workflow.navigate_to_event", workflow_navigate_to_event),
        ("workflow.navigate_to_breakpoint", workflow_navigate_to_breakpoint),
    ):
        specs.append(BoundTool(name, fn))
    return tuple(specs)

def build_dotnet_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    """Register dotnet.* tools via add_tool."""

    def dotnet_inspect(
        session_id: str,
        require_verified: bool = False,
    ) -> dict[str, Any]:
        """Inspect CLR headers/metadata; refuse unverified inputs when required."""
        return _dump(
            analysis.dotnet_inspect(
                session_id,
                require_verified=require_verified,
            )
        )

    def dotnet_deobfuscate(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0,
    ) -> dict[str, Any]:
        """Run configured de4dot into an artifact path; never overwrite the input."""
        return _dump(analysis.dotnet_deobfuscate(session_id, timeout=timeout))

    def dotnet_reactor_unpack(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0,
    ) -> dict[str, Any]:
        """Optional NETReactorSlayer unpack (authorized Reactor samples only)."""
        return _dump(analysis.dotnet_reactor_unpack(session_id, timeout=timeout))

    def dotnet_enumerate(
        session_id: str,
        kind: Annotated[
            str, Field(description="types|methods|fields|resources|strings")
        ],
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 64,
        require_verified: bool = True,
    ) -> dict[str, Any]:
        """Paginated CLR metadata enumeration (dotnet_metadata, not IDA)."""
        return _dump(
            analysis.dotnet_enumerate(
                session_id,
                kind,
                offset=offset,
                limit=limit,
                require_verified=require_verified,
            )
        )

    def dotnet_il(
        session_id: str,
        method_token: Annotated[int, Field(ge=0)],
        require_verified: bool = True,
    ) -> dict[str, Any]:
        """Bounded CIL subset disassembly for MethodDef token 0x0600xxxx."""
        return _dump(
            analysis.dotnet_il(
                session_id,
                method_token,
                require_verified=require_verified,
            )
        )

    def dotnet_xrefs(
        session_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 64,
        require_verified: bool = True,
    ) -> dict[str, Any]:
        """Weak MemberRef xref listing (not a full callgraph / not IDA)."""
        return _dump(
            analysis.dotnet_xrefs(
                session_id,
                offset=offset,
                limit=limit,
                require_verified=require_verified,
            )
        )

    def dotnet_verify(
        session_id: str,
        path: str,
        require_verified: bool = True,
    ) -> dict[str, Any]:
        """Re-inspect a .NET artifact under the session artifact root."""
        return _dump(
            analysis.dotnet_verify(
                session_id,
                path,
                require_verified=require_verified,
            )
        )

    specs: list[BoundTool] = []
    for name, fn in (
        ("dotnet.inspect", dotnet_inspect),
        ("dotnet.deobfuscate", dotnet_deobfuscate),
        ("dotnet.reactor.unpack", dotnet_reactor_unpack),
        ("dotnet.enumerate", dotnet_enumerate),
        ("dotnet.il", dotnet_il),
        ("dotnet.xrefs", dotnet_xrefs),
        ("dotnet.verify", dotnet_verify),
    ):
        specs.append(BoundTool(name, fn))
    return tuple(specs)

