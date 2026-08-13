from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import ModuleSelector, Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_meta_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="sync.static_to_runtime")
    def sync_static_to_runtime(session_id: str, address: int) -> dict[str, Any]:
        """Map an IDA address to the matching loaded main-module runtime address."""
        return _dump(analysis.sync_static_to_runtime(session_id, address))

    @tools.tool(name="sync.runtime_to_static")
    def sync_runtime_to_static(session_id: str, address: int) -> dict[str, Any]:
        """Map a loaded main-module runtime address back to its IDA address."""
        return _dump(analysis.sync_runtime_to_static(session_id, address))

    @tools.tool(name="sync.module_preferred_to_runtime")
    def sync_module_preferred_to_runtime(
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> dict[str, Any]:
        """Map an explicitly selected PE preferred VA to its current runtime VA."""
        return _dump(analysis.sync_module_preferred_to_runtime(session_id, selector, address))

    @tools.tool(name="sync.module_runtime_to_preferred")
    def sync_module_runtime_to_preferred(
        session_id: str,
        selector: ModuleSelector,
        address: int,
    ) -> dict[str, Any]:
        """Map an explicitly selected runtime VA back to its PE preferred VA."""
        return _dump(analysis.sync_module_runtime_to_preferred(session_id, selector, address))

    @tools.tool(name="sync.resolve_runtime_address")
    def sync_resolve_runtime_address(
        session_id: str,
        address: int,
        source: str = "static",
    ) -> dict[str, Any]:
        """Resolve a static VA, module RVA, or runtime VA to the live runtime VA.

        source is one of static (IDA address), rva (module offset) or runtime.
        The reply carries a top-level runtime_address, so callers never compute
        rebase deltas themselves before setting breakpoints or reading memory.
        """
        return _dump(analysis.resolve_runtime_address(session_id, address, source=source))

    @tools.tool(name="capabilities.search")
    def capabilities_search(
        backend: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        """Search discovered backend capabilities and readiness."""
        return _dump(analysis.capabilities_search(backend=backend, status=status))

    @tools.tool(name="capabilities.describe")
    def capabilities_describe(capability_id: str) -> dict[str, Any]:
        """Describe one capability id from the catalog."""
        return _dump(analysis.capabilities_describe(capability_id))

    @tools.tool(name="artifacts.list")
    def artifacts_list(
        session_id: str | None = None,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 50,
    ) -> dict[str, Any]:
        """List registered artifacts, newest first, with id, kind, size and path.

        Omit session_id for every artifact this instance knows about. Paged; the
        reply carries total and has_more.
        """
        return _dump(analysis.artifacts_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="artifacts.describe")
    def artifacts_describe(artifact_id: str) -> dict[str, Any]:
        """Metadata for one artifact: kind, size, sha256, origin and path."""
        return _dump(analysis.artifacts_describe(artifact_id))

    @tools.tool(name="artifacts.read")
    def artifacts_read(
        artifact_id: str, offset: int = 0, limit: Annotated[int, Field(ge=1, le=262144)] = 4096
    ) -> dict[str, Any]:
        """Read a byte range of one artifact, including text spilled out of a reply.

        A decompilation or disassembly too large to return inline is registered
        as an artifact and answered with artifact_id; this is how the rest of it
        is retrieved.
        """
        return _dump(analysis.artifacts_read(artifact_id, offset=offset, limit=limit))

    @tools.tool(name="artifacts.gc")
    def artifacts_gc(max_total_bytes: int = 512 * 1024 * 1024) -> dict[str, Any]:
        """Delete registered artifacts, oldest first, until the tree fits the budget.

        This destroys files. Collection also runs on its own after registration
        and session close, so calling it by hand is for reclaiming space now,
        not for routine upkeep. The newest artifact and any file another handle
        still holds are kept.
        """
        return _dump(analysis.artifacts_gc(max_total_bytes=max_total_bytes))

    @tools.tool(name="timeline.list")
    def timeline_list(
        session_id: str, offset: int = 0, limit: Annotated[int, Field(ge=1, le=256)] = 100
    ) -> dict[str, Any]:
        """What a session did that left a mark: opened, closed, wrote, drove a UI.

        Not a log of every call. Reads are absent, so a session that analysed
        for an hour without changing anything shows only its open and close.
        Each write carries the undo record written alongside it.
        """
        return _dump(analysis.timeline_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="sessions.unclean")
    def sessions_unclean() -> dict[str, Any]:
        """Every session that has not been closed cleanly, which includes live ones.

        A session is marked clean only by session.close, so one that is open and
        working right now appears here exactly like one abandoned by a process
        that died. This is not a list of sessions that are safe to clean up.
        Cross-check session.list, which covers only this process, and
        session.health before acting on anything here.
        """
        return _dump(analysis.sessions_unclean())

    @tools.tool(name="audit.list")
    def audit_list(
        session_id: str | None = None,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=256)] = 50,
    ) -> dict[str, Any]:
        """Session opens, session closes and UI drives, with arguments and outcome.

        Narrower than it sounds: a static write appears in timeline.list rather
        than here. Use this to ask which sessions ran and how they ended, and
        timeline.list to ask what one of them changed.
        """
        return _dump(analysis.audit_list(session_id, offset=offset, limit=limit))

    @tools.tool(name="session.health")
    def session_health(session_id: str | None = None) -> dict[str, Any]:
        """Report whether each open backend is alive and still connected.

        Checks on call rather than returning the last sweep, and rebuilds a
        dropped connection in place. A dead worker is reported rather than
        restarted, because a restarted debugger is attached to nothing; use
        session.recover once you are ready to relaunch.
        """
        return _dump(analysis.session_health(session_id))

    @tools.tool(name="session.recover")
    def session_recover(
        session_id: str,
        backends: list[str] | None = None,
    ) -> dict[str, Any]:
        """Re-open backends whose worker process died, without resuming execution.

        Defaults to the backends this session already had; pass ida/x64dbg to
        force specific ones. A recovered dynamic backend is attached to nothing,
        so relaunch or reattach explicitly afterwards.
        """
        return _dump(analysis.session_recover(session_id, backends))

    @tools.tool(name="batch.analyze")
    def batch_analyze(
        binaries: list[str],
        max_workers: Annotated[int, Field(ge=1, le=8)] = 2,
        open_static: bool = True,
    ) -> dict[str, Any]:
        """Create one session per binary with bounded parallelism.

        Entries fail independently so one unreadable sample cannot abort the
        batch; parallelism is capped because each static backend is a process.
        """
        return _dump(
            analysis.batch_analyze(
                binaries,
                max_workers=max_workers,
                open_static=open_static,
            )
        )

    @tools.tool(name="knowledge.record")
    def knowledge_record(
        session_id: str,
        kind: str,
        key: str,
        value: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record one durable analysis fact, idempotent per kind and key.

        Use kinds such as function, breakpoint, struct or api so later queries and
        the generated report can group what the analysis actually learned.
        """
        return _dump(analysis.knowledge_record(session_id, kind, key, value))

    @tools.tool(name="knowledge.query")
    def knowledge_query(
        session_id: str,
        kind: str | None = None,
        offset: int = 0,
        limit: Annotated[int, Field(ge=1, le=500)] = 100,
    ) -> dict[str, Any]:
        """Read accumulated analysis facts for a session, optionally one kind."""
        return _dump(
            analysis.knowledge_query(
                session_id,
                kind=kind,
                offset=offset,
                limit=limit,
            )
        )

    @tools.tool(name="report.generate")
    def report_generate(
        session_id: str,
        title: str | None = None,
        include_audit: bool = True,
        audit_limit: Annotated[int, Field(ge=1, le=200)] = 30,
    ) -> dict[str, Any]:
        """Render a Markdown analysis report from session state, findings and audit."""
        return _dump(
            analysis.report_generate(
                session_id,
                title=title,
                include_audit=include_audit,
                audit_limit=audit_limit,
            )
        )

    @tools.tool(name="meta.metrics")
    def meta_metrics(
        limit: Annotated[int, Field(ge=0, le=200)] = 20,
    ) -> dict[str, Any]:
        """Per-tool call counts, failures and latency percentiles for this process.

        Sampled from a bounded ring of recent calls; the same records are emitted
        as structured JSON log lines under the headless_re_mcp.telemetry logger.
        """
        return _dump(analysis.tool_metrics(limit=limit))
    return tools.bindings
