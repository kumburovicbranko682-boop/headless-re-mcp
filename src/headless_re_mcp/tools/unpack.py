from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

from headless_re_mcp.core.models import Result
from headless_re_mcp.core.service import AnalysisService, JsonObject
from headless_re_mcp.detection.models import ScanMode
from headless_re_mcp.tools.binding import BoundTool, ToolSetBuilder
from headless_re_mcp.tools.limits import ExternalToolTimeout, RunControlTimeout


def _dump(result: Result[JsonObject]) -> dict[str, Any]:
    value = result.model_dump(mode="json")
    if not isinstance(value, dict):
        raise TypeError("result envelope did not serialize to an object")
    return value


def build_unpack_tools(analysis: AnalysisService) -> tuple[BoundTool, ...]:
    tools = ToolSetBuilder()
    @tools.tool(name="unpack.upx.test")
    def unpack_upx_test(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
    ) -> dict[str, Any]:
        """Run official ``upx -t`` on the session binary without modifying the input.

        Answers with upx (the CLI result, including ok, stdout, stderr and
        returncode) and input_unchanged. There is no top-level stdout field.
        """
        return _dump(analysis.unpack_upx_test(session_id, timeout=timeout))

    @tools.tool(name="unpack.upx.unpack")
    def unpack_upx_unpack(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
        open_ida: bool = False,
    ) -> dict[str, Any]:
        """Decompress with official ``upx -d`` into a session artifact path.

        Answers with upx, output_path, comparison, input_unchanged, die_rescan,
        reanalyze, and claims_universal_unpack false. There is no top-level
        stdout field.
        """
        return _dump(
            analysis.unpack_upx_unpack(
                session_id,
                timeout=timeout,
                open_ida=open_ida,
            )
        )

    @tools.tool(name="unpack.external.probe")
    def unpack_external_probe(session_id: str) -> dict[str, Any]:
        """Probe optional user-configured XVLKC / VMP dumper / Scylla without running them.

        Answers with xvlkc, vmp_dumper and scylla (each status, configured,
        executable), and claims_universal_unpack false.
        """
        return _dump(analysis.unpack_external_probe(session_id))

    @tools.tool(name="unpack.xvlkc.unpack")
    def unpack_xvlkc_unpack(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0,
    ) -> dict[str, Any]:
        """Optional XVLKC unpack into a session artifact; never overwrite input.

        Answers with xvlkc, output_path, input_unchanged, and
        claims_universal_unpack false.
        """
        return _dump(analysis.unpack_xvlkc_unpack(session_id, timeout=timeout))

    @tools.tool(name="unpack.vmp.dump")
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

    @tools.tool(name="unpack.scylla.rebuild")
    def unpack_scylla_rebuild(
        session_id: str,
        timeout: Annotated[float, Field(gt=0, le=600.0)] = 120.0,
    ) -> dict[str, Any]:
        """Optional Scylla IAT/dump helper into a session artifact; never overwrite input.

        Answers with scylla, output_path, input_unchanged, and
        claims_universal_unpack false.
        """
        return _dump(analysis.unpack_scylla_rebuild(session_id, timeout=timeout))

    @tools.tool(name="unpack.auto")
    def unpack_auto(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 60.0,
        open_ida: bool = False,
    ) -> dict[str, Any]:
        """Route detection to official UPX unpack when appropriate; never fake success.

        Answers with status, unpack, recommendation, and claims_universal_unpack
        false. status is unpacked, not_upx, awaiting_oep or routed_m6 — not a
        boolean.
        """
        return _dump(
            analysis.unpack_auto(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
                open_ida=open_ida,
            )
        )

    @tools.tool(name="unpack.plan")
    def unpack_plan(
        session_id: str,
        mode: ScanMode = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: Annotated[float, Field(gt=0, le=300.0)] = 30.0,
        force_route: str | None = None,
    ) -> dict[str, Any]:
        """Build a non-authoritative unpack plan without executing side effects.

        Answers with plan (route, backend), recommendation, pe_vm_like,
        force_route, and claims_universal_unpack false. There is no routes field.
        """
        return _dump(
            analysis.unpack_plan(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
                force_route=force_route,
            )
        )

    @tools.tool(name="unpack.start")
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

        Answers with unpack (phase, route, deadline_at) and
        claims_universal_unpack false. Active sessions are not overwritten
        unless replace=True. Optional force_route overrides detection.
        There is no session field at the top level.
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

    @tools.tool(name="unpack.status")
    def unpack_status(session_id: str) -> dict[str, Any]:
        """Return the current unpack orchestration state and timeline summary.

        Answers with unpack (phase, route, timeline, deadline_at) and
        claims_universal_unpack false. There is no status or timeline field at
        the top level.
        """
        return _dump(analysis.unpack_status(session_id))

    @tools.tool(name="unpack.cancel")
    def unpack_cancel(
        session_id: str,
        reason: str = "cancelled by caller",
    ) -> dict[str, Any]:
        """Stop unpack orchestration. Undoes nothing that already happened.

        The original input is never overwritten, but that is the only guarantee:
        dumps already written stay on disk and stay registered, and a debuggee
        whose memory the run altered keeps those changes. The reply says so as
        artifacts_retained and safe_rollback, which is worth reading before
        cancelling in order to retry, since the next attempt starts from what
        this one left behind.
        """
        return _dump(analysis.unpack_cancel(session_id, reason=reason))

    @tools.tool(name="unpack.artifacts")
    def unpack_artifacts(session_id: str) -> dict[str, Any]:
        """List unpack session artifacts and timeline/state paths.

        Answers with artifacts, count, timeline_path, state_path, and
        claims_universal_unpack false. There is no items field.
        """
        return _dump(analysis.unpack_artifacts(session_id))

    @tools.tool(name="unpack.score_oep")
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

    @tools.tool(name="unpack.confirm_oep")
    def unpack_confirm_oep(
        session_id: str,
        oep_rva: int,
        candidate_id: str | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        module_base: int | None = None,
        auto_dump: bool = False,
        dump_timeout: RunControlTimeout = 60.0,
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

    @tools.tool(name="unpack.dump_module")
    def unpack_dump_module(
        session_id: str,
        base: int,
        size: int | None = None,
        save_headers: bool = True,
        timeout: RunControlTimeout = 60.0,
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

    @tools.tool(name="unpack.stub_coupling")
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

    @tools.tool(name="unpack.iat.scan")
    def unpack_iat_scan(
        session_id: str,
        module_base: int,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int = 8,
        mode: str = "all",
        timeout: RunControlTimeout = 60.0,
    ) -> dict[str, Any]:
        """List IAT candidates; caller must confirm before rebuild."""
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

    @tools.tool(name="unpack.iat.validate")
    def unpack_iat_validate(
        session_id: str,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        module_base: int | None = None,
        dump_path: str | None = None,
        timeout: RunControlTimeout = 30.0,
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

    @tools.tool(name="unpack.iat.rebuild")
    def unpack_iat_rebuild(
        session_id: str,
        dump_path: str,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        timeout: RunControlTimeout = 60.0,
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

    @tools.tool(name="unpack.pe.rebuild")
    def unpack_pe_rebuild(
        session_id: str,
        dump_path: str,
        entry_point_rva: int | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        timeout: RunControlTimeout = 60.0,
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

    @tools.tool(name="unpack.verify")
    def unpack_verify(
        session_id: str,
        path: str,
        use_die: bool = True,
        open_ida: bool = False,
        baseline_session_id: str | None = None,
        # Wider than run control: open_ida can sit through a full idalib analysis.
        timeout: ExternalToolTimeout = 60.0,
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
    return tools.bindings
