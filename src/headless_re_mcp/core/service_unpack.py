"""Unpacking: routing, the staged session, dumping, IAT repair and verification.

The largest surface split out of AnalysisService, and the one that reaches
furthest: unpacking drives the static backend, the dynamic backend, the detector
and the .NET tools in turn, which is why it needs so many of the facade's own
methods declared below.

Nothing here claims a universal unpacker. Every route is explicit, every stage
is gated on evidence the previous one produced, and a failed verification leaves
the session in a state that says so rather than presenting a partial dump as a
result. Behaviour is unchanged by the move.
"""

from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path
from threading import Event
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from headless_re_mcp.backends.common.bounded_run import BoundedCancelled, bound_cancel_scope
from headless_re_mcp.core.limits import rebuild_would_exhaust_memory
from headless_re_mcp.core.models import BackendKind, Result, RpcError, SessionState
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_detect import _detection_timeout
from headless_re_mcp.core.service_ext import _register_capture
from headless_re_mcp.core.session import InvalidStateTransition, file_sha256
from headless_re_mcp.core.windows import list_process_windows
from headless_re_mcp.detection import PeFormatError, ScanMode, scan_pe
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.iat_rank import (
    analyze_import_entries,
    gate_iat_rebuild,
    rank_iat_candidates,
)
from headless_re_mcp.unpack.observe import (
    collect_oep_observations,
    stub_rva_ranges_from_sections,
)
from headless_re_mcp.unpack.oep import score_oep_candidates
from headless_re_mcp.unpack.pause_quality import assess_pause_quality
from headless_re_mcp.unpack.pe_rebuild import (
    PeRebuildError,
    parse_runtime_headers,
    rebuild_imports,
    remap_dump_to_file,
    write_rebuilt_pe,
)
from headless_re_mcp.unpack.phase_bridge import (
    note_dump_success,
    note_imports_rebuilt,
    note_verified,
)
from headless_re_mcp.unpack.plan import build_unpack_plan
from headless_re_mcp.unpack.recommend import pe_suggests_vm_protector, recommend_unpack_route
from headless_re_mcp.unpack.session import (
    UnpackPhase,
    UnpackSessionError,
    UnpackSessionState,
    add_artifact,
    append_timeline,
    cancel_unpack_session,
    check_timeout,
    create_unpack_session,
    ensure_unpack_active,
    fail_unpack_session,
    persist_state_snapshot,
    transition,
    write_timeline_jsonl,
)
from headless_re_mcp.unpack.stage_labels import (
    STAGE_DUMPED,
    STAGE_IAT_REBUILT,
    STAGE_RUNNABLE,
    gate_stage_upgrade,
    resolve_artifact_kind_for_stage,
)
from headless_re_mcp.unpack.stub_calls import analyze_dump_stub_coupling

if TYPE_CHECKING:
    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.repository import AnalysisRepository
    from headless_re_mcp.core.runtime_state import BackendRuntimeOwner, UnpackStateOwner
    from headless_re_mcp.core.service import DieScanner, _BackendRuntime
    from headless_re_mcp.core.session import SessionRegistry

JsonObject = dict[str, Any]

# How many memory regions one OEP scoring pass will look at.
_OEP_REGION_SNAPSHOT_LIMIT = 512


def _refuse_rebuild_that_will_not_fit(
    path: Path, *, observed_size: int | None = None
) -> Result[JsonObject] | None:
    """Refuse a rebuild whose peak would not fit in memory, before allocating.

    Rebuilding holds the dump, the rebuilt image and working copies at once:
    measured at 3.0x the dump size for 64 MB and 4.0x for 256 MB. A dump of a
    few gigabytes therefore does not fail, it takes the process down -- and an
    unattended run loses every open session with it. The estimate is compared
    against memory actually free, so a large machine is not refused work it can
    do; when free memory cannot be determined the rebuild goes ahead.
    """
    if observed_size is None:
        try:
            size = path.stat().st_size
        except OSError:
            return None
    else:
        size = observed_size
    too_big, estimate, available = rebuild_would_exhaust_memory(size)
    if not too_big:
        return None
    return Result[JsonObject](
        ok=False,
        error=RpcError(
            code="dump_too_large",
            message=(
                f"rebuilding this {size / 1048576:.0f} MB dump needs about "
                f"{estimate / 1048576:.0f} MB, and only {(available or 0) / 1048576:.0f} MB "
                "is free; dump a narrower range or free memory first"
            ),
            details={
                "dump_bytes": size,
                "estimated_peak_bytes": estimate,
                "available_bytes": available,
            },
        ),
    )


def _read_dump_for_rebuild(
    path: Path,
) -> tuple[bytes | None, Result[JsonObject] | None]:
    """Bind the memory check and bounded read to the same open file handle."""
    with path.open("rb") as stream:
        observed_size = os.fstat(stream.fileno()).st_size
        refusal = _refuse_rebuild_that_will_not_fit(
            path, observed_size=observed_size
        )
        if refusal is not None:
            return None, refusal
        payload = stream.read(observed_size + 1)
    if len(payload) != observed_size:
        raise PeRebuildError("dump changed size while it was being read")
    return payload, None


class UnpackMixin:
    """Routing, staged unpack sessions, dumping, IAT repair and verification."""

    settings: Settings
    registry: SessionRegistry
    repository: AnalysisRepository
    _die_scanner: DieScanner
    _runtime_owner: BackendRuntimeOwner[_BackendRuntime]
    _unpack_owner: UnpackStateOwner[UnpackSessionState]
    _unpack_cancel_events: dict[str, Event]

    if TYPE_CHECKING:

        def _runtime(self, session_id: str, kind: BackendKind) -> _BackendRuntime: ...

        def _unpack_cancel_event(self, session_id: str) -> Event: ...

        def _reset_unpack_cancel(self, session_id: str) -> Event: ...

        def _signal_unpack_cancel(self, session_id: str) -> None: ...

        def _clear_unpack_cancel(self, session_id: str) -> None: ...

        def create_session(self, binary: str) -> Result[JsonObject]: ...

        def open_static(self, session_id: str) -> Result[JsonObject]: ...

        def static_functions(
            self,
            session_id: str,
            *,
            offset: int = 0,
            limit: int = 100,
        ) -> Result[JsonObject]: ...

        def dynamic_modules(self, session_id: str) -> Result[JsonObject]: ...

        def dynamic_pause(
            self,
            session_id: str,
            *,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def dynamic_registers_read(self, session_id: str) -> Result[JsonObject]: ...

        def memory_regions(
            self,
            session_id: str,
            *,
            offset: int = 0,
            limit: int | None = None,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def modules_dump(
            self,
            session_id: str,
            base: int,
            *,
            size: int | None = None,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def pe_headers_runtime(
            self,
            session_id: str,
            base: int,
            *,
            save_artifact: bool = True,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def imports_scan(
            self,
            session_id: str,
            module_base: int,
            *,
            search_start: int | None = None,
            search_size: int | None = None,
            max_candidates: int = 8,
            mode: str = "all",
            timeout: float = 60.0,
        ) -> Result[JsonObject]: ...

        def imports_read(
            self,
            session_id: str,
            iat_va: int,
            size: int,
            *,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def packer_classify(
            self,
            session_id: str,
            *,
            mode: ScanMode | str = ScanMode.NORMAL,
            use_die: bool = True,
            use_exeinfope: bool = False,
            timeout: float = 30.0,
        ) -> Result[JsonObject]: ...

        def dotnet_inspect(
            self,
            session_id: str,
            *,
            require_verified: bool = False,
        ) -> Result[JsonObject]: ...

        # From UnpackCliMixin: the official UPX CLI wrappers this routes to.
        def unpack_upx_test(
            self,
            session_id: str,
            *,
            timeout: float = 60.0,
        ) -> Result[JsonObject]: ...

        def unpack_upx_unpack(
            self,
            session_id: str,
            *,
            timeout: float = 60.0,
            open_ida: bool = False,
        ) -> Result[JsonObject]: ...

    def unpack_dump_module(
        self,
        session_id: str,
        base: int,
        *,
        size: int | None = None,
        save_headers: bool = True,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Dump a module by runtime size and optionally preserve PE headers."""
        blocked = self._guard_unpack_active(session_id, stage="dump_module")
        if blocked is not None:
            return blocked
        dumped = self.modules_dump(session_id, base, size=size, timeout=timeout)
        if not dumped.ok or dumped.data is None:
            return dumped
        blocked = self._guard_unpack_active(session_id, stage="dump_module_headers")
        if blocked is not None:
            # Dump file may already exist; retain it, do not advance phase.
            payload = dict(dumped.data)
            payload["claims_universal_unpack"] = False
            payload["aborted_after_dump"] = True
            payload["partial_artifacts_retained"] = True
            payload["safe_rollback"] = False
            return Result[JsonObject](
                ok=False,
                error=blocked.error,
                data=payload,
                meta=blocked.meta,
            )
        payload = dict(dumped.data)
        payload["claims_universal_unpack"] = False
        if save_headers:
            headers = self.pe_headers_runtime(
                session_id,
                base,
                save_artifact=True,
                timeout=timeout,
            )
            payload["headers"] = headers.data if headers.ok else None
            payload["headers_ok"] = headers.ok
            if not headers.ok and headers.error is not None:
                payload["headers_error"] = headers.error.model_dump()
        blocked = self._guard_unpack_active(session_id, stage="dump_module_advance")
        if blocked is not None:
            payload["aborted_before_phase_advance"] = True
            payload["partial_artifacts_retained"] = True
            payload["safe_rollback"] = False
            return Result[JsonObject](
                ok=False,
                error=blocked.error,
                data=payload,
                meta=blocked.meta,
            )
        output_path = str(payload.get("output_path", "") or "")
        output_sha = str(payload.get("sha256", "") or "")
        if output_path and output_sha:
            self._advance_unpack_after_dump(
                session_id,
                path=output_path,
                sha256=output_sha,
            )
        return _success(payload, session_id=session_id, backend="unpack")
    def unpack_stub_coupling(
        self,
        session_id: str,
        dump_path: str,
        *,
        iat_va: int | None = None,
        iat_size: int | None = None,
        module_base: int | None = None,
    ) -> Result[JsonObject]:
        """Analyze a dump for E8→VMP stub coupling vs FF15/FF25 API sites (MCP-facing)."""
        try:
            blocked = self._guard_unpack_active(session_id, stage="stub_coupling")
            if blocked is not None:
                return blocked
            path = Path(dump_path).expanduser().resolve(strict=True)
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in path.parents and path.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                        details={"dump_path": str(path), "artifact_root": str(artifact_root)},
                    ),
                )
            coupling = analyze_dump_stub_coupling(
                path,
                iat_va=iat_va,
                iat_size=iat_size,
                image_base=module_base,
            )
            analysis_gate = None
            pause = None
            if coupling.get("ok"):
                still = coupling.get("still_vm_stub_count")
                still_i = int(still) if isinstance(still, int) else None
                # Layout-less gate from stub stats alone for recoverability hint.
                fake_layout = {
                    "api_count": int(coupling.get("api_call_site_count") or 0),
                    "layout": "fragmented",
                    "ime_dominated": False,
                    "rebuild_allowed": False,
                    "rebuild_block_reason": "stub_coupling_only",
                }
                analysis_gate = gate_iat_rebuild(
                    fake_layout,
                    still_vm_stub_count=still_i,
                    min_api=0,
                )
                pause = assess_pause_quality(
                    ui_visible=None,
                    layout="fragmented",
                    rebuild_allowed=False,
                    recoverability=str(analysis_gate.get("recoverability") or ""),
                    still_vm_stub_count=still_i,
                    api_call_site_count=int(coupling.get("api_call_site_count") or 0),
                    code_nonzero_ratio=(
                        float(coupling["code_nonzero_ratio"])
                        if isinstance(coupling.get("code_nonzero_ratio"), (int, float))
                        else None
                    ),
                )
            payload: JsonObject = {
                "stub_coupling": coupling,
                "rebuild_gate_hint": analysis_gate,
                "pause_quality": pause,
                "stage_label": STAGE_DUMPED,
                "claims_universal_unpack": False,
                "note": (
                    "E8→VMP dominance implies vm_coupled_dump_only; "
                    "IAT rebuild alone cannot produce runnable PE"
                ),
            }
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_iat_scan(
        self,
        session_id: str,
        module_base: int,
        *,
        search_start: int | None = None,
        search_size: int | None = None,
        max_candidates: int = 8,
        mode: str = "all",
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """MCP-facing IAT candidate scan; caller must confirm before rebuild."""
        blocked = self._guard_unpack_active(session_id, stage="iat_scan")
        if blocked is not None:
            return blocked
        scanned = self.imports_scan(
            session_id,
            module_base,
            search_start=search_start,
            search_size=search_size,
            max_candidates=max(max_candidates * 3, 24),
            mode=mode,
            timeout=timeout,
        )
        if not scanned.ok or scanned.data is None:
            return scanned
        data = dict(scanned.data)
        raw_candidates = data.get("candidates")
        if not isinstance(raw_candidates, list):
            raw_candidates = []
        # Ask native for a wider pool then rank/dedupe locally.
        ranked = rank_iat_candidates(
            raw_candidates,
            module_base=module_base,
            module_size=int(data["module_size"])
            if isinstance(data.get("module_size"), int)
            else None,
            max_candidates=max_candidates,
        )
        data["raw_candidates"] = raw_candidates
        data["candidates"] = ranked["candidates"]
        data["candidate_count"] = ranked["candidate_count"]
        data["raw_candidate_count"] = ranked["raw_candidate_count"]
        data["best"] = ranked.get("best")
        data["confirmed"] = False
        data["claims_universal_unpack"] = False
        data["blind_selection"] = False
        data["next"] = (
            "Caller must confirm one candidate via unpack.iat.validate "
            "(iat_va, size, optional oep_rva) before rebuild. "
            "IME/high-RVA noise is down-ranked; half-sparse layouts need validate."
        )
        return _success(data, session_id=session_id, backend="unpack")
    def unpack_iat_validate(
        self,
        session_id: str,
        *,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        module_base: int | None = None,
        dump_path: str | None = None,
        timeout: float = 30.0,
    ) -> Result[JsonObject]:
        """Validate a caller-confirmed IAT range and optionally record OEP RVA."""
        blocked = self._guard_unpack_active(session_id, stage="iat_validate")
        if blocked is not None:
            return blocked
        read = self.imports_read(session_id, iat_va, size, timeout=timeout)
        if not read.ok or read.data is None:
            return read
        data = dict(read.data)
        entries = data.get("entries")
        if not isinstance(entries, list):
            entries = []
        pointer_size = (
            8
            if any(
                isinstance(item, dict) and int(item.get("value") or 0) > 0xFFFFFFFF
                for item in entries[:8]
            )
            else 4
        )
        analysis = analyze_import_entries(entries, pointer_size=pointer_size)
        stub_coupling: JsonObject | None = None
        still_vm_stub_count: int | None = None
        if dump_path:
            dump = Path(dump_path).expanduser().resolve()
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in dump.parents and dump.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                        details={"dump_path": str(dump), "artifact_root": str(artifact_root)},
                    ),
                )
            if not dump.is_file():
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path does not exist",
                        details={"dump_path": str(dump)},
                    ),
                )
            stub_coupling = analyze_dump_stub_coupling(
                dump,
                iat_va=iat_va,
                iat_size=size,
                image_base=module_base,
            )
            if stub_coupling.get("ok") and isinstance(
                stub_coupling.get("still_vm_stub_count"), int
            ):
                still_vm_stub_count = int(stub_coupling["still_vm_stub_count"])
        gate = gate_iat_rebuild(analysis, still_vm_stub_count=still_vm_stub_count)
        code_nonzero_ratio = None
        if isinstance(stub_coupling, dict) and isinstance(
            stub_coupling.get("code_nonzero_ratio"), (int, float)
        ):
            code_nonzero_ratio = float(stub_coupling["code_nonzero_ratio"])
        pause = assess_pause_quality(
            ui_visible=None,
            layout=str(analysis.get("layout") or ""),
            rebuild_allowed=bool(gate.get("rebuild_allowed")),
            recoverability=str(gate.get("recoverability") or ""),
            still_vm_stub_count=still_vm_stub_count,
            api_call_site_count=(
                int(stub_coupling["api_call_site_count"])
                if isinstance(stub_coupling, dict)
                and isinstance(stub_coupling.get("api_call_site_count"), int)
                else None
            ),
            resolved_ratio=float(analysis.get("resolved_ratio") or 0.0),
            code_nonzero_ratio=code_nonzero_ratio,
        )
        # Empty/encrypted CODE means pause is not IAT-ready even if layout looks dense.
        if code_nonzero_ratio is not None and code_nonzero_ratio < 0.05:
            gate = dict(gate)
            gate["rebuild_allowed"] = False
            gate["reasons"] = list(gate.get("reasons") or []) + [
                f"code_not_decrypted:nonzero_ratio={code_nonzero_ratio:.4f}"
            ]
            if gate.get("recoverability") == "iat_recoverable":
                gate["recoverability"] = "iat_insufficient"
        stage_gate = gate_stage_upgrade(
            current_stage=STAGE_DUMPED,
            target_stage=STAGE_IAT_REBUILT,
            rebuild_allowed=bool(gate.get("rebuild_allowed")),
            pause_iat_ready=bool(pause.get("iat_ready")),
        )
        resolved = int(analysis.get("api_count") or 0)
        total = int(analysis.get("slot_count") or 0)
        confidence = float(analysis.get("resolved_ratio") or 0.0)
        confirmed = bool(gate.get("rebuild_allowed")) and bool(pause.get("iat_ready"))
        data.update(
            {
                "confirmed": confirmed,
                "oep_rva": oep_rva,
                "module_base": module_base,
                "null_count": analysis.get("null_count"),
                "unresolved_count": analysis.get("unresolved_count"),
                "ordinal_hint_count": 0,
                "confidence": confidence,
                "layout": analysis.get("layout"),
                "layout_analysis": analysis,
                "rebuild_gate": gate,
                "recoverability": gate.get("recoverability"),
                "stub_coupling": stub_coupling,
                "pause_quality": pause,
                "stage_label": STAGE_IAT_REBUILT if confirmed else STAGE_DUMPED,
                "stage_upgrade_gate": stage_gate,
                "forwarded_exports_detected": False,
                "unfixed": [
                    "forwarded exports are not expanded",
                    "caller must still run unpack.iat.rebuild / unpack.pe.rebuild",
                    "UI visible != IAT ready; confirmed requires rebuild+pause gates",
                    *[str(r) for r in (gate.get("reasons") or [])],
                    *[str(r) for r in (pause.get("reasons") or [])],
                ],
                "claims_universal_unpack": False,
                "resolved_count": resolved,
                "slot_count": total,
            }
        )
        if not confirmed:
            data["warnings"] = [
                "rebuild_gate blocked this range; refuse confirmed=true",
            ]
            data["unfixed"] = [
                *data["unfixed"],
                "IAT range not confirmed; rebuild would be speculative",
            ]
        return _success(data, session_id=session_id, backend="unpack")
    def unpack_iat_rebuild(
        self,
        session_id: str,
        dump_path: str,
        *,
        iat_va: int,
        size: int,
        oep_rva: int | None = None,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Rebuild import tables on a dumped PE using a confirmed IAT range."""
        try:
            blocked = self._guard_unpack_active(session_id, stage="iat_rebuild")
            if blocked is not None:
                return blocked
            path = Path(dump_path).expanduser().resolve(strict=True)
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in path.parents and path.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                        details={"dump_path": str(path), "artifact_root": str(artifact_root)},
                    ),
                )
            read = self.imports_read(session_id, iat_va, size, timeout=timeout)
            if not read.ok or read.data is None:
                return read
            blocked = self._guard_unpack_active(session_id, stage="iat_rebuild_write")
            if blocked is not None:
                return blocked
            entries = read.data.get("entries")
            if not isinstance(entries, list):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(code="invalid_iat", message="imports.read returned no entries"),
                )
            analysis = analyze_import_entries(entries)
            stub_coupling = analyze_dump_stub_coupling(
                path,
                iat_va=iat_va,
                iat_size=size,
            )
            still_vm_stub_count = (
                int(stub_coupling["still_vm_stub_count"])
                if stub_coupling.get("ok")
                and isinstance(stub_coupling.get("still_vm_stub_count"), int)
                else None
            )
            gate = gate_iat_rebuild(analysis, still_vm_stub_count=still_vm_stub_count)
            code_ratio = stub_coupling.get("code_nonzero_ratio")
            if isinstance(code_ratio, (int, float)) and float(code_ratio) < 0.05:
                gate = dict(gate)
                gate["rebuild_allowed"] = False
                gate["reasons"] = list(gate.get("reasons") or []) + [
                    f"code_not_decrypted:nonzero_ratio={float(code_ratio):.4f}"
                ]
                if gate.get("recoverability") == "iat_recoverable":
                    gate["recoverability"] = "iat_insufficient"
            if not gate.get("rebuild_allowed"):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="iat_rebuild_blocked",
                        message="IAT rebuild gate refused this range",
                        details={
                            "layout_analysis": analysis,
                            "rebuild_gate": gate,
                            "stub_coupling": stub_coupling,
                            "recoverability": gate.get("recoverability"),
                        },
                    ),
                )
            raw, refusal = _read_dump_for_rebuild(path)
            if refusal is not None:
                return refusal
            assert raw is not None
            # If dump looks like a pure memory image, remap first.
            try:
                pe_bytes, remap_report = remap_dump_to_file(raw, entry_point_rva=oep_rva)
            except PeRebuildError:
                pe_bytes = raw
                remap_report = None
            headers = parse_runtime_headers(pe_bytes)
            image_base = int(headers["image_base"])
            confirmed_iat_rva = iat_va - image_base if iat_va >= image_base else iat_va
            if type(confirmed_iat_rva) is not int or confirmed_iat_rva < 0:
                raise PeRebuildError("iat_va does not map to a usable IAT RVA")
            rebuilt, report = rebuild_imports(
                pe_bytes, entries, iat_rva=confirmed_iat_rva
            )
            blocked = self._guard_unpack_active(session_id, stage="iat_rebuild_advance")
            if blocked is not None:
                return blocked
            out_dir = artifact_root / "unpack" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"iat-rebuilt-{uuid4().hex}.exe"
            sha = write_rebuilt_pe(out_path, rebuilt)
            payload: JsonObject = {
                "input_path": str(path),
                "output_path": str(out_path),
                "sha256": sha,
                "iat_va": iat_va,
                "size": size,
                "oep_rva": oep_rva,
                "report": report.to_dict(),
                "rebuild_gate": gate,
                "stub_coupling": stub_coupling,
                "recoverability": gate.get("recoverability"),
                "stage_label": STAGE_IAT_REBUILT,
                "artifact_kind": "iat_rebuilt",
                "claims_universal_unpack": False,
            }
            if remap_report is not None:
                payload["remap_report"] = remap_report.to_dict()
            # Same leak as unpack.pe.rebuild: measured a 2048-byte
            # iat-rebuilt-*.exe with artifacts.list total=0, gc removed=0,
            # surviving close_all.
            payload = _register_capture(
                self,
                session_id,
                out_path,
                kind="iat_rebuilt",
                source="unpack.iat.rebuild",
                payload=payload,
            )
            try:
                verified = scan_pe(out_path)
                payload["pe_verify"] = {
                    "ok": True,
                    "architecture": verified.architecture,
                    "entry_point_rva": verified.pe.entry_point_rva,
                    "section_count": len(verified.pe.sections),
                    "import_function_count": verified.pe.imports.function_count,
                }
            except PeFormatError as exc:
                payload["pe_verify"] = {"ok": False, "error": str(exc)}
                report.unfixed.append(f"built-in PE parse failed: {exc}")
                payload["report"] = report.to_dict()
                # A rebuilt image the built-in parser rejects is not IAT-complete.
                # Returning ok and advancing the session used to send an unattended
                # agent into verify/reanalyze on a non-PE.
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_pe",
                        message=str(exc),
                        details={"pe_verify": payload["pe_verify"]},
                    ),
                    data=payload,
                    meta={"session_id": session_id, "backend": "unpack"},
                )
            self._advance_unpack_after_imports_rebuilt(
                session_id,
                path=str(out_path),
                sha256=sha,
                kind="iat_rebuilt",
            )
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_pe_rebuild(
        self,
        session_id: str,
        dump_path: str,
        *,
        entry_point_rva: int | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Remap a runtime dump to file layout and optionally rebuild imports."""
        try:
            blocked = self._guard_unpack_active(session_id, stage="pe_rebuild")
            if blocked is not None:
                return blocked
            path = Path(dump_path).expanduser().resolve(strict=True)
            artifact_root = self.settings.artifact_root.expanduser().resolve()
            if artifact_root not in path.parents and path.parent != artifact_root:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="dump_path must be inside the session artifact root",
                    ),
                )
            raw, refusal = _read_dump_for_rebuild(path)
            if refusal is not None:
                return refusal
            assert raw is not None
            rebuilt, report = remap_dump_to_file(raw, entry_point_rva=entry_point_rva)
            import_report = None
            if iat_va is not None and iat_size is not None:
                blocked = self._guard_unpack_active(session_id, stage="pe_rebuild_iat")
                if blocked is not None:
                    return blocked
                read = self.imports_read(session_id, iat_va, iat_size, timeout=timeout)
                if not read.ok or read.data is None:
                    return read
                entries = read.data.get("entries")
                if not isinstance(entries, list):
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="invalid_iat",
                            message="imports.read returned no entries",
                        ),
                    )
                rebuilt, import_report = rebuild_imports(rebuilt, entries)
            blocked = self._guard_unpack_active(session_id, stage="pe_rebuild_write")
            if blocked is not None:
                return blocked
            out_dir = artifact_root / "unpack" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"pe-rebuilt-{uuid4().hex}.exe"
            sha = write_rebuilt_pe(out_path, rebuilt)
            payload: JsonObject = {
                "input_path": str(path),
                "output_path": str(out_path),
                "sha256": sha,
                "entry_point_rva": entry_point_rva,
                "report": report.to_dict(),
                "claims_universal_unpack": False,
            }
            if import_report is not None:
                payload["import_report"] = import_report.to_dict()
            # Retention and artifacts.gc only see registered rows. Measured:
            # a 1024-byte pe-rebuilt-*.exe listed total=0, gc removed=0,
            # and survived close_session and close_all.
            payload = _register_capture(
                self,
                session_id,
                out_path,
                kind="pe_rebuilt",
                source="unpack.pe.rebuild",
                payload=payload,
            )
            # Structural verify with built-in parser.
            try:
                verified = scan_pe(out_path)
                payload["pe_verify"] = {
                    "ok": True,
                    "architecture": verified.architecture,
                    "entry_point_rva": verified.pe.entry_point_rva,
                    "section_count": len(verified.pe.sections),
                    "import_function_count": verified.pe.imports.function_count,
                }
            except PeFormatError as exc:
                payload["pe_verify"] = {"ok": False, "error": str(exc)}
                report.unfixed.append(f"built-in PE parse failed: {exc}")
                payload["report"] = report.to_dict()
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_pe",
                        message=str(exc),
                        details={"pe_verify": payload["pe_verify"]},
                    ),
                    data=payload,
                    meta={"session_id": session_id, "backend": "unpack"},
                )
            if import_report is not None:
                blocked = self._guard_unpack_active(session_id, stage="pe_rebuild_advance")
                if blocked is not None:
                    payload["aborted_before_phase_advance"] = True
                    payload["partial_artifacts_retained"] = True
                    payload["safe_rollback"] = False
                    return Result[JsonObject](
                        ok=False,
                        error=blocked.error,
                        data=payload,
                        meta=blocked.meta,
                    )
                self._advance_unpack_after_imports_rebuilt(
                    session_id,
                    path=str(out_path),
                    sha256=sha,
                    kind="pe_rebuilt",
                )
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_verify(
        self,
        session_id: str,
        path: str,
        *,
        use_die: bool = True,
        open_ida: bool = False,
        baseline_session_id: str | None = None,
        timeout: float = 60.0,
        expect_window_title: str | None = None,
        expect_window_class: str | None = None,
        ui_pid: int | None = None,
    ) -> Result[JsonObject]:
        """Re-parse a rebuilt PE with built-in parser, optional DIE, optional IDA compare.

        Optional UI gates (``expect_window_title`` / ``expect_window_class``) check a
        live process via Win32 enumeration when ``ui_pid`` is set or the session has
        an attached debuggee PID. Gates never claim universal unpack success.
        """
        try:
            session = self.registry.get(session_id)
            session.require_pe()
            # path is schema-typed as a string, but the agent and OpenAI-bridge
            # transports bind it straight from model output with no pydantic
            # coercion. Path(path) raises a raw TypeError on a non-str value
            # (int, list, None) that the except below filed as a logged
            # internal_error incident -- unlike the invalid_params the
            # ownership check right after answers for a bad *string* path.
            if not isinstance(path, str):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(code="invalid_params", message="path must be a string"),
                )
            target = Path(path).expanduser().resolve(strict=True)
            from headless_re_mcp.core.service import _session_owns_artifact_path

            if not _session_owns_artifact_path(
                self.settings.artifact_root, session_id, target
            ):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message=(
                            "path must be inside the current session artifact "
                            "directory (unpack/dump/dotnet/detection)"
                        ),
                        details={"path": str(target), "session_id": session_id},
                    ),
                )
            bounded_timeout = _detection_timeout(timeout)
            pe_report = scan_pe(target)
            payload: JsonObject = {
                "path": str(target),
                "sha256": pe_report.sha256,
                "architecture": pe_report.architecture,
                "pe": {
                    "entry_point_rva": pe_report.pe.entry_point_rva,
                    "section_count": len(pe_report.pe.sections),
                    "import_function_count": pe_report.pe.imports.function_count,
                    "dotnet": pe_report.pe.dotnet,
                },
                "claims_universal_unpack": False,
                "unfixed": [],
            }
            if use_die and self.settings.diec is not None:
                try:
                    die_result = self._die_scanner(
                        self.settings.diec,
                        target,
                        mode=ScanMode.NORMAL,
                        timeout=bounded_timeout,
                    )
                    payload["die"] = {
                        "status": "completed",
                        "version": die_result.source.version,
                        "finding_count": len(die_result.findings),
                        "findings": [
                            {
                                "category": finding.category.value
                                if hasattr(finding.category, "value")
                                else str(finding.category),
                                "name": finding.name,
                                "summary": finding.summary,
                            }
                            for finding in die_result.findings[:32]
                        ],
                    }
                except DieScanError as exc:
                    payload["die"] = {"status": "failed", "error": str(exc)}
                    payload["unfixed"].append(f"DIE rescan failed: {exc}")
            elif use_die:
                payload["die"] = {"status": "unavailable"}
                payload["unfixed"].append("DIE not configured")

            ida_compare: JsonObject | None = None
            if open_ida:
                child = self.create_session(str(target))
                if child.ok and child.data is not None:
                    child_id = str(child.data["session"]["id"])
                    opened = self.open_static(child_id)
                    ida_compare = {
                        "session_id": child_id,
                        "static_open_ok": opened.ok,
                    }
                    if baseline_session_id:
                        try:
                            base_funcs = self.static_functions(baseline_session_id)
                            new_funcs = self.static_functions(child_id) if opened.ok else None
                            ida_compare["baseline_functions"] = (
                                base_funcs.data if base_funcs.ok else None
                            )
                            ida_compare["rebuilt_functions"] = (
                                new_funcs.data if new_funcs and new_funcs.ok else None
                            )
                        except Exception as exc:  # noqa: BLE001 - compare is best-effort
                            ida_compare["compare_error"] = str(exc)
                            payload["unfixed"].append("IDA function compare incomplete")
                else:
                    ida_compare = {
                        "static_open_ok": False,
                        "error": child.error.model_dump() if child.error else None,
                    }
                    payload["unfixed"].append("IDA reopen failed")
            payload["ida"] = ida_compare
            ida_ok = bool(
                open_ida and isinstance(ida_compare, dict) and ida_compare.get("static_open_ok")
            )

            if expect_window_title is not None or expect_window_class is not None:
                gate_pid = ui_pid
                if gate_pid is None:
                    try:
                        runtime = self._runtime(session_id, BackendKind.X64DBG)
                        gate_pid = int(getattr(runtime.worker, "pid", 0) or 0) or None
                        # Prefer debuggee pid from last state if available.
                        state = getattr(runtime.worker, "last_state", None)
                        if isinstance(state, dict) and isinstance(state.get("pid"), int):
                            gate_pid = int(state["pid"])
                    except Exception:  # noqa: BLE001 - UI gate is best-effort
                        gate_pid = None
                ui_gate: JsonObject = {
                    "expect_window_title": expect_window_title,
                    "expect_window_class": expect_window_class,
                    "pid": gate_pid,
                    "matched": False,
                    "checked": False,
                }
                if gate_pid is None or type(gate_pid) is not int or gate_pid <= 0:
                    ui_gate["status"] = "skipped_no_pid"
                    payload["unfixed"].append("UI window gate skipped: no pid")
                else:
                    try:
                        windows = list_process_windows(gate_pid)
                        ui_gate["checked"] = True
                        ui_gate["window_count"] = len(windows)
                        matched = False
                        for window in windows:
                            title = str(window.get("title") or "")
                            class_name = str(window.get("class_name") or "")
                            title_ok = (
                                expect_window_title is None
                                or expect_window_title.casefold() in title.casefold()
                            )
                            class_ok = (
                                expect_window_class is None
                                or class_name == expect_window_class
                            )
                            if title_ok and class_ok:
                                matched = True
                                ui_gate["match"] = {
                                    "title": title,
                                    "class_name": class_name,
                                    "hwnd": window.get("hwnd"),
                                }
                                break
                        ui_gate["matched"] = matched
                        ui_gate["status"] = "matched" if matched else "not_matched"
                        if not matched:
                            payload["unfixed"].append("UI window title/class gate not matched")
                    except Exception as exc:  # noqa: BLE001
                        ui_gate["status"] = "error"
                        ui_gate["error"] = str(exc)
                        payload["unfixed"].append(f"UI window gate failed: {exc}")
                payload["ui_gate"] = ui_gate

            pe_ok = True
            pe_verify = payload.get("pe")
            if not isinstance(pe_verify, dict):
                pe_ok = False
            ui_matched = None
            ui_gate_payload = payload.get("ui_gate")
            if isinstance(ui_gate_payload, dict):
                ui_matched = bool(ui_gate_payload.get("matched"))
            runnable_gate = gate_stage_upgrade(
                current_stage=STAGE_IAT_REBUILT,
                target_stage=STAGE_RUNNABLE,
                rebuild_allowed=True,
                pe_verify_ok=pe_ok,
                ui_gate_matched=ui_matched,
            )
            artifact_kind = resolve_artifact_kind_for_stage(
                target_stage=STAGE_RUNNABLE,
                preferred_kind="runnable_pe",
                upgrade_gate=runnable_gate,
            )
            payload["stage_label"] = (
                STAGE_RUNNABLE if runnable_gate.get("allowed") else STAGE_IAT_REBUILT
            )
            payload["stage_upgrade_gate"] = runnable_gate
            payload["artifact_kind"] = artifact_kind
            if not runnable_gate.get("allowed"):
                payload["unfixed"].append(
                    "stage stays iat-rebuilt/verified; runnable requires UI+PE gates"
                )

            self._advance_unpack_after_verify(
                session_id,
                path=str(target),
                sha256=str(payload["sha256"]),
                open_ida=open_ida,
                ida_ok=ida_ok,
            )
            return _success(payload, session_id=session_id, backend="unpack")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_plan(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: float = 30.0,
        force_route: str | None = None,
    ) -> Result[JsonObject]:
        """Build a non-authoritative unpack plan without side effects."""
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"unpack.plan cannot run in {session.state.value} state"
                )
            classified = self.packer_classify(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
            )
            if not classified.ok or classified.data is None:
                return classified
            candidates = classified.data.get("candidates")
            if not isinstance(candidates, list):
                candidates = []
            session = self.registry.get(session_id)
            pe_report = scan_pe(session.require_pe())
            pe_vm_like = pe_suggests_vm_protector(
                finding_ids=tuple(item.id for item in pe_report.findings),
                section_names=tuple(section.name for section in pe_report.pe.sections),
            )
            recommendation = recommend_unpack_route(
                candidates,
                pe_dotnet=pe_report.pe.dotnet,
                pe_vm_like=pe_vm_like,
                force_route=force_route,
            )
            plan = build_unpack_plan(
                candidates,
                pe_dotnet=pe_report.pe.dotnet,
                pe_vm_like=pe_vm_like,
                force_route=force_route,
                recommendation=recommendation,
            )
            return _success(
                {
                    "plan": plan,
                    "recommendation": recommendation.to_dict(),
                    "pe_vm_like": pe_vm_like,
                    "force_route": force_route,
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_start(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: float = 120.0,
        open_ida: bool = False,
        execute_upx: bool = True,
        replace: bool = False,
        force_route: str | None = None,
    ) -> Result[JsonObject]:
        """Start an unpack orchestration session from the current detection plan.

        Refuses to silently overwrite a still-active unpack session unless
        ``replace=True``. Terminal phases ``failed`` / ``cancelled`` /
        ``reanalyzed`` may be restarted without the flag.
        """
        try:
            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"unpack.start cannot run in {session.state.value} state"
                )
            if type(replace) is not bool:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(code="invalid_params", message="replace must be a boolean"),
                )
            existing = self._unpack_owner.get(session_id)
            if existing is not None:
                checked = check_timeout(existing)
                if checked is not existing:
                    self._store_unpack_session(checked)
                    existing = checked
                # failed/cancelled/reanalyzed are restartable; verified and in-flight are not.
                restartable = {
                    UnpackPhase.FAILED,
                    UnpackPhase.CANCELLED,
                    UnpackPhase.REANALYZED,
                }
                if existing.phase not in restartable and not replace:
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="unpack_already_active",
                            message=(
                                "unpack session already active; pass replace=True to "
                                "explicitly start a new orchestration"
                            ),
                            details={
                                "phase": existing.phase.value,
                                "route": existing.route,
                                "replace_required": True,
                            },
                        ),
                        meta={"unpack": existing.to_dict()},
                    )
            planned = self.unpack_plan(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=min(timeout, 60.0),
                force_route=force_route,
            )
            if not planned.ok or planned.data is None:
                return planned
            plan = planned.data["plan"]
            assert isinstance(plan, dict)
            session = self.registry.get(session_id)
            route = str(plan.get("route", "none"))
            self._reset_unpack_cancel(session_id)
            state = create_unpack_session(
                session_id,
                route=route,
                plan=plan,
                timeout_seconds=timeout,
                input_sha256=session.sha256,
            )
            state = add_artifact(
                state,
                kind="input_binary",
                path=str(session.require_pe()),
                sha256=session.sha256 or "",
                phase=UnpackPhase.DETECTED,
            )
            bounded_probe: JsonObject | None = None

            if route == "upx" and execute_upx:
                with bound_cancel_scope(self._unpack_cancel_event(session_id)):
                    state = self._run_upx_orchestration(
                        state,
                        session_id,
                        timeout=timeout,
                        open_ida=open_ida,
                    )
            elif route == "dotnet":
                # Hand off to M6: run inspect only; never auto-deobfuscate or claim success.
                inspect = self.dotnet_inspect(session_id, require_verified=False)
                if not inspect.ok or inspect.data is None:
                    code = (
                        inspect.error.code if inspect.error is not None else "dotnet_inspect_failed"
                    )
                    state = fail_unpack_session(
                        state,
                        code=str(code),
                        message=(
                            inspect.error.message
                            if inspect.error is not None
                            else "dotnet.inspect failed on .NET unpack route"
                        ),
                        details={"route": route, "plan": plan},
                        retryable=True,
                    )
                    bounded_probe = {
                        "route": "dotnet",
                        "dotnet_inspect_ok": False,
                        "claims_universal_unpack": False,
                    }
                else:
                    kind = str(inspect.data.get("kind") or "")
                    verified = kind in {"pure_managed", "mixed_mode"}
                    state = append_timeline(
                        state,
                        event="routed_m6",
                        message=(
                            ".NET route handed to M6 after inspect; optional "
                            "dotnet.deobfuscate/verify next. No automatic deobfuscation."
                        ),
                        input_sha256=session.sha256,
                        details={
                            "route": route,
                            "clr_kind": kind,
                            "clr_verified": verified,
                            "next": (
                                ["dotnet.deobfuscate", "dotnet.verify"]
                                if verified
                                else ["dotnet.inspect", "dotnet.verify"]
                            ),
                        },
                    )
                    bounded_probe = {
                        "route": "dotnet",
                        "dotnet_inspect": inspect.data,
                        "clr_kind": kind,
                        "clr_verified": verified,
                        "next": (
                            ["dotnet.deobfuscate", "dotnet.verify"]
                            if verified
                            else ["dotnet.inspect", "dotnet.verify"]
                        ),
                        "claims_universal_unpack": False,
                    }
            elif route in {"generic_dynamic", "bounded_dynamic"}:
                state = transition(
                    state,
                    UnpackPhase.RUNNING,
                    event="awaiting_runtime",
                    message=(
                        "Native/VM route entered running phase; gather OEP observations "
                        "then call unpack.confirm_oep (heuristics are not authoritative)."
                    ),
                    input_sha256=session.sha256,
                    details={"route": route},
                )
                state, bounded_probe = self._bounded_runtime_probe(
                    state,
                    session_id,
                    route=route,
                )
            else:
                state = append_timeline(
                    state,
                    event="no_packer_route",
                    message="No packer route; prefer static analysis.",
                    input_sha256=session.sha256,
                )
                bounded_probe = None

            session = self.registry.get(session_id)
            if session.state in {
                SessionState.CLOSING,
                SessionState.CLOSED,
                SessionState.FAILED,
            }:
                raise InvalidStateTransition(
                    f"unpack.start cannot run in {session.state.value} state"
                )
            self._store_unpack_session(state)
            payload: JsonObject = {
                "unpack": state.to_dict(),
                "claims_universal_unpack": False,
            }
            if bounded_probe is not None:
                payload["bounded_probe"] = bounded_probe
            return _success(payload, session_id=session_id, backend="unpack")
        except BoundedCancelled:
            current = self._unpack_owner.get(session_id)
            if current is not None and current.phase not in {
                UnpackPhase.CANCELLED,
                UnpackPhase.FAILED,
                UnpackPhase.REANALYZED,
            }:
                current = cancel_unpack_session(current, reason="cancelled by caller")
                self._store_unpack_session(current)
            if current is not None:
                return _success(
                    {
                        "unpack": current.to_dict(),
                        "claims_universal_unpack": False,
                        "original_input_preserved": True,
                    },
                    session_id=session_id,
                    backend="unpack",
                )
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code="unpack_cancelled",
                    message="unpack cancelled by caller",
                    details={"session_id": session_id},
                ),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_status(self, session_id: str) -> Result[JsonObject]:
        """Return the current unpack orchestration state for a session."""
        try:
            self.registry.get(session_id).require_pe()
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session; call unpack.plan / unpack.start first",
                        details={"session_id": session_id},
                    ),
                )
            checked = check_timeout(state)
            if checked is not state:
                self._store_unpack_session(checked)
                state = checked
            return _success(
                {"unpack": state.to_dict(), "claims_universal_unpack": False},
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_cancel(
        self,
        session_id: str,
        *,
        reason: str = "cancelled by caller",
    ) -> Result[JsonObject]:
        """Cancel an active unpack session without modifying the original input.

        Cancel is not a rollback: dumps and other artifacts are retained, and the
        original input binary is left untouched. If a dynamic backend is open,
        a best-effort pause is attempted.
        """
        try:
            self.registry.get(session_id)
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session to cancel",
                        details={"session_id": session_id},
                    ),
                )
            debuggee_paused_attempted = False
            dynamic_open = self._runtime_owner.get(session_id, BackendKind.X64DBG) is not None
            self._signal_unpack_cancel(session_id)
            if dynamic_open:
                debuggee_paused_attempted = True
                with suppress(Exception):
                    self.dynamic_pause(session_id)
            state = cancel_unpack_session(
                state,
                reason=reason,
                debuggee_paused_attempted=debuggee_paused_attempted,
            )
            self._store_unpack_session(state)
            return _success(
                {
                    "unpack": state.to_dict(),
                    "original_input_preserved": True,
                    "debuggee_paused_attempted": debuggee_paused_attempted,
                    "artifacts_retained": True,
                    "safe_rollback": False,
                    "note": "cancel does not undo dumps or restore prior memory/file state",
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_artifacts(self, session_id: str) -> Result[JsonObject]:
        """List artifacts produced by the current unpack session."""
        try:
            self.registry.get(session_id).require_pe()
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session; no artifacts ledger",
                        details={"session_id": session_id},
                    ),
                )
            directory = self._unpack_session_dir(session_id)
            return _success(
                {
                    "artifacts": [item.to_dict() for item in state.artifacts],
                    "count": len(state.artifacts),
                    "timeline_path": str(directory / "timeline.jsonl"),
                    "state_path": str(directory / "state.json"),
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def unpack_score_oep(
        self,
        session_id: str,
        *,
        module_base: int,
        module_size: int,
        observations: list[JsonObject] | None = None,
        stub_rva_ranges: list[tuple[int, int]] | None = None,
        max_candidates: int = 8,
        imports_resolved_hint: bool = False,
        previous_regions: list[JsonObject] | None = None,
    ) -> Result[JsonObject]:
        """Score OEP candidates from observations; never auto-confirms.

        When ``observations`` is empty/None, snapshots are collected from the
        dynamic backend (registers.read + memory.regions). Missing dynamic
        backend yields a clear error — never a fake success.
        """
        try:
            self.registry.get(session_id)
            blocked = self._guard_unpack_active(session_id, stage="score_oep")
            if blocked is not None:
                return blocked
            state = self._unpack_owner.get(session_id)

            collected_note: str | None = None
            auto_collected = False
            effective_stub = list(stub_rva_ranges or ())
            effective_observations = list(observations or [])
            entry_point_rva: int | None = None

            if not effective_observations:
                auto_collected = True
                collected = self._collect_oep_observations_from_runtime(
                    session_id,
                    module_base=module_base,
                    module_size=module_size,
                    stub_rva_ranges=effective_stub,
                    imports_resolved_hint=imports_resolved_hint,
                    previous_regions=previous_regions,
                )
                if not collected.ok:
                    return collected
                assert collected.data is not None
                effective_observations = list(collected.data.get("observations") or [])
                stub_from_runtime = collected.data.get("stub_rva_ranges") or []
                if not effective_stub and stub_from_runtime:
                    effective_stub = [(int(start), int(size)) for start, size in stub_from_runtime]
                entry_raw = collected.data.get("entry_point_rva")
                if type(entry_raw) is int:
                    entry_point_rva = entry_raw
                collected_note = str(
                    collected.data.get("note")
                    or "observations auto-collected from runtime snapshots"
                )

            candidates = score_oep_candidates(
                module_base=module_base,
                module_size=module_size,
                observations=effective_observations,
                stub_rva_ranges=effective_stub or (),
                max_candidates=max_candidates,
            )
            if state is not None and state.phase not in {
                UnpackPhase.FAILED,
                UnpackPhase.CANCELLED,
                UnpackPhase.REANALYZED,
            }:
                from dataclasses import replace as _replace

                if state.phase == UnpackPhase.RUNNING:
                    state = transition(
                        state,
                        UnpackPhase.OEP_CANDIDATE,
                        event="oep_candidates_scored",
                        message=(
                            f"scored {len(candidates)} OEP candidate(s); "
                            "none are authoritative until unpack.confirm_oep"
                        ),
                        details={
                            "candidate_count": len(candidates),
                            "auto_collected": auto_collected,
                            "observation_count": len(effective_observations),
                        },
                    )
                else:
                    state = append_timeline(
                        state,
                        event="oep_candidates_scored",
                        message=f"scored {len(candidates)} OEP candidate(s)",
                        details={
                            "candidate_count": len(candidates),
                            "auto_collected": auto_collected,
                            "observation_count": len(effective_observations),
                        },
                    )
                state = _replace(
                    state,
                    oep_candidates=tuple(candidates),
                    module_base=module_base,
                )
                self._store_unpack_session(state)
            payload: JsonObject = {
                "candidates": candidates,
                "candidate_count": len(candidates),
                "observations": effective_observations,
                "observation_count": len(effective_observations),
                "auto_collected": auto_collected,
                "authoritative": False,
                "blind_selection": False,
                "claims_universal_unpack": False,
                "unpack": state.to_dict() if state is not None else None,
            }
            if collected_note is not None:
                payload["note"] = collected_note
            if entry_point_rva is not None:
                payload["entry_point_rva"] = entry_point_rva
            if effective_stub:
                payload["stub_rva_ranges"] = [
                    {"rva": start, "size": size} for start, size in effective_stub
                ]
            return _success(
                payload,
                session_id=session_id,
                backend="unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def _collect_oep_observations_from_runtime(
        self,
        session_id: str,
        *,
        module_base: int,
        module_size: int,
        stub_rva_ranges: list[tuple[int, int]],
        imports_resolved_hint: bool,
        previous_regions: list[JsonObject] | None,
    ) -> Result[JsonObject]:
        """Gather RIP + memory regions (+ optional PE stub hints) for OEP scoring."""
        registers = self.dynamic_registers_read(session_id)
        if not registers.ok or registers.data is None:
            if registers.error is not None and registers.error.code == "backend_unavailable":
                return registers
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code=registers.error.code if registers.error else "backend_unavailable",
                    message=(
                        registers.error.message
                        if registers.error
                        else "dynamic registers.read unavailable for OEP observation"
                    ),
                    details={
                        "session_id": session_id,
                        "step": "registers.read",
                        **(registers.error.details if registers.error else {}),
                    },
                    retryable=bool(registers.error.retryable) if registers.error else False,
                ),
                meta=registers.meta,
            )

        regions_result = self.memory_regions(
            session_id,
            offset=0,
            limit=_OEP_REGION_SNAPSHOT_LIMIT,
        )
        if not regions_result.ok or regions_result.data is None:
            if (
                regions_result.error is not None
                and regions_result.error.code == "backend_unavailable"
            ):
                return regions_result
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code=(
                        regions_result.error.code if regions_result.error else "backend_unavailable"
                    ),
                    message=(
                        regions_result.error.message
                        if regions_result.error
                        else "dynamic memory.regions unavailable for OEP observation"
                    ),
                    details={
                        "session_id": session_id,
                        "step": "memory.regions",
                        **(regions_result.error.details if regions_result.error else {}),
                    },
                    retryable=(
                        bool(regions_result.error.retryable) if regions_result.error else False
                    ),
                ),
                meta=regions_result.meta,
            )

        regs = registers.data.get("registers")
        rip: int | None = None
        if isinstance(regs, dict):
            for name in ("rip", "eip"):
                value = regs.get(name)
                if type(value) is int:
                    rip = value
                    break

        regions_raw = regions_result.data.get("regions")
        regions: list[JsonObject] = (
            [dict(item) for item in regions_raw if isinstance(item, dict)]
            if isinstance(regions_raw, list)
            else []
        )

        effective_stub = list(stub_rva_ranges)
        entry_point_rva: int | None = None
        pe = self.pe_headers_runtime(session_id, module_base, save_artifact=False)
        if pe.ok and pe.data is not None:
            entry_raw = pe.data.get("entry_point_rva")
            if type(entry_raw) is int and entry_raw >= 0:
                entry_point_rva = entry_raw
            if not effective_stub:
                sections = pe.data.get("sections")
                if isinstance(sections, list):
                    effective_stub = stub_rva_ranges_from_sections(
                        [item for item in sections if isinstance(item, dict)]
                    )

        cached_previous = previous_regions
        if cached_previous is None:
            cached_previous = self._unpack_owner.get_protection_snapshot(session_id)

        observations = collect_oep_observations(
            module_base=module_base,
            module_size=module_size,
            rip=rip,
            regions=regions,
            previous_regions=cached_previous,
            stub_rva_ranges=effective_stub,
            entry_point_rva=entry_point_rva,
            imports_resolved_hint=imports_resolved_hint,
        )

        self._unpack_owner.put_protection_snapshot(
            session_id,
            [
                {
                    "base": item.get("base"),
                    "size": item.get("size"),
                    "protect": item.get("protect"),
                    "protect_name": item.get("protect_name"),
                }
                for item in regions
                if isinstance(item.get("base"), int)
            ],
        )

        note = "observations auto-collected from runtime snapshots"
        if not observations:
            note = (
                "runtime snapshots collected but yielded no OEP observations "
                "(need RIP in module code and/or protect diffs vs prior snapshot)"
            )
        return _success(
            {
                "observations": observations,
                "stub_rva_ranges": effective_stub,
                "entry_point_rva": entry_point_rva,
                "rip": rip,
                "region_count": len(regions),
                "note": note,
                "authoritative": False,
            },
            session_id=session_id,
            backend="unpack",
        )
    def unpack_confirm_oep(
        self,
        session_id: str,
        *,
        oep_rva: int,
        candidate_id: str | None = None,
        iat_va: int | None = None,
        iat_size: int | None = None,
        module_base: int | None = None,
        auto_dump: bool = False,
        dump_timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Caller-confirmed OEP (and optional IAT); never accepts heuristic alone as final.

        When ``auto_dump`` is True and ``module_base`` (or session module_base) is set,
        also runs ``unpack.dump_module`` to advance the session into ``dumped``.
        """
        try:
            if type(oep_rva) is not int or oep_rva < 0:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_params",
                        message="oep_rva must be a non-negative integer",
                    ),
                )
            if type(auto_dump) is not bool:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(code="invalid_params", message="auto_dump must be a boolean"),
                )
            state = self._unpack_owner.get(session_id)
            if state is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_not_started",
                        message="no unpack session; call unpack.start first",
                    ),
                )
            checked = check_timeout(state)
            if checked is not state:
                self._store_unpack_session(checked)
                state = checked
            if (
                state.phase == UnpackPhase.FAILED
                and state.failure is not None
                and state.failure.code == "unpack_timeout"
            ):
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="unpack_timeout",
                        message=state.failure.message,
                        details=state.failure.details,
                    ),
                )
            from dataclasses import replace as _replace

            if state.phase == UnpackPhase.RUNNING:
                state = transition(
                    state,
                    UnpackPhase.OEP_CANDIDATE,
                    event="oep_confirmed",
                    message="caller confirmed OEP RVA",
                    details={
                        "oep_rva": oep_rva,
                        "candidate_id": candidate_id,
                        "confirmed_by": "caller",
                    },
                )
            elif state.phase == UnpackPhase.OEP_CANDIDATE:
                state = append_timeline(
                    state,
                    event="oep_confirmed",
                    message="caller confirmed OEP RVA",
                    details={
                        "oep_rva": oep_rva,
                        "candidate_id": candidate_id,
                        "confirmed_by": "caller",
                    },
                )
            else:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="invalid_phase",
                        message=(
                            f"confirm_oep requires running/oep_candidate phase, "
                            f"got {state.phase.value}"
                        ),
                        details={"phase": state.phase.value},
                    ),
                )
            resolved_base = module_base if module_base is not None else state.module_base
            state = _replace(
                state,
                confirmed_oep_rva=oep_rva,
                confirmed_iat_va=iat_va,
                confirmed_iat_size=iat_size,
                module_base=resolved_base,
            )
            self._store_unpack_session(state)

            dump_result: JsonObject | None = None
            if auto_dump:
                blocked = self._guard_unpack_active(session_id, stage="confirm_oep_auto_dump")
                if blocked is not None:
                    return blocked
                if resolved_base is None or type(resolved_base) is not int or resolved_base <= 0:
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code="invalid_params",
                            message="auto_dump requires module_base on confirm or session",
                            details={"unpack": state.to_dict()},
                        ),
                    )
                dumped = self.unpack_dump_module(
                    session_id,
                    resolved_base,
                    timeout=dump_timeout,
                )
                dump_result = dumped.data if dumped.ok else None
                if not dumped.ok:
                    return Result[JsonObject](
                        ok=False,
                        error=dumped.error
                        or RpcError(
                            code="dump_failed",
                            message="auto_dump failed after OEP confirm",
                        ),
                        meta={"unpack": self._unpack_owner.get(session_id)},
                    )
                state = self._unpack_owner.get(session_id) or state

            return _success(
                {
                    "unpack": state.to_dict(),
                    "confirmed_oep_rva": oep_rva,
                    "role": "confirmed",
                    "auto_dump": auto_dump,
                    "dump": dump_result,
                    "next": (
                        ["unpack.iat.scan", "unpack.pe.rebuild", "unpack.verify"]
                        if auto_dump
                        else ["unpack.dump_module", "unpack.iat.scan", "unpack.pe.rebuild"]
                    ),
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="unpack",
            )
        except UnpackSessionError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(code="invalid_phase", message=str(exc)),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="unpack")
    def _bounded_runtime_probe(
        self,
        state: UnpackSessionState,
        session_id: str,
        *,
        route: str,
    ) -> tuple[UnpackSessionState, JsonObject]:
        """Best-effort bounded probe for native/VM routes without claiming unpack success.

        If a dynamic backend is already open: list modules, remember a module base,
        and optionally score OEP candidates from live observations. Never dumps or
        confirms OEP automatically.
        """
        from dataclasses import replace as _replace

        probe: JsonObject = {
            "route": route,
            "dynamic_open": False,
            "module_base": None,
            "oep_scored": False,
            "candidate_count": 0,
            "claims_universal_unpack": False,
            "note": (
                "bounded probe only; caller must confirm_oep then dump/rebuild; "
                "does not open a new debugger session"
            ),
        }
        dynamic_open = self._runtime_owner.get(session_id, BackendKind.X64DBG) is not None
        probe["dynamic_open"] = dynamic_open
        if not dynamic_open:
            state = append_timeline(
                state,
                event="bounded_probe_skipped",
                message="dynamic backend not open; open_dynamic+pause before score_oep/dump",
                details={"route": route},
            )
            return state, probe

        modules = self.dynamic_modules(session_id)
        if not modules.ok or modules.data is None:
            state = append_timeline(
                state,
                event="bounded_probe_modules_failed",
                message="modules.list failed during bounded probe",
                details={
                    "error": modules.error.model_dump() if modules.error else None,
                },
            )
            probe["modules_error"] = modules.error.model_dump() if modules.error else None
            return state, probe

        module_list = modules.data.get("modules")
        if not isinstance(module_list, list) or not module_list:
            state = append_timeline(
                state,
                event="bounded_probe_no_modules",
                message="no modules returned for bounded probe",
            )
            return state, probe

        first = module_list[0]
        if not isinstance(first, dict):
            return state, probe
        base = first.get("base")
        size = first.get("size")
        if type(base) is not int or base <= 0:
            return state, probe
        probe["module_base"] = base
        probe["module_size"] = size if type(size) is int else None
        probe["module_name"] = first.get("name")
        state = _replace(state, module_base=base)
        state = append_timeline(
            state,
            event="bounded_probe_modules_listed",
            message="recorded candidate module base for later dump/OEP scoring",
            details={"module_base": base, "module_name": first.get("name")},
        )

        # Optional OEP score when paused; failures stay observable.
        if type(size) is int and size > 0:
            scored = self.unpack_score_oep(
                session_id,
                module_base=base,
                module_size=size,
                observations=None,
            )
            if scored.ok and scored.data is not None:
                probe["oep_scored"] = True
                probe["candidate_count"] = int(scored.data.get("candidate_count") or 0)
                refreshed = self._unpack_owner.get(session_id)
                if refreshed is not None:
                    state = refreshed
            else:
                probe["oep_score_error"] = scored.error.model_dump() if scored.error else None
                state = append_timeline(
                    state,
                    event="bounded_probe_oep_score_deferred",
                    message=(
                        "OEP auto-score unavailable (likely not paused); "
                        "caller may retry unpack.score_oep after pause"
                    ),
                    details=probe.get("oep_score_error"),
                )
        return state, probe
    def _run_upx_orchestration(
        self,
        state: UnpackSessionState,
        session_id: str,
        *,
        timeout: float,
        open_ida: bool,
    ) -> UnpackSessionState:
        tested = self.unpack_upx_test(session_id, timeout=timeout)
        if not tested.ok:
            return fail_unpack_session(
                state,
                code="upx_test_failed",
                message="official UPX test failed; not claiming unpack success",
                details=tested.error.model_dump() if tested.error else {},
                retryable=True,
            )
        state = append_timeline(
            state,
            event="upx_test_ok",
            message="official upx -t succeeded",
            details=tested.data or {},
        )
        self._store_unpack_session(state)
        checked, code = ensure_unpack_active(state, stage="upx_unpack")
        if code is not None:
            self._store_unpack_session(checked)
            return checked
        state = checked
        unpacked = self.unpack_upx_unpack(
            session_id,
            timeout=timeout,
            open_ida=open_ida,
        )
        if not unpacked.ok or unpacked.data is None:
            return fail_unpack_session(
                state,
                code="upx_unpack_failed",
                message="official UPX unpack failed; not claiming success",
                details=unpacked.error.model_dump() if unpacked.error else {},
                retryable=True,
            )
        output_path = str(unpacked.data.get("output_path", ""))
        output_sha = None
        if output_path:
            output_sha = file_sha256(Path(output_path))
            state = add_artifact(
                state,
                kind="upx_unpacked",
                path=output_path,
                sha256=output_sha,
                phase=UnpackPhase.VERIFIED,
            )
        state = transition(
            state,
            UnpackPhase.VERIFIED,
            event="upx_unpacked",
            message="official UPX unpack produced an artifact",
            output_sha256=output_sha,
            details={
                "comparison": unpacked.data.get("comparison"),
                "die_rescan": unpacked.data.get("die_rescan"),
            },
        )
        reanalyze = unpacked.data.get("reanalyze")
        if open_ida and isinstance(reanalyze, dict) and reanalyze.get("static_open_ok"):
            state = transition(
                state,
                UnpackPhase.REANALYZED,
                event="ida_reopened",
                message="unpacked artifact opened in IDA idalib",
                output_sha256=output_sha,
                details={"reanalyze": reanalyze},
            )
        return state
    def _unpack_session_dir(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id:
            raise ValueError("invalid session id for unpack artifact path")
        return (
            self.settings.artifact_root.expanduser().resolve() / "unpack" / session_id / "session"
        )
    def _store_unpack_session(self, state: UnpackSessionState) -> None:
        self._unpack_owner.put(state.session_id, state)

        def write(directory: Path) -> None:
            write_timeline_jsonl(state, directory / "timeline.jsonl")
            persist_state_snapshot(state, directory / "state.json")

        self.repository.persist_unpack_state(
            state.session_id,
            write=write,
        )
    def _guard_unpack_active(
        self,
        session_id: str,
        *,
        stage: str,
    ) -> Result[JsonObject] | None:
        """Block new unpack work when session is timed out / cancelled / terminal.

        Returns an error ``Result`` to propagate, or ``None`` when work may proceed
        (including when no unpack session exists yet).
        """
        state = self._unpack_owner.get(session_id)
        if state is None:
            return None
        checked, code = ensure_unpack_active(state, stage=stage)
        if checked is not state:
            self._store_unpack_session(checked)
            state = checked
        elif code is not None and state.phase in {
            UnpackPhase.FAILED,
            UnpackPhase.CANCELLED,
            UnpackPhase.REANALYZED,
        }:
            # Already terminal; refresh store is a no-op but keeps API uniform.
            self._store_unpack_session(state)
        if code is None:
            return None
        message = (
            state.failure.message
            if state.failure is not None and code == "unpack_timeout"
            else f"unpack session cannot continue ({state.phase.value}) at {stage}"
        )
        details: JsonObject = {"phase": state.phase.value, "stage": stage}
        if state.failure is not None:
            details["failure"] = state.failure.to_dict()
        return Result[JsonObject](
            ok=False,
            error=RpcError(code=code, message=message, details=details),
            meta={"unpack": state.to_dict()},
        )
    def _advance_unpack_after_dump(
        self,
        session_id: str,
        *,
        path: str,
        sha256: str,
    ) -> None:
        """Advance session to dumped when a dump artifact is produced."""
        state = self._unpack_owner.get(session_id)
        if state is None:
            return
        try:
            state = check_timeout(state)
            if state.phase == UnpackPhase.FAILED:
                self._store_unpack_session(state)
                return
            state = note_dump_success(
                state,
                output_path=path,
                sha256=sha256,
                module_base=state.module_base,
            )
            self._store_unpack_session(state)
        except UnpackSessionError:
            return
    def _advance_unpack_after_imports_rebuilt(
        self,
        session_id: str,
        *,
        path: str,
        sha256: str,
        kind: str,
    ) -> None:
        """Advance session to imports_rebuilt after IAT/PE rebuild."""
        state = self._unpack_owner.get(session_id)
        if state is None:
            return
        try:
            state = check_timeout(state)
            if state.phase == UnpackPhase.FAILED:
                self._store_unpack_session(state)
                return
            state = note_imports_rebuilt(
                state,
                output_path=path,
                sha256=sha256,
                kind=kind,
            )
            self._store_unpack_session(state)
        except UnpackSessionError:
            return
    def _advance_unpack_after_verify(
        self,
        session_id: str,
        *,
        path: str,
        sha256: str,
        open_ida: bool,
        ida_ok: bool,
    ) -> None:
        """Advance session to verified / reanalyzed after unpack.verify."""
        state = self._unpack_owner.get(session_id)
        if state is None:
            return
        try:
            state = check_timeout(state)
            if state.phase == UnpackPhase.FAILED:
                self._store_unpack_session(state)
                return
            state = note_verified(
                state,
                path=path,
                sha256=sha256,
                reanalyzed=bool(open_ida and ida_ok),
            )
            self._store_unpack_session(state)
        except UnpackSessionError:
            return
