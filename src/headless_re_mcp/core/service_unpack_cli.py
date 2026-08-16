"""UPX / external unpack CLI ops extracted from AnalysisService."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from headless_re_mcp.core.models import Result, RpcError
from headless_re_mcp.core.results import _failure, _success
from headless_re_mcp.core.service_ext import _register_capture
from headless_re_mcp.core.session import file_sha256
from headless_re_mcp.detection import ScanMode, scan_pe
from headless_re_mcp.detection.die import DieScanError
from headless_re_mcp.unpack.scylla import ScyllaError
from headless_re_mcp.unpack.session import UnpackPhase
from headless_re_mcp.unpack.vmp_dumper import VmpDumperError
from headless_re_mcp.unpack.xvlkc import XvlkcError

if TYPE_CHECKING:
    from collections.abc import Callable

    from headless_re_mcp.config import Settings
    from headless_re_mcp.core.service import DieScanner, UpxTester, UpxUnpacker
    from headless_re_mcp.core.session import SessionRegistry

JsonObject = dict[str, Any]


def _detection_timeout(timeout: float) -> float:
    from headless_re_mcp.core.service import _detection_timeout as real
    return real(timeout)


class UnpackCliMixin:
    """UPX and external unpacker CLI helpers.

    The members below are supplied by ``AnalysisService``, which this mixes into.
    """

    settings: Settings
    registry: SessionRegistry
    _die_scanner: DieScanner
    _upx_tester: UpxTester
    _upx_unpacker: UpxUnpacker
    _xvlkc_runner: Callable[..., Any]
    _vmp_dumper_runner: Callable[..., Any]
    _scylla_runner: Callable[..., Any]

    if TYPE_CHECKING:

        def create_session(self, binary: str) -> Result[JsonObject]: ...

        def open_static(self, session_id: str) -> Result[JsonObject]: ...

        def dynamic_state(self, session_id: str) -> Result[JsonObject]: ...

        def unpack_status(self, session_id: str) -> Result[JsonObject]: ...

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
        ) -> Result[JsonObject]: ...

        def _annotate_debuggee_pids(self, session_id: str, state: JsonObject) -> JsonObject: ...

    def unpack_upx_test(
        self,
        session_id: str,
        *,
        timeout: float = 60.0,
    ) -> Result[JsonObject]:
        """Run official ``upx -t`` against the session binary without modifying it."""
        try:
            session = self.registry.get(session_id)
            bounded_timeout = _detection_timeout(timeout)
            if self.settings.upx is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="capability_unavailable",
                        message="official UPX CLI is not configured",
                        details={"hint": "set HEADLESS_RE_UPX to the official upx executable"},
                    ),
                )
            current_sha = file_sha256(session.require_binary())
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )
            result = self._upx_tester(
                self.settings.upx,
                session.require_binary(),
                input_sha256=session.sha256,
                timeout=bounded_timeout,
            )
            return _success(
                {"upx": result.to_dict(), "input_unchanged": True},
                session_id=session_id,
                backend="upx",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="upx")

    def unpack_upx_unpack(
        self,
        session_id: str,
        *,
        timeout: float = 60.0,
        open_ida: bool = False,
    ) -> Result[JsonObject]:
        """Run official ``upx -d`` into a session artifact without overwriting the input."""
        try:
            session = self.registry.get(session_id)
            bounded_timeout = _detection_timeout(timeout)
            if type(open_ida) is not bool:
                raise ValueError("open_ida must be a boolean")
            if self.settings.upx is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="capability_unavailable",
                        message="official UPX CLI is not configured",
                        details={"hint": "set HEADLESS_RE_UPX to the official upx executable"},
                    ),
                )
            current_sha = file_sha256(session.require_binary())
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )

            before = scan_pe(session.require_binary())
            output_dir = self.settings.artifact_root.expanduser().resolve() / "unpack" / session_id
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"upx-unpacked-{uuid4().hex}.exe"
            result = self._upx_unpacker(
                self.settings.upx,
                session.require_binary(),
                output_path,
                input_sha256=session.sha256,
                timeout=bounded_timeout,
            )
            assert result.output_path is not None
            after = scan_pe(result.output_path)
            comparison = {
                "input_sha256": session.sha256,
                "output_sha256": result.output_sha256,
                "architecture_match": before.architecture == after.architecture,
                "entry_point_rva": {
                    "before": before.pe.entry_point_rva,
                    "after": after.pe.entry_point_rva,
                },
                "section_count": {
                    "before": len(before.pe.sections),
                    "after": len(after.pe.sections),
                },
                "import_function_count": {
                    "before": before.pe.imports.function_count,
                    "after": after.pe.imports.function_count,
                },
            }
            if before.architecture != after.architecture:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="architecture_mismatch",
                        message="UPX output architecture does not match the input",
                        details=comparison,
                    ),
                )

            die_rescan: JsonObject | None = None
            if self.settings.diec is not None:
                try:
                    die_result = self._die_scanner(
                        self.settings.diec,
                        result.output_path,
                        mode=ScanMode.NORMAL,
                        timeout=bounded_timeout,
                    )
                    die_rescan = {
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
                                "confidence": finding.confidence,
                            }
                            for finding in die_result.findings[:32]
                        ],
                    }
                except DieScanError as exc:
                    die_rescan = {
                        "status": "failed",
                        "error": str(exc),
                    }

            reanalyze: JsonObject | None = None
            if open_ida:
                child = self.create_session(str(result.output_path))
                if child.ok and child.data is not None:
                    child_session = child.data["session"]
                    child_id = str(child_session["id"]) if isinstance(child_session, dict) else ""
                    opened = self.open_static(child_id) if child_id else child
                    reanalyze = {
                        "session": child.data.get("session"),
                        "static_open": opened.data if opened.ok else None,
                        "static_open_ok": opened.ok,
                        "error": (
                            None
                            if opened.ok
                            else (opened.error.model_dump() if opened.error else None)
                        ),
                    }
                else:
                    reanalyze = {
                        "session": None,
                        "static_open_ok": False,
                        "error": child.error.model_dump() if child.error else None,
                    }

            payload = {
                "upx": result.to_dict(),
                "comparison": comparison,
                "output_path": str(result.output_path),
                "input_unchanged": file_sha256(session.require_binary()) == session.sha256,
                "die_rescan": die_rescan,
                "reanalyze": reanalyze,
                "claims_universal_unpack": False,
            }
            # A bare output_path is a dead end: nothing on the tool surface
            # opens one, and retention only collects registered rows.
            # Measured: 5 unpacks, 5 files / 5120 bytes, 0 artifact rows.
            payload = _register_capture(
                self,
                session_id,
                Path(result.output_path),
                kind="upx_unpacked",
                source="unpack.upx.unpack",
                payload=payload,
            )
            return _success(payload, session_id=session_id, backend="upx")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="upx")

    def unpack_external_probe(self, session_id: str) -> Result[JsonObject]:
        """Probe optional external unpackers without running them on the session binary."""
        try:
            self.registry.get(session_id)
            xvlkc_path = self.settings.xvlkc
            vmp_path = self.settings.vmp_dumper
            xvlkc_status: JsonObject
            if xvlkc_path is None:
                xvlkc_status = {
                    "configured": False,
                    "status": "missing",
                    "executable": None,
                }
            elif not xvlkc_path.is_file():
                xvlkc_status = {
                    "configured": True,
                    "status": "blocked",
                    "executable": str(xvlkc_path),
                }
            else:
                from headless_re_mcp.unpack.xvlkc import probe_xvlkc

                ok, output = probe_xvlkc(xvlkc_path)
                xvlkc_status = {
                    "configured": True,
                    "status": "ready" if ok else "blocked",
                    "executable": str(xvlkc_path),
                    "probe_ok": ok,
                    "probe_output": output[:500] if output else None,
                }
            vmp_status: JsonObject
            if vmp_path is None:
                vmp_status = {
                    "configured": False,
                    "status": "missing",
                    "executable": None,
                }
            elif not vmp_path.is_file():
                vmp_status = {
                    "configured": True,
                    "status": "blocked",
                    "executable": str(vmp_path),
                }
            else:
                from headless_re_mcp.unpack.vmp_dumper import probe_vmp_dumper

                ok, output = probe_vmp_dumper(vmp_path)
                vmp_status = {
                    "configured": True,
                    "status": "ready" if ok else "blocked",
                    "executable": str(vmp_path),
                    "probe_ok": ok,
                    "probe_output": output[:500] if output else None,
                }
            scylla_path = self.settings.scylla
            scylla_status: JsonObject
            if scylla_path is None:
                scylla_status = {
                    "configured": False,
                    "status": "missing",
                    "executable": None,
                }
            elif not scylla_path.is_file():
                scylla_status = {
                    "configured": True,
                    "status": "blocked",
                    "executable": str(scylla_path),
                }
            else:
                from headless_re_mcp.unpack.scylla import probe_scylla

                ok, output = probe_scylla(scylla_path)
                scylla_status = {
                    "configured": True,
                    "status": "ready" if ok else "blocked",
                    "executable": str(scylla_path),
                    "probe_ok": ok,
                    "probe_output": output[:500] if output else None,
                }
            return _success(
                {
                    "xvlkc": xvlkc_status,
                    "vmp_dumper": vmp_status,
                    "scylla": scylla_status,
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="external_unpack",
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="external_unpack")

    def unpack_xvlkc_unpack(
        self,
        session_id: str,
        *,
        timeout: float = 120.0,
    ) -> Result[JsonObject]:
        """Optional XVLKC unpack into a session artifact; never overwrite input."""
        try:
            session = self.registry.get(session_id)
            if self.settings.xvlkc is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="capability_unavailable",
                        message="XVLKC CLI is not configured",
                        details={"hint": "set HEADLESS_RE_XVLKC to a user-owned executable"},
                    ),
                )
            current_sha = file_sha256(session.require_binary())
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )
            out_dir = self.settings.artifact_root.expanduser().resolve() / "unpack" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"xvlkc-{uuid4().hex}.exe"
            result = self._xvlkc_runner(
                self.settings.xvlkc,
                session.require_binary(),
                out_path,
                input_sha256=session.sha256,
                timeout=_detection_timeout(timeout),
            )
            payload = {
                "xvlkc": result.to_dict(),
                "output_path": str(result.output_path),
                "input_unchanged": file_sha256(session.require_binary()) == session.sha256,
                "claims_universal_unpack": False,
            }
            # Measured: 5 unpacks, 5 files / 5120 bytes, 0 artifact rows.
            payload = _register_capture(
                self,
                session_id,
                Path(result.output_path),
                kind="xvlkc_unpacked",
                source="unpack.xvlkc.unpack",
                payload=payload,
            )
            return _success(
                payload,
                session_id=session_id,
                backend="xvlkc",
            )
        except XvlkcError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code=str(exc.code),
                    message=str(exc),
                    details=dict(exc.details),
                ),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="xvlkc")

    def unpack_vmp_dump(
        self,
        session_id: str,
        *,
        timeout: float = 120.0,
        module_name: str | None = None,
        entry_point_rva: int | None = None,
        disable_reloc: bool = False,
        pid: int | None = None,
    ) -> Result[JsonObject]:
        """Optional upstream VMPDump (process mode) into a session artifact.

        Requires a live debuggee PID. Does not overwrite the session input.
        Upstream is x64-oriented (0xnobody/vmpdump); never claims universal unpack.
        """
        try:
            session = self.registry.get(session_id)
            if self.settings.vmp_dumper is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="capability_unavailable",
                        message="VMP dumper CLI is not configured",
                        details={
                            "hint": (
                                "set HEADLESS_RE_VMP_DUMPER to a user-owned build of "
                                "https://github.com/0xnobody/vmpdump (GPL-3.0); "
                                "toolkit VMPx64Dump3.x-3.5.exe is a known binary form"
                            )
                        },
                    ),
                )
            current_sha = file_sha256(session.require_binary())
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )
            meta_pid = session.metadata.get("debuggee_pid")
            debuggee_pid: int | None = None
            if isinstance(pid, int) and pid > 0:
                debuggee_pid = pid
            elif isinstance(meta_pid, int) and meta_pid > 0:
                debuggee_pid = meta_pid
            else:
                try:
                    state = self.dynamic_state(session_id)
                    if state.ok and state.data is not None:
                        annotated = self._annotate_debuggee_pids(
                            session_id, dict(state.data)
                        )
                        cand = annotated.get("debuggee_pid")
                        if isinstance(cand, int) and cand > 0:
                            debuggee_pid = cand
                except BaseException:
                    debuggee_pid = None
            if debuggee_pid is None or debuggee_pid <= 0:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="debuggee_required",
                        message=(
                            "VMPDump requires a live debuggee; launch/attach and "
                            "pause past OEP before unpack.vmp.dump"
                        ),
                        details={
                            "upstream": "https://github.com/0xnobody/vmpdump",
                            "supported_arch": "x64",
                        },
                    ),
                )
            resolved_module = (
                module_name
                if module_name is not None
                else Path(session.require_binary()).name
            )
            out_dir = self.settings.artifact_root.expanduser().resolve() / "unpack" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"vmp-dump-{uuid4().hex}.exe"
            search_roots = [Path(session.require_binary()).resolve().parent, out_dir]
            result = self._vmp_dumper_runner(
                self.settings.vmp_dumper,
                session.require_binary(),
                out_path,
                input_sha256=session.sha256,
                timeout=_detection_timeout(timeout),
                pid=debuggee_pid,
                module_name=resolved_module,
                entry_point_rva=entry_point_rva,
                disable_reloc=disable_reloc,
                search_roots=search_roots,
            )
            return _success(
                {
                    "vmp_dumper": result.to_dict(),
                    "output_path": str(result.output_path),
                    "dump_ok": result.dump_ok,
                    "imports_rebuilt": result.imports_rebuilt,
                    "vm_restored": result.vm_restored,
                    "pid": debuggee_pid,
                    "module_name": resolved_module,
                    "input_unchanged": file_sha256(session.require_binary()) == session.sha256,
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="vmp_dumper",
            )
        except VmpDumperError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code=str(exc.code),
                    message=str(exc),
                    details=dict(exc.details),
                ),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="vmp_dumper")
    def unpack_scylla_rebuild(
        self,
        session_id: str,
        *,
        timeout: float = 120.0,
    ) -> Result[JsonObject]:
        """Optional Scylla helper into a session artifact; never overwrite input."""
        try:
            session = self.registry.get(session_id)
            if self.settings.scylla is None:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="capability_unavailable",
                        message="Scylla CLI is not configured",
                        details={"hint": "set HEADLESS_RE_SCYLLA to a user-owned executable"},
                    ),
                )
            current_sha = file_sha256(session.require_binary())
            if current_sha != session.sha256:
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code="input_changed",
                        message="session input changed after session creation",
                        details={
                            "session_id": session_id,
                            "expected_sha256": session.sha256,
                            "actual_sha256": current_sha,
                        },
                    ),
                )
            out_dir = self.settings.artifact_root.expanduser().resolve() / "unpack" / session_id
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"scylla-iat-rebuilt-{uuid4().hex}.exe"
            result = self._scylla_runner(
                self.settings.scylla,
                session.require_binary(),
                out_path,
                input_sha256=session.sha256,
                timeout=_detection_timeout(timeout),
            )
            return _success(
                {
                    "scylla": result.to_dict(),
                    "output_path": str(result.output_path),
                    "input_unchanged": file_sha256(session.require_binary()) == session.sha256,
                    "claims_universal_unpack": False,
                },
                session_id=session_id,
                backend="scylla",
            )
        except ScyllaError as exc:
            return Result[JsonObject](
                ok=False,
                error=RpcError(
                    code=str(exc.code),
                    message=str(exc),
                    details=dict(exc.details),
                ),
            )
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="scylla")

    def unpack_auto(
        self,
        session_id: str,
        *,
        mode: ScanMode | str = ScanMode.NORMAL,
        use_die: bool = True,
        timeout: float = 60.0,
        open_ida: bool = False,
    ) -> Result[JsonObject]:
        """M5 convenience entry: plan+start; UPX executes, other routes stay observable.

        If an unpack session is already active, reuse it instead of silently replacing.
        """
        try:
            started = self.unpack_start(
                session_id,
                mode=mode,
                use_die=use_die,
                timeout=timeout,
                open_ida=open_ida,
                execute_upx=True,
            )
            if (
                not started.ok
                and started.error is not None
                and started.error.code == "unpack_already_active"
            ):
                status = self.unpack_status(session_id)
                if not status.ok or status.data is None:
                    return started
                started = Result[JsonObject](
                    ok=True,
                    data={
                        "unpack": status.data["unpack"],
                        "claims_universal_unpack": False,
                        "reused_existing": True,
                    },
                    error=None,
                    meta=dict(status.meta),
                )
            if not started.ok or started.data is None:
                return started
            unpack = started.data.get("unpack")
            if not isinstance(unpack, dict):
                return started
            route = str(unpack.get("route", "none"))
            phase = str(unpack.get("phase", ""))
            payload: JsonObject = {
                "recommendation": unpack.get("plan"),
                "unpack": unpack,
                "claims_universal_unpack": False,
            }
            if started.data.get("reused_existing"):
                payload["reused_existing"] = True
            if route == "upx" and phase in {
                UnpackPhase.VERIFIED.value,
                UnpackPhase.REANALYZED.value,
            }:
                payload["status"] = "unpacked"
                artifacts = unpack.get("artifacts") or []
                upx_arts = [
                    item
                    for item in artifacts
                    if isinstance(item, dict) and item.get("kind") == "upx_unpacked"
                ]
                output_path = upx_arts[-1].get("path") if upx_arts else None
                output_sha = upx_arts[-1].get("sha256") if upx_arts else None
                # Keep a compatibility view alongside the M5 session state.
                payload["unpack"] = {
                    **unpack,
                    "output_path": output_path,
                    "output_sha256": output_sha,
                    "input_unchanged": True,
                }
                return _success(payload, session_id=session_id, backend="upx")
            if route == "upx" and phase == UnpackPhase.FAILED.value:
                failure = unpack.get("failure") or {}
                payload["status"] = str(failure.get("code") or "upx_failed")
                payload["next"] = "generic_dynamic"
                return Result[JsonObject](
                    ok=False,
                    error=RpcError(
                        code=str(failure.get("code") or "upx_failed"),
                        message=str(
                            failure.get("message")
                            or "official UPX path failed; not claiming success"
                        ),
                        details=payload,
                    ),
                )
            if route == "dotnet":
                unpack_phase = str(unpack.get("phase", ""))
                if unpack_phase == UnpackPhase.FAILED.value:
                    failure = unpack.get("failure") or {}
                    payload["status"] = str(failure.get("code") or "dotnet_failed")
                    payload["next"] = ["dotnet.inspect"]
                    return Result[JsonObject](
                        ok=False,
                        error=RpcError(
                            code=str(failure.get("code") or "dotnet_failed"),
                            message=str(
                                failure.get("message")
                                or ".NET unpack route failed before M6 hand-off"
                            ),
                            details=payload,
                        ),
                    )
                probe = started.data.get("bounded_probe")
                if not isinstance(probe, dict):
                    # Reused session: recover hand-off hints from timeline.
                    for item in reversed(list(unpack.get("timeline") or [])):
                        if isinstance(item, dict) and item.get("event") == "routed_m6":
                            details = item.get("details") or {}
                            if isinstance(details, dict):
                                probe = {
                                    "next": details.get("next"),
                                    "clr_verified": details.get("clr_verified"),
                                    "dotnet_inspect": None,
                                }
                            break
                payload["status"] = "routed_m6"
                payload["next"] = (
                    probe.get("next")
                    if isinstance(probe, dict) and isinstance(probe.get("next"), list)
                    else ["dotnet.deobfuscate", "dotnet.verify"]
                )
                if isinstance(probe, dict):
                    payload["dotnet"] = probe.get("dotnet_inspect")
                    payload["clr_verified"] = probe.get("clr_verified")
                return _success(payload, session_id=session_id, backend="unpack")
            if route in {"generic_dynamic", "bounded_dynamic"}:
                payload["status"] = "awaiting_oep"
                payload["next"] = "unpack.confirm_oep"
                return _success(payload, session_id=session_id, backend="unpack")
            payload["status"] = "not_upx"
            payload["next"] = route
            return _success(payload, session_id=session_id, backend="upx")
        except BaseException as exc:
            return _failure(exc, session_id=session_id, backend="upx")


